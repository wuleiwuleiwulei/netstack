/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "net_http_client_exec.h"

#include <cstddef>
#include <cstring>
#include <memory>
#include <thread>
#include <unistd.h>
#include <pthread.h>
#ifdef HTTP_MULTIPATH_CERT_ENABLE
#include <openssl/ssl.h>
#endif
#ifdef HTTP_ONLY_VERIFY_ROOT_CA_ENABLE
#ifndef HTTP_MULTIPATH_CERT_ENABLE
#include <openssl/ssl.h>
#endif
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#endif
#if HAS_NETMANAGER_BASE
#include <netdb.h>
#endif

#ifdef HTTP_PROXY_ENABLE
#include "parameter.h"
#endif
#ifdef HAS_NETMANAGER_BASE
#include "http_proxy.h"
#include "net_conn_client.h"
#include "network_security_config.h"
using NetworkSecurityConfig = OHOS::NetManagerStandard::NetworkSecurityConfig;
#endif

#include "net_http_utils.h"
#include "net_http_cache_proxy.h"
#include "constant.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "securec.h"

#define NETSTACK_CURL_EASY_SET_OPTION(handle, opt, data, asyncContext)                                   \
    do {                                                                                                 \
        CURLcode result = curl_easy_setopt(handle, opt, data);                                           \
        if (result != CURLE_OK) {                                                                        \
            const char *err = curl_easy_strerror(result);                                                \
            NETSTACK_LOGE("Failed to set option: %{public}s, %{public}s %{public}d", #opt, err, result); \
            (asyncContext)->SetErrorCode(result);                                                        \
            return false;                                                                                \
        }                                                                                                \
    } while (0)

namespace OHOS::NetStack::Http {
static constexpr int CURL_TIMEOUT_MS = 50;
static constexpr int CONDITION_TIMEOUT_S = 3600;
static constexpr int CURL_MAX_WAIT_MSECS = 10;
static constexpr int CURL_HANDLE_NUM = 10;
static constexpr const char *TLS12_SECURITY_CIPHER_SUITE = R"(DEFAULT:!eNULL:!EXPORT)";
static constexpr int NETSTACK_NAPI_INTERNAL_ERROR = 2300002;

#ifdef HTTP_MULTIPATH_CERT_ENABLE
static constexpr const int32_t UID_TRANSFORM_DIVISOR = 200000;
static constexpr const char *BASE_PATH = "/data/certificates/user_cacerts/";
static constexpr const char *USER_CERT_ROOT_PATH = "/data/certificates/user_cacerts/0/";
static constexpr int32_t SYSPARA_MAX_SIZE = 128;
static constexpr const char *DEFAULT_HTTP_PROXY_HOST = "NONE";
static constexpr const char *DEFAULT_HTTP_PROXY_PORT = "0";
static constexpr const char *DEFAULT_HTTP_PROXY_EXCLUSION_LIST = "NONE";
static constexpr const char *HTTP_PROXY_HOST_KEY = "persist.netmanager_base.http_proxy.host";
static constexpr const char *HTTP_PROXY_PORT_KEY = "persist.netmanager_base.http_proxy.port";
static constexpr const char *HTTP_PROXY_EXCLUSIONS_KEY = "persist.netmanager_base.http_proxy.exclusion_list";
#endif

#ifdef HTTP_ONLY_VERIFY_ROOT_CA_ENABLE
static constexpr const int SSL_CTX_EX_DATA_REQUEST_CONTEXT_INDEX = 1;
#endif

bool NetHttpClientExec::AddCurlHandle(CURL *handle, RequestContext *context)
{
    if (handle == nullptr || staticVariable_.curlMulti == nullptr) {
        NETSTACK_LOGE("handle nullptr");
        return false;
    }

    std::thread([context, handle] {
        std::lock_guard guard(staticVariable_.curlMultiMutex);
        // Do SetServerSSLCertOption here to avoid blocking the main thread.
        SetServerSSLCertOption(handle, context);
        staticVariable_.infoQueue.emplace(context, handle);
        staticVariable_.conditionVariable.notify_all();
        {
            std::lock_guard lockGuard(staticContextSet_.mutexForContextVec);
            NetHttpClientExec::staticContextSet_.contextSet.emplace(context);
        }
    }).detach();

    return true;
}

NetHttpClientExec::StaticVariable NetHttpClientExec::staticVariable_; /* NOLINT */
NetHttpClientExec::StaticContextVec NetHttpClientExec::staticContextSet_;

void NetHttpClientExec::ExecRequest(RequestContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return;
    }
    context->options.SetRequestTime(GetNowTimeGMT());
    CacheProxy proxy(context->options);
    if (context->IsUsingCache() && proxy.ReadResponseFromCache(context)) {
        return;
    }
    if (!RequestWithoutCache(context)) {
        context->SetErrorCode(NETSTACK_NAPI_INTERNAL_ERROR);
        context->SendResponse();
        delete context;
        context = nullptr;
    }
}

bool NetHttpClientExec::RequestWithoutCache(RequestContext *context)
{
    if (!staticVariable_.initialized) {
        NETSTACK_LOGE("curl not init");
        return false;
    }

    auto handle = curl_easy_init();
    if (!handle) {
        NETSTACK_LOGE("Failed to create fetch task");
        return false;
    }

    std::vector<std::string> vec;
    std::for_each(context->options.GetHeader().begin(), context->options.GetHeader().end(),
                  [&vec](const std::pair<std::string, std::string> &p) {
                      if (!p.second.empty()) {
                          vec.emplace_back(p.first + HTTP_HEADER_SEPARATOR + p.second);
                      } else {
                          vec.emplace_back(p.first + HTTP_HEADER_BLANK_SEPARATOR);
                      }
                  });
    context->SetCurlHeaderList(MakeHeaders(vec));

    if (!SetOption(handle, context, context->GetCurlHeaderList())) {
        NETSTACK_LOGE("set option failed");
        curl_easy_cleanup(handle);
        return false;
    }

    context->response.SetRequestTime(GetNowTimeGMT());

    if (!AddCurlHandle(handle, context)) {
        NETSTACK_LOGE("add handle failed");
        curl_easy_cleanup(handle);
        return false;
    }

    return true;
}

bool NetHttpClientExec::GetCurlDataFromHandle(CURL *handle, RequestContext *context, CURLMSG curlMsg, CURLcode result)
{
    if (curlMsg != CURLMSG_DONE) {
        NETSTACK_LOGE("CURLMSG %{public}s", std::to_string(curlMsg).c_str());
        context->SetErrorCode(NETSTACK_NAPI_INTERNAL_ERROR);
        return false;
    }

    if (result != CURLE_OK) {
        context->SetErrorCode(result);
        NETSTACK_LOGE("CURLcode result %{public}s", std::to_string(result).c_str());
        return false;
    }

    context->response.SetResponseTime(GetNowTimeGMT());

    int64_t responseCode;
    CURLcode code = curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &responseCode);
    if (code != CURLE_OK) {
        context->SetErrorCode(code);
        return false;
    }
    context->response.SetResponseCode(responseCode);
    if (context->response.GetResponseCode() == static_cast<uint32_t>(ResponseCode::NOT_MODIFIED)) {
        NETSTACK_LOGI("cache is NOT_MODIFIED, we use the cache");
        context->SetResponseByCache();
        return true;
    }
    NETSTACK_LOGI("responseCode is %{public}s", std::to_string(responseCode).c_str());

    struct curl_slist *cookies = nullptr;
    code = curl_easy_getinfo(handle, CURLINFO_COOKIELIST, &cookies);
    if (code != CURLE_OK) {
        context->SetErrorCode(code);
        return false;
    }

    std::unique_ptr<struct curl_slist, decltype(&curl_slist_free_all)> cookiesHandle(cookies, curl_slist_free_all);
    while (cookies) {
        context->response.AppendCookies(cookies->data, strlen(cookies->data));
        if (cookies->next != nullptr) {
            context->response.AppendCookies(HTTP_LINE_SEPARATOR,
                strlen(HTTP_LINE_SEPARATOR));
        }
        cookies = cookies->next;
    }
    return true;
}

double NetHttpClientExec::GetTimingFromCurl(CURL *handle, CURLINFO info)
{
    time_t timing;
    CURLcode result = curl_easy_getinfo(handle, info, &timing);
    if (result != CURLE_OK) {
        NETSTACK_LOGE("Failed to get timing: %{public}d, %{public}s", info, curl_easy_strerror(result));
        return 0;
    }
    return TimeUtils::Microseconds2Milliseconds(timing);
}

void NetHttpClientExec::CacheCurlPerformanceTiming(CURL* handle, RequestContext* context)
{
    context->CachePerformanceTimingItem(
        RESPONSE_DNS_TIMING, NetHttpClientExec::GetTimingFromCurl(handle, CURLINFO_NAMELOOKUP_TIME_T));
    context->CachePerformanceTimingItem(
        RESPONSE_TCP_TIMING, NetHttpClientExec::GetTimingFromCurl(handle, CURLINFO_CONNECT_TIME_T));
    context->CachePerformanceTimingItem(
        RESPONSE_TLS_TIMING, NetHttpClientExec::GetTimingFromCurl(handle, CURLINFO_APPCONNECT_TIME_T));
    context->CachePerformanceTimingItem(
        RESPONSE_FIRST_SEND_TIMING, NetHttpClientExec::GetTimingFromCurl(handle, CURLINFO_PRETRANSFER_TIME_T));
    context->CachePerformanceTimingItem(RESPONSE_FIRST_RECEIVE_TIMING,
        NetHttpClientExec::GetTimingFromCurl(handle, CURLINFO_STARTTRANSFER_TIME_T));
    context->CachePerformanceTimingItem(
        RESPONSE_TOTAL_FINISH_TIMING, NetHttpClientExec::GetTimingFromCurl(handle, CURLINFO_TOTAL_TIME_T));
    context->CachePerformanceTimingItem(
        RESPONSE_REDIRECT_TIMING, NetHttpClientExec::GetTimingFromCurl(handle, CURLINFO_REDIRECT_TIME_T));
}

void NetHttpClientExec::HandleCurlData(CURLMsg *msg)
{
    if (msg == nullptr) {
        return;
    }

    auto handle = msg->easy_handle;
    if (handle == nullptr) {
        return;
    }

    auto it = staticVariable_.contextMap.find(handle);
    if (it == staticVariable_.contextMap.end()) {
        NETSTACK_LOGE("can not find context");
        return;
    }

    auto context = it->second;
    staticVariable_.contextMap.erase(it);
    if (context == nullptr) {
        NETSTACK_LOGE("can not find context");
        return;
    }
    NETSTACK_LOGI("priority = %{public}d", context->options.GetPriority());
    context->SetExecOK(GetCurlDataFromHandle(handle, context, msg->msg, msg->data.result));
    CacheCurlPerformanceTiming(handle, context);
    if (context->IsExecOK()) {
        CacheProxy proxy(context->options);
        proxy.WriteResponseToCache(context->response);
    }
    size_t callbackSize = 0;
    if (context->IsRequestInStream() && context->streamingCallback != nullptr) {
        callbackSize = context->streamingCallback->dataEnd.size();
    }
    // call onDataEnd
    if (callbackSize > 0) {
        for (size_t i = 0; i < callbackSize; i++) {
            context->streamingCallback->dataEnd[i]();
        }
    }
    context->SendResponse();
    delete context;
    context = nullptr;
}

std::string NetHttpClientExec::MakeUrl(const std::string &url, std::string param, const std::string &extraParam)
{
    if (param.empty()) {
        param += extraParam;
    } else {
        param += HTTP_URL_PARAM_SEPARATOR;
        param += extraParam;
    }

    if (param.empty()) {
        return url;
    }

    return url + HTTP_URL_PARAM_START + param;
}


bool NetHttpClientExec::MethodForGet(const std::string &method)
{
    return (method == HTTP_METHOD_HEAD || method == HTTP_METHOD_OPTIONS ||
            method == HTTP_METHOD_TRACE || method == HTTP_METHOD_GET ||
            method == HTTP_METHOD_CONNECT);
}

bool NetHttpClientExec::MethodForPost(const std::string &method)
{
    return (method == HTTP_METHOD_POST || method == HTTP_METHOD_PUT ||
            method == HTTP_METHOD_DELETE);
}

bool NetHttpClientExec::EncodeUrlParam(std::string &str)
{
    char encoded[4];
    std::string encodeOut;
    size_t length = strlen(str.c_str());
    for (size_t i = 0; i < length; ++i) {
        auto c = static_cast<uint8_t>(str.c_str()[i]);
        if (IsUnReserved(c)) {
            encodeOut += static_cast<char>(c);
        } else {
            if (sprintf_s(encoded, sizeof(encoded), "%%%02X", c) < 0) {
                return false;
            }
            encodeOut += encoded;
        }
    }

    if (str == encodeOut) {
        return false;
    }
    str = encodeOut;
    return true;
}

void NetHttpClientExec::AddRequestInfo()
{
    std::lock_guard guard(staticVariable_.curlMultiMutex);
    int num = 0;
    while (!staticVariable_.infoQueue.empty()) {
        if (!staticVariable_.runThread || staticVariable_.curlMulti == nullptr) {
            break;
        }

        auto info = staticVariable_.infoQueue.top();
        staticVariable_.infoQueue.pop();
        auto ret = curl_multi_add_handle(staticVariable_.curlMulti, info.handle);
        if (ret == CURLM_OK) {
            staticVariable_.contextMap[info.handle] = info.context;
        }

        ++num;
        if (num >= CURL_HANDLE_NUM) {
            break;
        }
    }
}

bool NetHttpClientExec::IsContextDeleted(RequestContext *context)
{
    if (context == nullptr) {
        return true;
    }
    {
        std::lock_guard<std::mutex> lockGuard(NetHttpClientExec::staticContextSet_.mutexForContextVec);
        auto it = std::find(NetHttpClientExec::staticContextSet_.contextSet.begin(),
                            NetHttpClientExec::staticContextSet_.contextSet.end(), context);
        if (it == NetHttpClientExec::staticContextSet_.contextSet.end()) {
            NETSTACK_LOGI("context has been deleted in libuv thread");
            return true;
        }
    }
    return false;
}

void NetHttpClientExec::RunThread()
{
    while (staticVariable_.runThread && staticVariable_.curlMulti != nullptr) {
        AddRequestInfo();
        SendRequest();
        ReadResponse();
        std::this_thread::sleep_for(std::chrono::milliseconds(CURL_TIMEOUT_MS));
        std::unique_lock l(staticVariable_.curlMultiMutex);
        staticVariable_.conditionVariable.wait_for(l, std::chrono::seconds(CONDITION_TIMEOUT_S), [] {
            return !staticVariable_.infoQueue.empty() || !staticVariable_.contextMap.empty();
        });
    }
}

void NetHttpClientExec::SendRequest()
{
    std::lock_guard guard(staticVariable_.curlMultiMutex);

    int runningHandle = 0;
    int num = 0;
    do {
        if (!staticVariable_.runThread || staticVariable_.curlMulti == nullptr) {
            break;
        }

        auto ret = curl_multi_perform(staticVariable_.curlMulti, &runningHandle);

        if (runningHandle > 0) {
            ret = curl_multi_poll(staticVariable_.curlMulti, nullptr, 0, CURL_MAX_WAIT_MSECS, nullptr);
        }

        if (ret != CURLM_OK) {
            return;
        }

        ++num;
        if (num >= CURL_HANDLE_NUM) {
            break;
        }
    } while (runningHandle > 0);
}

void NetHttpClientExec::ReadResponse()
{
    std::lock_guard guard(staticVariable_.curlMultiMutex);
    CURLMsg *msg = nullptr; /* NOLINT */
    do {
        if (!staticVariable_.runThread || staticVariable_.curlMulti == nullptr) {
            break;
        }

        int leftMsg;
        msg = curl_multi_info_read(staticVariable_.curlMulti, &leftMsg);
        if (msg) {
            if (msg->msg == CURLMSG_DONE) {
                HandleCurlData(msg);
            }
            if (msg->easy_handle) {
                (void)curl_multi_remove_handle(staticVariable_.curlMulti, msg->easy_handle);
                (void)curl_easy_cleanup(msg->easy_handle);
            }
        }
    } while (msg);
}

void NetHttpClientExec::GetGlobalHttpProxyInfo(std::string &host, int32_t &port, std::string &exclusions)
{
#ifdef HTTP_PROXY_ENABLE
    char httpProxyHost[SYSPARA_MAX_SIZE] = {0};
    char httpProxyPort[SYSPARA_MAX_SIZE] = {0};
    char httpProxyExclusions[SYSPARA_MAX_SIZE] = {0};
    GetParameter(HTTP_PROXY_HOST_KEY, DEFAULT_HTTP_PROXY_HOST, httpProxyHost, sizeof(httpProxyHost));
    GetParameter(HTTP_PROXY_PORT_KEY, DEFAULT_HTTP_PROXY_PORT, httpProxyPort, sizeof(httpProxyPort));
    GetParameter(HTTP_PROXY_EXCLUSIONS_KEY, DEFAULT_HTTP_PROXY_EXCLUSION_LIST, httpProxyExclusions,
                 sizeof(httpProxyExclusions));

    host = Decode(httpProxyHost);
    if (host == DEFAULT_HTTP_PROXY_HOST) {
        host = std::string();
    }
    exclusions = httpProxyExclusions;
    if (exclusions == DEFAULT_HTTP_PROXY_EXCLUSION_LIST) {
        exclusions = std::string();
    }

    port = std::atoi(httpProxyPort);
#endif
}

void NetHttpClientExec::GetHttpProxyInfo(RequestContext *context, std::string &host,
    int32_t &port, std::string &exclusions)
{
    if (context->options.GetUsingHttpProxyType() == UsingHttpProxyType::USE_DEFAULT) {
#ifdef HAS_NETMANAGER_BASE
        using namespace NetManagerStandard;
        HttpProxy httpProxy;
        NetConnClient::GetInstance().GetDefaultHttpProxy(httpProxy);
        host = httpProxy.GetHost();
        port = httpProxy.GetPort();
        exclusions = CommonUtils::ToString(httpProxy.GetExclusionList());
#else
        GetGlobalHttpProxyInfo(host, port, exclusions);
#endif
    } else if (context->options.GetUsingHttpProxyType() == UsingHttpProxyType::USE_SPECIFIED) {
        context->options.GetSpecifiedHttpProxy(host, port, exclusions);
    }
}

bool NetHttpClientExec::Initialize()
{
    std::lock_guard<std::mutex> lock(staticVariable_.mutexForInitialize);
    if (staticVariable_.initialized) {
        return true;
    }
    NETSTACK_LOGI("call curl_global_init");
    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
        NETSTACK_LOGE("Failed to initialize 'curl'");
        return false;
    }

    staticVariable_.curlMulti = curl_multi_init();
    if (staticVariable_.curlMulti == nullptr) {
        NETSTACK_LOGE("Failed to initialize 'curl_multi'");
        return false;
    }

    staticVariable_.workThread = std::thread(RunThread);

    staticVariable_.initialized = true;
    return staticVariable_.initialized;
}

bool NetHttpClientExec::SetOtherOption(CURL *curl, OHOS::NetStack::Http::RequestContext *context)
{
    std::string url = context->options.GetUrl();
    std::string host;
    std::string exclusions;
    int32_t port = 0;
    GetHttpProxyInfo(context, host, port, exclusions);
    if (!host.empty() && !CommonUtils::IsHostNameExcluded(url, exclusions, ",")) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PROXY, host.c_str(), context);
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PROXYPORT, port, context);
        auto curlTunnelValue = (url.find("https://") != std::string::npos) ? 1L : 0L;
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_HTTPPROXYTUNNEL, curlTunnelValue, context);
        auto proxyType = (host.find("https://") != std::string::npos) ? CURLPROXY_HTTPS : CURLPROXY_HTTP;
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PROXYTYPE, proxyType, context);
    }
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_CIPHER_LIST, TLS12_SECURITY_CIPHER_SUITE, context);
#ifdef NETSTACK_PROXY_PASS
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PROXYUSERPWD, NETSTACK_PROXY_PASS, context);
#endif // NETSTACK_PROXY_PASS

#ifdef HTTP_CURL_PRINT_VERBOSE
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_VERBOSE, 1L, context);
#endif

#ifndef WINDOWS_PLATFORM
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_ACCEPT_ENCODING, "", context);
#endif
    return true;
}

CURLcode MultiPathSslCtxFunction(CURL *curl, void *sslCtx, const CertsPath *certsPath)
{
#ifdef HTTP_MULTIPATH_CERT_ENABLE
    if (certsPath == nullptr) {
        NETSTACK_LOGE("certsPath is null");
        return CURLE_SSL_CERTPROBLEM;
    }
    if (sslCtx == nullptr) {
        NETSTACK_LOGE("ssl_ctx is null");
        return CURLE_SSL_CERTPROBLEM;
    }

    for (const auto &path : certsPath->certPathList) {
        if (path.empty() || access(path.c_str(), F_OK) != 0) {
            NETSTACK_LOGD("certificate directory path is not exist");
            continue;
        }
        if (!SSL_CTX_load_verify_locations(static_cast<SSL_CTX *>(sslCtx), nullptr, path.c_str())) {
            NETSTACK_LOGE("loading certificates from directory error.");
            continue;
        }
    }
    if (access(certsPath->certFile.c_str(), F_OK) != 0) {
        NETSTACK_LOGD("certificate directory path is not exist");
    } else if (!SSL_CTX_load_verify_locations(static_cast<SSL_CTX *>(sslCtx), certsPath->certFile.c_str(), nullptr)) {
        NETSTACK_LOGE("loading certificates from context cert error.");
    }
#endif // HTTP_MULTIPATH_CERT_ENABLE
    return CURLE_OK;
}

#ifdef HTTP_ONLY_VERIFY_ROOT_CA_ENABLE
static int VerifyCertPubkey(X509 *cert, const std::string &pinnedPubkey)
{
    if (pinnedPubkey.empty()) {
        // if no pinned pubkey specified, don't pin (Curl default)
        return CURLE_OK;
    }
    if (cert == nullptr) {
        NETSTACK_LOGE("no cert specified.");
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    unsigned char *certPubkey = nullptr;
    int pubkeyLen = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &certPubkey);
    std::string certPubKeyDigest;
    if (!CommonUtils::Sha256sum(certPubkey, pubkeyLen, certPubKeyDigest)) {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    NETSTACK_LOGI("pubkey sha256: %{public}s", certPubKeyDigest.c_str());
    if (CommonUtils::IsCertPubKeyInPinned(certPubKeyDigest, pinnedPubkey)) {
        return CURLE_OK;
    }
    return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
}

static int VerifyCallback(int preverifyOk, X509_STORE_CTX *ctx)
{
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    int err = X509_STORE_CTX_get_error(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);

    NETSTACK_LOGI("X509_STORE_CTX error code %{public}d, depth %{public}d", err, depth);

    SSL *ssl = static_cast<SSL *>(X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
    SSL_CTX *sslctx = SSL_get_SSL_CTX(ssl);
    RequestContext *requestContext = static_cast<RequestContext *>(SSL_CTX_get_ex_data(sslctx,
        SSL_CTX_EX_DATA_REQUEST_CONTEXT_INDEX));
    if (requestContext == nullptr) {
        NETSTACK_LOGE("creat requestContext instance failed");
        return 0;
    }
    if (requestContext->IsRootCaVerifiedOk()) {
        // root CA hash verified, normal procedure.
        return preverifyOk;
    }

    int verifyResult = VerifyCertPubkey(cert, requestContext->GetPinnedPubkey());
    if (!requestContext->IsRootCaVerified()) {
        // not verified yet, so this is the root CA verifying.
        NETSTACK_LOGD("Verifying Root CA.");
        requestContext->SetRootCaVerifiedOk(verifyResult == CURLE_OK);
        requestContext->SetRootCaVerified();
    }
    if (verifyResult != CURLE_OK && depth == 0) {
        // peer site certificate, since root ca verify not ok, and peer site is also not ok
        // return failed.
        return 0;
    }
    return preverifyOk;
}
#endif  // HTTP_ONLY_VERIFY_ROOT_CA_ENABLE

CURLcode VerifyRootCaSslCtxFunction(CURL *curl, void *sslCtx, void *context)
{
#ifdef HTTP_ONLY_VERIFY_ROOT_CA_ENABLE
    SSL_CTX *ctx = static_cast<SSL_CTX *>(sslCtx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, VerifyCallback);
    SSL_CTX_set_ex_data(ctx, SSL_CTX_EX_DATA_REQUEST_CONTEXT_INDEX, context);
#endif
    return CURLE_OK;
}

CURLcode SslCtxFunction(CURL *curl, void *sslCtx, void *parm)
{
    auto requestContext = static_cast<RequestContext *>(parm);
    if (requestContext == nullptr) {
        NETSTACK_LOGE("requestContext is null");
        return CURLE_SSL_CERTPROBLEM;
    }
    CURLcode result = MultiPathSslCtxFunction(curl, sslCtx, &requestContext->GetCertsPath());
    if (result != CURLE_OK) {
        return result;
    }
    if (!requestContext->GetPinnedPubkey().empty()) {
        return VerifyRootCaSslCtxFunction(curl, sslCtx, requestContext);
    }
    return CURLE_OK;
}

bool NetHttpClientExec::SetServerSSLCertOption(CURL *curl, OHOS::NetStack::Http::RequestContext *context)
{
#ifndef NO_SSL_CERTIFICATION
#ifdef HAS_NETMANAGER_BASE
    auto hostname = CommonUtils::GetHostnameFromURL(context->options.GetUrl());
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    std::vector<std::string> certs;
    // add app cert path
    auto ret = NetworkSecurityConfig::GetInstance().GetTrustAnchorsForHostName(hostname, certs);
    if (ret != 0) {
        NETSTACK_LOGE("GetTrustAnchorsForHostName error. ret [%{public}d]", ret);
    }
#ifdef HTTP_MULTIPATH_CERT_ENABLE
    // add user cert path
    certs.emplace_back(USER_CERT_ROOT_PATH);
    certs.emplace_back(BASE_PATH + std::to_string(getuid() / UID_TRANSFORM_DIVISOR));
    // add system cert path
    certs.emplace_back(HTTP_PREPARE_CA_PATH);
    context->SetCertsPath(std::move(certs), context->options.GetCaPath());
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYPEER, 1L, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYHOST, 2L, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_CAINFO, nullptr, context);
#else
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_CAINFO, nullptr, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYPEER, 0L, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYHOST, 0L, context);
#endif // HTTP_MULTIPATH_CERT_ENABLE
#else
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYPEER, 0L, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYHOST, 0L, context);
#endif //  !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    // pin trusted certifcate keys.
    std::string pins;
    if (NetworkSecurityConfig::GetInstance().GetPinSetForHostName(hostname, pins) != 0 || pins.empty()) {
        NETSTACK_LOGD("Get no pinset by host name");
    } else if (NetworkSecurityConfig::GetInstance().IsPinOpenModeVerifyRootCa(hostname)) {
        context->SetPinnedPubkey(pins);
    } else {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PINNEDPUBLICKEY, pins.c_str(), context);
    }
#if defined(HTTP_MULTIPATH_CERT_ENABLE) || defined(HTTP_ONLY_VERIFY_ROOT_CA_ENABLE)
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_CTX_FUNCTION, SslCtxFunction, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_CTX_DATA, context, context);
#endif
#else
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_CAINFO, nullptr, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYPEER, 0L, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYHOST, 0L, context);
#endif // HAS_NETMANAGER_BASE
#else
    // in real life, you should buy a ssl certification and rename it to /etc/ssl/cert.pem
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYHOST, 0L, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYPEER, 0L, context);
#endif // NO_SSL_CERTIFICATION

    return true;
}

bool NetHttpClientExec::SetMultiPartOption(CURL *curl, RequestContext *context)
{
    auto header =  context->options.GetHeader();
    auto type = CommonUtils::ToLower(header[HTTP_CONTENT_TYPE]);
    if (type != HTTP_CONTENT_TYPE_MULTIPART) {
        return true;
    }
    auto multiPartDataList = context->options.GetMultiPartDataList();
    if (multiPartDataList.empty()) {
        return true;
    }
    curl_mime *multipart = curl_mime_init(curl);
    if (multipart == nullptr) {
        return false;
    }
    context->SetMultipart(multipart);
    curl_mimepart *part = nullptr;
    bool hasData = false;
    for (auto &multiFormData : multiPartDataList) {
        if (multiFormData.name.empty()) {
            continue;
        }
        if (multiFormData.data.empty() && multiFormData.filePath.empty()) {
            NETSTACK_LOGE("Failed to set name error no data and filepath at the same time");
            continue;
        }
        part = curl_mime_addpart(multipart);
        SetFormDataOption(multiFormData, part, curl, context);
        hasData = true;
    }
    if (hasData) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_MIMEPOST, multipart, context);
    }
    return true;
}

void NetHttpClientExec::SetFormDataOption(MultiFormData &multiFormData, curl_mimepart *part,
    CURL *curl, RequestContext *context)
{
    CURLcode result = curl_mime_name(part, multiFormData.name.c_str());
    if (result != CURLE_OK) {
        NETSTACK_LOGE("Failed to set name error: %{public}s", curl_easy_strerror(result));
        return;
    }
    if (!multiFormData.contentType.empty()) {
        result = curl_mime_type(part, multiFormData.contentType.c_str());
        if (result != CURLE_OK) {
            NETSTACK_LOGE("Failed to set contentType error: %{public}s", curl_easy_strerror(result));
        }
    }
    if (!multiFormData.remoteFileName.empty()) {
        result = curl_mime_filename(part, multiFormData.remoteFileName.c_str());
        if (result != CURLE_OK) {
            NETSTACK_LOGE("Failed to set remoteFileName error: %{public}s", curl_easy_strerror(result));
        }
    }
    if (!multiFormData.data.empty()) {
        result = curl_mime_data(part, multiFormData.data.c_str(), multiFormData.data.length());
        if (result != CURLE_OK) {
            NETSTACK_LOGE("Failed to set data error: %{public}s", curl_easy_strerror(result));
        }
    } else {
        result = curl_mime_filedata(part, multiFormData.filePath.c_str());
        if (result != CURLE_OK) {
            NETSTACK_LOGE("Failed to set file data error: %{public}s", curl_easy_strerror(result));
        }
    }
}

bool NetHttpClientExec::SetSSLCertOption(CURL *curl, OHOS::NetStack::Http::RequestContext *context)
{
    std::string cert;
    std::string certType;
    std::string key;
    SecureChar keyPasswd;
    context->options.GetClientCert(cert, certType, key, keyPasswd);
    if (cert.empty()) {
        NETSTACK_LOGI("SetSSLCertOption param is empty.");
        return false;
    }
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSLCERT, cert.c_str(), context);
    if (!key.empty()) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSLKEY, key.c_str(), context);
    }
    if (!certType.empty()) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSLCERTTYPE, certType.c_str(), context);
    }
    if (keyPasswd.Length() > 0) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_KEYPASSWD, keyPasswd.Data(), context);
    }
    return true;
}

bool NetHttpClientExec::SetDnsOption(CURL *curl, RequestContext *context)
{
    std::vector<std::string> dnsServers = context->options.GetDnsServers();
    if (dnsServers.empty()) {
        return true;
    }
    std::string serverList;
    for (auto &server : dnsServers) {
        serverList += server + ",";
        NETSTACK_LOGI("SetDns server: %{public}s", CommonUtils::AnonymizeIp(server).c_str());
    }
    serverList.pop_back();
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_DNS_SERVERS, serverList.c_str(), context);
    return true;
}

bool NetHttpClientExec::SetRequestOption(CURL *curl, RequestContext *context)
{
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_HTTP_VERSION, context->options.GetHttpVersion(), context);
    const std::string range = context->options.GetRangeString();
    if (range.empty()) {
        // Some servers don't like requests that are made without a user-agent field, so we provide one
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_USERAGENT, HTTP_DEFAULT_USER_AGENT, context);
    } else {
        // https://curl.se/libcurl/c/CURLOPT_RANGE.html
        if (context->options.GetMethod() == HTTP_METHOD_PUT) {
            context->SetErrorCode(CURLE_RANGE_ERROR);
            NETSTACK_LOGE("For HTTP PUT uploads this option should not be used, since it may conflict with \
                          other options.");
            return false;
        }
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_RANGE, range.c_str(), context);
    }
    if (!context->options.GetDohUrl().empty()) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_DOH_URL, context->options.GetDohUrl().c_str(), context);
    }
    SetDnsOption(curl, context);
    SetSSLCertOption(curl, context);
    SetMultiPartOption(curl, context);
    return true;
}

bool NetHttpClientExec::SetOption(CURL *curl, RequestContext *context, struct curl_slist *requestHeader)
{
    const std::string &method = context->options.GetMethod();
    if (!MethodForGet(method) && !MethodForPost(method)) {
        NETSTACK_LOGE("method %{public}s not supported", method.c_str());
        return false;
    }

    if (context->options.GetMethod() == HTTP_METHOD_HEAD) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_NOBODY, 1L, context);
    }

    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_URL, context->options.GetUrl().c_str(), context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_CUSTOMREQUEST, method.c_str(), context);

    if (MethodForPost(method) && !context->options.GetBody().empty()) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_POST, 1L, context);
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_POSTFIELDS, context->options.GetBody().c_str(), context);
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_POSTFIELDSIZE, context->options.GetBody().size(), context);
    }

    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_XFERINFOFUNCTION, ProgressCallback, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_XFERINFODATA, context, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_NOPROGRESS, 0L, context);

    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_WRITEFUNCTION, OnWritingMemoryBody, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_WRITEDATA, context, context);

    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_HEADERFUNCTION, OnWritingMemoryHeader, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_HEADERDATA, context, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_HTTPHEADER, requestHeader, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_FOLLOWLOCATION, 1L, context);

    /* first #undef CURL_DISABLE_COOKIES in curl config */
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_COOKIEFILE, "", context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_NOSIGNAL, 1L, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_TIMEOUT_MS, context->options.GetReadTimeout(), context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_CONNECTTIMEOUT_MS, context->options.GetConnectTimeout(), context);

    SetRequestOption(curl, context);

    if (!SetOtherOption(curl, context)) {
        return false;
    }
    return true;
}

size_t NetHttpClientExec::OnWritingMemoryBody(const void *data, size_t size, size_t memBytes, void *userData)
{
    auto context = static_cast<RequestContext *>(userData);
    if (context == nullptr) {
        return 0;
    }
    if (context->IsDestroyed()) {
        context->StopAndCachePerformanceTiming(RESPONSE_BODY_TIMING);
        return 0;
    }
    size_t callbackSize = 0;
    if (context->streamingCallback != nullptr) {
        callbackSize = context->streamingCallback->dataReceive.size();
    }
    if (context->IsRequestInStream() && callbackSize > 0) {
        context->SetTempData(data, size * memBytes);
        // call OnDataReceive
        auto tmp = context->GetTempData();
        context->PopTempData();
        for (size_t i = 0; i < callbackSize; i++) {
            CArrUI8 body;
            body.head = reinterpret_cast<uint8_t*>(MallocCString(tmp));
            body.size = static_cast<int64_t>(tmp.size());
            context->streamingCallback->dataReceive[i](body);
        }
        context->StopAndCachePerformanceTiming(RESPONSE_BODY_TIMING);
        return size * memBytes;
    }
    if (context->response.GetResult().size() > context->options.GetMaxLimit()) {
        NETSTACK_LOGE("response data exceeds the maximum limit");
        context->StopAndCachePerformanceTiming(RESPONSE_BODY_TIMING);
        return 0;
    }
    context->response.AppendResult(data, size * memBytes);
    context->StopAndCachePerformanceTiming(RESPONSE_BODY_TIMING);
    return size * memBytes;
}

static std::map<std::string, std::string> MakeHeaderWithSetCookie(RequestContext *context)
{
    std::map<std::string, std::string> tempMap = context->response.GetHeader();
    std::string setCookies;
    size_t loop = 0;
    for (const auto &setCookie : context->response.GetsetCookie()) {
        setCookies += setCookie;
        if (loop + 1 < context->response.GetsetCookie().size()) {
            setCookies += HTTP_LINE_SEPARATOR;
        }
        ++loop;
    }
    tempMap[RESPONSE_KEY_SET_COOKIE] = setCookies;
    return tempMap;
}

size_t NetHttpClientExec::OnWritingMemoryHeader(const void *data, size_t size, size_t memBytes, void *userData)
{
    auto context = static_cast<RequestContext *>(userData);
    if (context == nullptr) {
        return 0;
    }
    if (context->IsDestroyed()) {
        context->StopAndCachePerformanceTiming(RESPONSE_HEADER_TIMING);
        return 0;
    }
    if (context->response.GetResult().size() > context->options.GetMaxLimit()) {
        NETSTACK_LOGE("response data exceeds the maximum limit");
        context->StopAndCachePerformanceTiming(RESPONSE_HEADER_TIMING);
        return 0;
    }
    context->response.AppendRawHeader(data, size * memBytes);
    if (CommonUtils::EndsWith(context->response.GetRawHeader(), HTTP_RESPONSE_HEADER_SEPARATOR)) {
        context->response.ParseHeaders();
        int callbackSize = 0;
        int callOnceSize = 0;
        if (context->streamingCallback) {
            callbackSize = static_cast<int>(context->streamingCallback->headersReceive.size());
            callOnceSize = static_cast<int>(context->streamingCallback->headersReceiveOnce.size());
        }
        
        // call onHeadersReceive
        if (!context->IsDestroyed() && (callbackSize > 0 || callOnceSize > 0)) {
            auto headersMap = MakeHeaderWithSetCookie(context);
            for (int i = 0; i < callbackSize; i++) {
                auto ret = g_map2CArrString(headersMap);
                context->streamingCallback->headersReceive[i](ret);
            }
            for (int i = 0; i < callOnceSize; i++) {
                auto ret = g_map2CArrString(headersMap);
                context->streamingCallback->headersReceiveOnce[i](ret);
            }
            context->streamingCallback->headersReceiveOnce.clear();
        }
    }
    context->StopAndCachePerformanceTiming(RESPONSE_HEADER_TIMING);
    return size * memBytes;
}

struct curl_slist *NetHttpClientExec::MakeHeaders(const std::vector<std::string> &vec)
{
    struct curl_slist *header = nullptr;
    std::for_each(vec.begin(), vec.end(), [&header](const std::string &s) {
        if (!s.empty()) {
            header = curl_slist_append(header, s.c_str());
        }
    });
    return header;
}

int NetHttpClientExec::ProgressCallback(void *userData, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal,
    curl_off_t ulnow)
{
    auto context = static_cast<RequestContext*>(userData);
    if (context == nullptr) {
        return 0;
    }
    if (ultotal != 0 && ultotal >= ulnow && !context->CompareWithLastElement(ulnow, ultotal)) {
        context->SetUlLen(ulnow, ultotal);
        size_t callbackSize = 0;
        if (context->streamingCallback != nullptr) {
            callbackSize = context->streamingCallback->dataSendProgress.size();
        }
        // call OnDataUploadProgress
        if (!IsContextDeleted(context) && callbackSize > 0) {
            auto ulLen = context->GetUlLen();
            for (size_t i = 0; i < callbackSize; i++) {
                CDataSendProgressInfo info = {.sendSize = ulLen.nLen, .totalSize = ulLen.tLen};
                context->streamingCallback->dataSendProgress[i](info);
            }
        }
    }
    if (!context->IsRequestInStream()) {
        return 0;
    }
    if (dltotal != 0) {
        context->SetDlLen(dlnow, dltotal);
        int callbackSize = 0;
        if (context->streamingCallback != nullptr) {
            callbackSize = static_cast<int>(context->streamingCallback->dataReceiveProgress.size());
        }

        // call OnDataProgress
        if (!IsContextDeleted(context) && callbackSize > 0 && dlnow != 0) {
            auto dlLen = context->GetDlLen();
            for (int i = 0; i < callbackSize; i++) {
                CDataReceiveProgressInfo info = {.receiveSize = dlLen.nLen, .totalSize = dlLen.tLen};
                context->streamingCallback->dataReceiveProgress[i](info);
            }
        }
    }
    return 0;
}

bool NetHttpClientExec::IsUnReserved(unsigned char in)
{
    if ((in >= '0' && in <= '9') || (in >= 'a' && in <= 'z') || (in >= 'A' && in <= 'Z')) {
        return true;
    }
    switch (in) {
        case '-':
        case '.':
        case '_':
        case '~':
            return true;
        default:
            break;
    }
    return false;
}

bool NetHttpClientExec::IsInitialized()
{
    return staticVariable_.initialized;
}

void NetHttpClientExec::DeInitialize()
{
    std::lock_guard<std::mutex> lock(staticVariable_.curlMultiMutex);
    staticVariable_.runThread = false;
    staticVariable_.conditionVariable.notify_all();
    if (staticVariable_.workThread.joinable()) {
        staticVariable_.workThread.join();
    }
    if (staticVariable_.curlMulti) {
        curl_multi_cleanup(staticVariable_.curlMulti);
    }
    staticVariable_.initialized = false;
}
}