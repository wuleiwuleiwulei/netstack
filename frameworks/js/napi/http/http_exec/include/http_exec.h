/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMMUNICATIONNETSTACK_HTTP_REQUEST_EXEC_H
#define COMMUNICATIONNETSTACK_HTTP_REQUEST_EXEC_H

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <utility>
#include <vector>
#include <set>
#ifdef HTTP_MULTIPATH_CERT_ENABLE
#include <openssl/ssl.h>
#endif

#include "curl/curl.h"
#include "napi/native_api.h"
#include "request_context.h"

namespace OHOS::NetStack::HttpOverCurl {
    struct TransferCallbacks;
}

namespace OHOS::NetStack::Http {

#if !HAS_NETMANAGER_BASE
static constexpr int CURL_TIMEOUT_MS = 20;
static constexpr int CONDITION_TIMEOUT_S = 3600;
static constexpr int CURL_MAX_WAIT_MSECS = 10;
static constexpr int CURL_HANDLE_NUM = 10;
#endif
static constexpr const uint32_t EVENT_PARAM_ZERO = 0;
static constexpr const uint32_t EVENT_PARAM_ONE = 1;
static constexpr const uint32_t EVENT_PARAM_TWO = 2;
static constexpr const char *TLS12_SECURITY_CIPHER_SUITE = R"(DEFAULT:!eNULL:!EXPORT)";
#if !HAS_NETMANAGER_BASE
static constexpr const char *HTTP_TASK_RUN_THREAD = "OS_NET_TaskHttp";
static constexpr const char *HTTP_CLIENT_TASK_THREAD = "OS_NET_HttpJs";
#endif

#if HAS_NETMANAGER_BASE
static constexpr const char *HTTP_REQ_TRACE_NAME = "HttpRequest";
#endif

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

static constexpr const char *HTTP_AF_ONLYV4 = "ONLY_V4";
static constexpr const char *HTTP_AF_ONLYV6 = "ONLY_V6";
static int64_t g_limitSdkReport = 0;
constexpr long HTTP_STATUS_REDIRECT_START = 300;
constexpr long HTTP_STATUS_CLIENT_ERROR_START = 400;

[[maybe_unused]] static void RequestContextDeleter(RequestContext *context)
{
    context->DeleteReference();
    delete context;
    context = nullptr;
}

class HttpResponseCacheExec final {
public:
    HttpResponseCacheExec() = default;

    ~HttpResponseCacheExec() = default;

    static bool ExecFlush(BaseContext *context);

    static napi_value FlushCallback(BaseContext *context);

    static bool ExecDelete(BaseContext *context);

    static napi_value DeleteCallback(BaseContext *context);
};

class HttpExec final {
public:
    HttpExec() = default;

    ~HttpExec() = default;

    static bool RequestWithoutCache(RequestContext *context);

    static bool ExecRequest(RequestContext *context);

    static bool HandleInitialRequestPostProcessing(
        RequestContext *context, HiAppEventReport hiAppEventReport, int64_t &limitSdkReport);

    static napi_value BuildRequestCallback(RequestContext *context);

    static napi_value RequestCallback(RequestContext *context);

    static napi_value RequestInStreamCallback(RequestContext *context);

    static std::string MakeUrl(const std::string &url, std::string param, const std::string &extraParam);

    static bool MethodForGet(const std::string &method);

    static bool MethodForPost(const std::string &method);

    static bool EncodeUrlParam(std::string &str);

    static bool ParseHostAndPortFromUrl(const std::string &url, std::string &host, uint16_t &port);

    static void AsyncWorkRequestCallback(napi_env env, napi_status status, void *data);

    static bool GetCurlDataFromHandle(CURL *handle, RequestContext *context, CURLMSG curlMsg, CURLcode result);

#if !HAS_NETMANAGER_BASE
    static bool Initialize();

    static bool IsInitialized();

    static void DeInitialize();
#endif

    static void AsyncRunRequest(RequestContext *context);

    static void EnqueueCallback(RequestContext *context);

    static std::map<std::string, std::string> MakeHeaderWithSetCookie(RequestContext *context);

    static void ResponseHeaderCallback(uv_work_t *work, int status);

    static void ProcessResponseBodyAndEmitEvents(RequestContext *context);

    static void ProcessResponseHeadersAndEmitEvents(RequestContext *context);

private:
    static bool SetOption(CURL *curl, RequestContext *context, struct curl_slist *requestHeader);

    static bool SetOtherOption(CURL *curl, RequestContext *context);

    static bool SetOtherFixedOption(CURL *curl, RequestContext *context);

    static bool SetAuthOptions(CURL *curl, OHOS::NetStack::Http::RequestContext *context);

    static bool SetRequestOption(void *curl, RequestContext *context);

    static bool SetSSLCertOption(CURL *curl, RequestContext *context);

    static bool SetServerSSLCertOption(CURL *curl, OHOS::NetStack::Http::RequestContext *context);

    static bool SetDnsOption(CURL *curl, RequestContext *context);

    static bool SetDnsResolvOption(CURL *curl, RequestContext *context);

    static bool SetTCPOption(CURL *curl, RequestContext *context);

    static bool SetCertPinnerOption(CURL *curl, RequestContext *context);

#if HAS_NETMANAGER_BASE
    static void SetRequestInfoCallbacks(HttpOverCurl::TransferCallbacks &callbacks);
#endif

    static size_t OnWritingMemoryBody(const void *data, size_t size, size_t memBytes, void *userData);

    static size_t OnWritingMemoryHeader(const void *data, size_t size, size_t memBytes, void *userData);

    static struct curl_slist *MakeHeaders(const std::vector<std::string> &vec);

    static napi_value MakeResponseHeader(napi_env env, void *ctx);

    static bool IsUnReserved(unsigned char in);

    static bool ProcByExpectDataType(napi_value object, RequestContext *context);

    static bool AddCurlHandle(CURL *handle, RequestContext *context);

#if ENABLE_HTTP_INTERCEPT
    static bool SetFollowLocation(CURL *handle, RequestContext *context);
#endif

#if HAS_NETMANAGER_BASE
    static void HandleCurlData(CURLMsg *msg, RequestContext *context);
#else
    static void HandleCurlData(CURLMsg *msg);
#endif

    static double GetTimingFromCurl(CURL *handle, CURLINFO info);

    static void CacheCurlPerformanceTiming(CURL *handle, RequestContext *context);

    static curl_off_t GetSizeFromCurl(CURL *handle, RequestContext *context);

    static bool SetSslTypeAndClientEncCert(CURL *curl, RequestContext *context);

#if !HAS_NETMANAGER_BASE
    static void RunThread();

    static void SendRequest();

    static void ReadResponse();
#endif

    static void GetGlobalHttpProxyInfo(std::string &host, int32_t &port, std::string &exclusions);

    static void GetHttpProxyInfo(RequestContext *context, std::string &host, int32_t &port, std::string &exclusions,
        NapiUtils::SecureData &username, NapiUtils::SecureData &password);

    static void OnDataReceive(napi_env env, napi_status status, void *data);

    static void OnDataProgress(napi_env env, napi_status status, void *data);

    static void OnDataUploadProgress(napi_env env, napi_status status, void *data);

    static int ProgressCallback(void *userData, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal,
                                curl_off_t ulnow);

    static bool SetMultiPartOption(void *curl, RequestContext *context);

    static void SetFormDataOption(MultiFormData &multiFormData, curl_mimepart *part,
                                  void *curl, RequestContext *context);

    static bool IsBuiltWithOpenSSL();

#if !HAS_NETMANAGER_BASE
    static void AddRequestInfo();
#endif

    static CURLcode SslCtxFunction(void *curl, void *ssl_ctx, void *parm);
    static CURLcode MultiPathSslCtxFunction(CURL *curl, void *ssl_ctx, void *request_context);
    static CURLcode VerifyRootCaSslCtxFunction(CURL *curl, void *ssl_ctx, void *context);

    static bool SetDnsCacheOption(CURL *curl, RequestContext *context);

    static bool SetIpResolve(CURL *curl, RequestContext *context);

    static void FinalResponseProcessing(RequestContext *requestContext);

    struct RequestInfo {
        RequestInfo() = delete;
        ~RequestInfo() = default;

        RequestInfo(RequestContext *c, CURL *h)
        {
            context = c;
            handle = h;
        }

        RequestContext *context;
        CURL *handle;

        bool operator<(const RequestInfo &info) const
        {
            return context->options.GetPriority() < info.context->options.GetPriority();
        }

        bool operator>(const RequestInfo &info) const
        {
            return context->options.GetPriority() > info.context->options.GetPriority();
        }
    };

#if !HAS_NETMANAGER_BASE
    struct StaticVariable {
        StaticVariable() : curlMulti(nullptr), initialized(false), runThread(true) {}

        ~StaticVariable()
        {
            if (HttpExec::IsInitialized()) {
                HttpExec::DeInitialize();
            }
        }

        std::mutex curlMultiMutex;
        std::mutex mutexForInitialize;
        CURLM *curlMulti;
        std::map<CURL *, RequestContext *> contextMap;
        std::thread workThread;
        std::condition_variable conditionVariable;
        std::priority_queue<RequestInfo> infoQueue;

#ifndef MAC_PLATFORM
        std::atomic_bool initialized;
        std::atomic_bool runThread;
#else
        bool initialized;
        bool runThread;
#endif
    };
    static StaticVariable staticVariable_;
#endif
};
} // namespace OHOS::NetStack::Http

#endif /* COMMUNICATIONNETSTACK_HTTP_REQUEST_EXEC_H */
