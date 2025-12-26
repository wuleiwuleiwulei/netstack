/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "request_context.h"

#include <algorithm>
#include <atomic>
#include <limits>
#include <string>
#include <utility>
#include <sstream>

#include "constant.h"
#include "http_exec.h"
#include "http_tls_config.h"
#include "napi_utils.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "request_tracer.h"
#include "secure_char.h"
#include "timing.h"
#if HAS_NETMANAGER_BASE
#include "http_network_message.h"
#endif
#ifdef HTTP_HANDOVER_FEATURE
#include "http_handover_handler.h"
#include "http_handover_info.h"
#endif

static constexpr const int PARAM_JUST_URL = 1;

static constexpr const int PARAM_JUST_URL_OR_CALLBACK = 1;

static constexpr const int PARAM_URL_AND_OPTIONS_OR_CALLBACK = 2;

static constexpr const int PARAM_URL_AND_OPTIONS_AND_CALLBACK = 3;

static constexpr const uint32_t DNS_SERVER_SIZE = 3;

static constexpr size_t CADATA_STRING_MAX_LENGTH = 8000;
namespace OHOS::NetStack::Http {
static const std::map<int32_t, const char *> HTTP_ERR_MAP = {
    {HTTP_UNSUPPORTED_PROTOCOL, "Unsupported protocol"},
    {HTTP_URL_MALFORMAT, "Invalid URL format or missing URL"},
    {HTTP_COULDNT_RESOLVE_PROXY, "Failed to resolve the proxy name"},
    {HTTP_COULDNT_RESOLVE_HOST, "Failed to resolve the host name"},
    {HTTP_COULDNT_CONNECT, "Failed to connect to the server"},
    {HTTP_WEIRD_SERVER_REPLY, "Invalid server response"},
    {HTTP_REMOTE_ACCESS_DENIED, "Access to the remote resource denied"},
    {HTTP_HTTP2_ERROR, "Error in the HTTP2 framing layer"},
    {HTTP_PARTIAL_FILE, "Transferred a partial file"},
    {HTTP_WRITE_ERROR, "Failed to write the received data to the disk or application"},
    {HTTP_UPLOAD_FAILED, "Upload failed"},
    {HTTP_READ_ERROR, "Failed to open or read local data from the file or application"},
    {HTTP_OUT_OF_MEMORY, "Out of memory"},
    {HTTP_OPERATION_TIMEDOUT, "Operation timeout"},
    {HTTP_TOO_MANY_REDIRECTS, "The number of redirections reaches the maximum allowed"},
    {HTTP_GOT_NOTHING, "The server returned nothing (no header or data)"},
    {HTTP_SEND_ERROR, "Failed to send data to the peer"},
    {HTTP_RECV_ERROR, "Failed to receive data from the peer"},
    {HTTP_SSL_CERTPROBLEM, "Local SSL certificate error"},
    {HTTP_SSL_CIPHER, "The specified SSL cipher cannot be used"},
    {HTTP_PEER_FAILED_VERIFICATION, "Invalid SSL peer certificate or SSH remote key"},
    {HTTP_BAD_CONTENT_ENCODING, "Invalid HTTP encoding format"},
    {HTTP_FILESIZE_EXCEEDED, "Maximum file size exceeded"},
    {HTTP_REMOTE_DISK_FULL, "Remote disk full"},
    {HTTP_REMOTE_FILE_EXISTS, "Remote file already exists"},
    {HTTP_SSL_CACERT_BADFILE, "The SSL CA certificate does not exist or is inaccessible"},
    {HTTP_REMOTE_FILE_NOT_FOUND, "Remote file not found"},
    {HTTP_AUTH_ERROR, "Authentication error"},
    {HTTP_SSL_PINNEDPUBKEYNOTMATCH, "Specified pinned public key did not match"},
    {HTTP_CLEARTEXT_NOT_PERMITTED, "Cleartext traffic not permitted"},
    {HTTP_NOT_ALLOWED_HOST, "It is not allowed to access this domain"},
    {HTTP_UNKNOWN_OTHER_ERROR, "Internal error"},
};
static std::atomic<int32_t> g_currentTaskId = std::numeric_limits<int32_t>::min();
RequestContext::RequestContext(napi_env env, const std::shared_ptr<EventManager> &manager)
    : BaseContext(env, manager),
      taskId_(g_currentTaskId++),
      usingCache_(true),
      requestInStream_(false),
      curlHeaderList_(nullptr),
      multipart_(nullptr),
      curlHostList_(nullptr),
      isAtomicService_(false),
      bundleName_(""),
      trace_("HttpRequest_" + std::to_string(taskId_))
{
    StartTiming();
#if HAS_NETMANAGER_BASE
    networkProfilerUtils_ = std::make_unique<NetworkProfilerUtils>();
#endif
}

void RequestContext::StartTiming()
{
    time_t startTime = Timing::TimeUtils::GetNowTimeMicroseconds();
    timerMap_.RecieveTimer(HttpConstant::RESPONSE_HEADER_TIMING).Start(startTime);
    timerMap_.RecieveTimer(HttpConstant::RESPONSE_BODY_TIMING).Start(startTime);
    timerMap_.RecieveTimer(HttpConstant::RESPONSE_TOTAL_TIMING).Start(startTime);

    // init RESPONSE_HEADER_TIMING and RESPONSE_BODY_TIMING
    performanceTimingMap_[HttpConstant::RESPONSE_HEADER_TIMING] = 0.0;
    performanceTimingMap_[HttpConstant::RESPONSE_BODY_TIMING] = 0.0;
}

void RequestContext::ParseParams(napi_value *params, size_t paramsCount)
{
    bool valid = CheckParamsType(params, paramsCount);
    if (!valid) {
        if (paramsCount == PARAM_JUST_URL_OR_CALLBACK) {
            if (NapiUtils::GetValueType(GetEnv(), params[0]) == napi_function) {
                SetCallback(params[0]);
            }
            return;
        }
        if (paramsCount == PARAM_URL_AND_OPTIONS_OR_CALLBACK) {
            if (NapiUtils::GetValueType(GetEnv(), params[1]) == napi_function) {
                SetCallback(params[1]);
            }
            return;
        }
        if (paramsCount == PARAM_URL_AND_OPTIONS_AND_CALLBACK) {
            if (NapiUtils::GetValueType(GetEnv(), params[PARAM_URL_AND_OPTIONS_AND_CALLBACK - 1]) == napi_function) {
                SetCallback(params[PARAM_URL_AND_OPTIONS_AND_CALLBACK - 1]);
            }
            return;
        }
        return;
    }

    if (paramsCount == PARAM_JUST_URL) {
        options.SetUrl(NapiUtils::GetStringFromValueUtf8(GetEnv(), params[0]));
        SetParseOK(true);
        return;
    }

    if (paramsCount == PARAM_URL_AND_OPTIONS_OR_CALLBACK) {
        napi_valuetype type = NapiUtils::GetValueType(GetEnv(), params[1]);
        if (type == napi_function) {
            options.SetUrl(NapiUtils::GetStringFromValueUtf8(GetEnv(), params[0]));
            SetParseOK(SetCallback(params[1]) == napi_ok);
            return;
        }
        if (type == napi_object) {
            UrlAndOptions(params[0], params[1]);
            return;
        }
        return;
    }

    if (paramsCount == PARAM_URL_AND_OPTIONS_AND_CALLBACK) {
        if (SetCallback(params[PARAM_URL_AND_OPTIONS_AND_CALLBACK - 1]) != napi_ok) {
            return;
        }
        UrlAndOptions(params[0], params[1]);
    }
}

#if ENABLE_HTTP_INTERCEPT
void RequestContext::SetInterceptorRefs(const std::map<std::string, napi_ref> &interceptorRefs)
{
    interceptorRefs_.clear();
    interceptorRefs_ = interceptorRefs;
    interceptor_ = std::make_unique<HttpInterceptor>(interceptorRefs_);
}

HttpInterceptor *RequestContext::GetInterceptor()
{
    return interceptor_.get();
}
#endif

bool RequestContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_JUST_URL) {
        // just url
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_string;
    }
    if (paramsCount == PARAM_URL_AND_OPTIONS_OR_CALLBACK) {
        // should be url, callback or url, options
        napi_valuetype type = NapiUtils::GetValueType(GetEnv(), params[1]);
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_string &&
               (type == napi_function || type == napi_object);
    }
    if (paramsCount == PARAM_URL_AND_OPTIONS_AND_CALLBACK) {
        // should be url options and callback
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_string &&
               NapiUtils::GetValueType(GetEnv(), params[1]) == napi_object &&
               NapiUtils::GetValueType(GetEnv(), params[PARAM_URL_AND_OPTIONS_AND_CALLBACK - 1]) == napi_function;
    }
    return false;
}

void RequestContext::ParseNumberOptions(napi_value optionsValue)
{
    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_READ_TIMEOUT)) {
        options.SetReadTimeout(
            NapiUtils::GetUint32Property(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_READ_TIMEOUT));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_MAX_LIMIT)) {
        options.SetMaxLimit(NapiUtils::GetUint32Property(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_MAX_LIMIT));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_CONNECT_TIMEOUT)) {
        options.SetConnectTimeout(
            NapiUtils::GetUint32Property(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_CONNECT_TIMEOUT));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_USING_CACHE)) {
        napi_value value = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_USING_CACHE);
        if (NapiUtils::GetValueType(GetEnv(), value) == napi_boolean) {
            usingCache_ = NapiUtils::GetBooleanFromValue(GetEnv(), value);
        }
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_USING_PROTOCOL)) {
        napi_value value = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_USING_PROTOCOL);
        if (NapiUtils::GetValueType(GetEnv(), value) == napi_number) {
            uint32_t number = NapiUtils::GetUint32FromValue(GetEnv(), value);
            if (number == static_cast<uint32_t>(HttpProtocol::HTTP1_1) ||
                number == static_cast<uint32_t>(HttpProtocol::HTTP2) ||
                number == static_cast<uint32_t>(HttpProtocol::HTTP3)) {
                options.SetUsingProtocol(static_cast<HttpProtocol>(number));
            }
        }
    }
    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_EXPECT_DATA_TYPE)) {
        napi_value value =
            NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_EXPECT_DATA_TYPE);
        if (NapiUtils::GetValueType(GetEnv(), value) == napi_number) {
            uint32_t type = NapiUtils::GetUint32FromValue(GetEnv(), value);
            options.SetHttpDataType(static_cast<HttpDataType>(type));
        }
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_PRIORITY)) {
        napi_value value = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_PRIORITY);
        if (NapiUtils::GetValueType(GetEnv(), value) == napi_number) {
            uint32_t priority = NapiUtils::GetUint32FromValue(GetEnv(), value);
            options.SetPriority(priority);
        }
    }
}

void RequestContext::ParseMaxRedirects(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_MAX_REDIRECTS)) {
        return;
    }
    napi_value value = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_MAX_REDIRECTS);
    if (NapiUtils::GetValueType(GetEnv(), value) != napi_number) {
        NETSTACK_LOGE("ParseMaxRedirects: maxRedirects not number");
        return;
    }
    int64_t maxRedirects = 0;
    if (napi_get_value_int64(GetEnv(), value, &maxRedirects) != napi_ok) {
        NETSTACK_LOGE("ParseMaxRedirects: napi_get_value_int64 error");
        return;
    }
    if (maxRedirects > INT32_MAX || maxRedirects < 0) {
        NETSTACK_LOGE("ParseMaxRedirects: invalid maxRedirects value");
        return;
    }
    options.SetMaxRedirects(static_cast<uint32_t>(maxRedirects));
}

void RequestContext::ParseRemoteValidationMode(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_REMOTE_VALIDATION)) {
        NETSTACK_LOGD("no remote validation mode config");
        return;
    }
    napi_value value = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_REMOTE_VALIDATION);
    if (NapiUtils::GetValueType(GetEnv(), value) == napi_string) {
        auto remoteValidationMode = NapiUtils::GetStringFromValueUtf8(GetEnv(), value);
        if (remoteValidationMode == "skip") {
            NETSTACK_LOGI("ParseRemoteValidationMode remoteValidationMode skip");
            options.SetCanSkipCertVerifyFlag(true);
        } else if (remoteValidationMode != "system") {
            NETSTACK_LOGE("RemoteValidationMode config error");
        }
    }
}

void RequestContext::ParseTlsOption(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_TLS_OPTION)) {
        NETSTACK_LOGD("no tls config");
        return;
    }
    napi_value tlsVersionValue = NapiUtils::GetNamedProperty(
        GetEnv(), optionsValue, HttpConstant::PARAM_KEY_TLS_OPTION);
    napi_valuetype type = NapiUtils::GetValueType(GetEnv(), tlsVersionValue);
    if (type != napi_object && type != napi_string) {
        NETSTACK_LOGE("tlsVersionValue type error");
        return;
    }
    uint32_t tlsVersionMin = NapiUtils::GetUint32Property(GetEnv(), tlsVersionValue, "tlsVersionMin");
    uint32_t tlsVersionMax = NapiUtils::GetUint32Property(GetEnv(), tlsVersionValue, "tlsVersionMax");
    NETSTACK_LOGD("tlsVersionMin = %{public}d, tlsVersionMax = %{public}d", tlsVersionMin, tlsVersionMax);
    TlsOption tlsOption;
    tlsOption.tlsVersionMin = static_cast<TlsVersion>(tlsVersionMin);
    tlsOption.tlsVersionMax = static_cast<TlsVersion>(tlsVersionMax);
    if (!NapiUtils::HasNamedProperty(GetEnv(), tlsVersionValue, "cipherSuites")) {
        NETSTACK_LOGD("no cipherSuites");
        options.SetTlsOption(tlsOption);
        return;
    }
    auto cipherSuiteNapi = NapiUtils::GetNamedProperty(GetEnv(), tlsVersionValue, "cipherSuites");
    if (!NapiUtils::IsArray(GetEnv(), cipherSuiteNapi)) {
        options.SetTlsOption(tlsOption);
        return;
    }
    auto length = NapiUtils::GetArrayLength(GetEnv(), cipherSuiteNapi);
    for (uint32_t i = 0; i < length; ++i) {
        auto standardNameNapi = NapiUtils::GetArrayElement(GetEnv(), cipherSuiteNapi, i);
        auto cipherSuite = GetTlsCipherSuiteFromStandardName(
            NapiUtils::GetStringFromValueUtf8(GetEnv(), standardNameNapi));
        if (cipherSuite != CipherSuite::INVALID) {
            tlsOption.cipherSuite.emplace(cipherSuite);
        }
    }

    options.SetTlsOption(tlsOption);
}

void RequestContext::ParseServerAuthentication(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_SERVER_AUTH)) {
        NETSTACK_LOGD("no server authentication config");
        return;
    }
    napi_value serverAuthenticationValue = NapiUtils::GetNamedProperty(
        GetEnv(), optionsValue, HttpConstant::PARAM_KEY_SERVER_AUTH);
    napi_valuetype type = NapiUtils::GetValueType(GetEnv(), serverAuthenticationValue);
    if (type != napi_object) {
        NETSTACK_LOGE("server authentication type error");
        return;
    }
    ServerAuthentication serverAuthentication;
    auto credentialNapi = NapiUtils::GetNamedProperty(GetEnv(), serverAuthenticationValue, "credential");
    NapiUtils::GetSecureDataPropertyUtf8(GetEnv(),
        credentialNapi, "username", serverAuthentication.credential.username);
    NapiUtils::GetSecureDataPropertyUtf8(GetEnv(),
        credentialNapi, "password", serverAuthentication.credential.password);
    auto authenticationType = NapiUtils::GetStringPropertyUtf8(GetEnv(),
        serverAuthenticationValue, "authenticationType");
    if (authenticationType == "basic") {
        serverAuthentication.authenticationType = AuthenticationType::BASIC;
    } else if (authenticationType == "ntlm") {
        serverAuthentication.authenticationType = AuthenticationType::NTLM;
    } else if (authenticationType == "digest") {
        serverAuthentication.authenticationType = AuthenticationType::DIGEST;
    }
    options.SetServerAuthentication(serverAuthentication);
}

void RequestContext::ParseHeader(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_HEADER)) {
        return;
    }
    napi_value header = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_HEADER);
    if (NapiUtils::GetValueType(GetEnv(), header) != napi_object) {
        return;
    }
    if (HttpExec::MethodForPost(options.GetMethod())) {
        options.SetHeader(CommonUtils::ToLower(HttpConstant::HTTP_CONTENT_TYPE),
                          HttpConstant::HTTP_CONTENT_TYPE_JSON); // default
    }
    auto names = NapiUtils::GetPropertyNames(GetEnv(), header);
    if (names.size() == 0) {
        NETSTACK_LOGD("ParseHeader set fail");
        return;
    }
    std::for_each(names.begin(), names.end(), [header, this](const std::string &name) {
        napi_value value = NapiUtils::GetNamedProperty(GetEnv(), header, name);
        std::string valueStr = NapiUtils::NapiValueToString(GetEnv(), value);
        options.SetHeader(CommonUtils::ToLower(name), valueStr);
    });
}

bool RequestContext::HandleMethodForGet(napi_value extraData)
{
    std::string url = options.GetUrl();
    std::string param;
    auto index = url.find(HttpConstant::HTTP_URL_PARAM_START);
    if (index != std::string::npos) {
        param = url.substr(index + 1);
        url.resize(index);
    }

    napi_valuetype type = NapiUtils::GetValueType(GetEnv(), extraData);
    if (type == napi_string) {
        std::string extraParam = NapiUtils::GetStringFromValueUtf8(GetEnv(), extraData);

        options.SetUrl(HttpExec::MakeUrl(url, param, extraParam));
        return true;
    }
    if (type != napi_object) {
        return true;
    }

    std::string extraParam;
    auto names = NapiUtils::GetPropertyNames(GetEnv(), extraData);
    if (names.size() == 0) {
        NETSTACK_LOGD("HandleMethodForGet extraData invalid");
    }
    std::for_each(names.begin(), names.end(), [this, extraData, &extraParam](std::string name) {
        auto value = NapiUtils::GetStringPropertyUtf8(GetEnv(), extraData, name);
        if (!name.empty() && !value.empty()) {
            bool encodeName = HttpExec::EncodeUrlParam(name);
            bool encodeValue = HttpExec::EncodeUrlParam(value);
            if (encodeName || encodeValue) {
                options.SetHeader(CommonUtils::ToLower(HttpConstant::HTTP_CONTENT_TYPE),
                                  HttpConstant::HTTP_CONTENT_TYPE_URL_ENCODE);
            }
            extraParam +=
                name + HttpConstant::HTTP_URL_NAME_VALUE_SEPARATOR + value + HttpConstant::HTTP_URL_PARAM_SEPARATOR;
        }
    });
    if (!extraParam.empty()) {
        extraParam.pop_back(); // remove the last &
    }

    options.SetUrl(HttpExec::MakeUrl(url, param, extraParam));
    return true;
}

bool RequestContext::ParseExtraData(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_EXTRA_DATA)) {
        NETSTACK_LOGD("no extraData");
        return true;
    }

    napi_value extraData = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_EXTRA_DATA);
    if (NapiUtils::GetValueType(GetEnv(), extraData) == napi_undefined ||
        NapiUtils::GetValueType(GetEnv(), extraData) == napi_null) {
        NETSTACK_LOGD("extraData is undefined or null");
        return true;
    }

    if (HttpExec::MethodForGet(options.GetMethod())) {
        return HandleMethodForGet(extraData);
    }

    if (HttpExec::MethodForPost(options.GetMethod())) {
        return GetRequestBody(extraData);
    }
    
    if (!options.GetMethod().empty()) {
        return GetRequestBody(extraData);
    }
    return false;
}

void RequestContext::ParseUsingHttpProxy(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_USING_HTTP_PROXY)) {
        NETSTACK_LOGD("Use default proxy");
        return;
    }
    napi_value httpProxyValue =
        NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_USING_HTTP_PROXY);
    napi_valuetype type = NapiUtils::GetValueType(GetEnv(), httpProxyValue);
    if (type == napi_boolean) {
        bool usingProxy = NapiUtils::GetBooleanFromValue(GetEnv(), httpProxyValue);
        UsingHttpProxyType usingType = usingProxy ? UsingHttpProxyType::USE_DEFAULT : UsingHttpProxyType::NOT_USE;
        options.SetUsingHttpProxyType(usingType);
        return;
    }
    if (type != napi_object) {
        return;
    }
    std::string host = NapiUtils::GetStringPropertyUtf8(GetEnv(), httpProxyValue, HttpConstant::HTTP_PROXY_KEY_HOST);
    int32_t port = NapiUtils::GetInt32Property(GetEnv(), httpProxyValue, HttpConstant::HTTP_PROXY_KEY_PORT);
    std::string exclusionList;
    if (NapiUtils::HasNamedProperty(GetEnv(), httpProxyValue, HttpConstant::HTTP_PROXY_KEY_EXCLUSION_LIST)) {
        napi_value exclusionListValue =
            NapiUtils::GetNamedProperty(GetEnv(), httpProxyValue, HttpConstant::HTTP_PROXY_KEY_EXCLUSION_LIST);
        uint32_t listLength = NapiUtils::GetArrayLength(GetEnv(), exclusionListValue);
        for (uint32_t index = 0; index < listLength; ++index) {
            napi_value exclusionValue = NapiUtils::GetArrayElement(GetEnv(), exclusionListValue, index);
            std::string exclusion = NapiUtils::GetStringFromValueUtf8(GetEnv(), exclusionValue);
            if (index != 0) {
                exclusionList = exclusionList + HttpConstant::HTTP_PROXY_EXCLUSIONS_SEPARATOR;
            }
            exclusionList += exclusion;
        }
    }

    NapiUtils::SecureData username;
    NapiUtils::SecureData password;
    if (NapiUtils::HasNamedProperty(GetEnv(), httpProxyValue, HttpConstant::HTTP_PROXY_KEY_USERNAME) &&
        NapiUtils::HasNamedProperty(GetEnv(), httpProxyValue, HttpConstant::HTTP_PROXY_KEY_PASSWORD)) {
        NapiUtils::GetSecureDataPropertyUtf8(GetEnv(), httpProxyValue, HttpConstant::HTTP_PROXY_KEY_PASSWORD, password);
        NapiUtils::GetSecureDataPropertyUtf8(GetEnv(), httpProxyValue, HttpConstant::HTTP_PROXY_KEY_USERNAME, username);
    }

    options.SetSpecifiedHttpProxy(host, port, exclusionList, username, password);
    options.SetUsingHttpProxyType(UsingHttpProxyType::USE_SPECIFIED);
}

bool RequestContext::GetRequestBody(napi_value extraData)
{
    /* if body is empty, return false, or curl will wait for body */

    napi_valuetype type = NapiUtils::GetValueType(GetEnv(), extraData);
    if (type == napi_string) {
        auto body = NapiUtils::GetStringFromValueUtf8(GetEnv(), extraData);
        if (body.empty()) {
            return false;
        }
        options.SetBody(body.c_str(), body.size());
        return true;
    }

    if (NapiUtils::ValueIsArrayBuffer(GetEnv(), extraData)) {
        size_t length = 0;
        void *data = NapiUtils::GetInfoFromArrayBufferValue(GetEnv(), extraData, &length);
        if (data == nullptr) {
            return false;
        }
        options.SetBody(data, length);
        return true;
    }

    if (type == napi_object) {
        std::string body = NapiUtils::GetStringFromValueUtf8(GetEnv(), NapiUtils::JsonStringify(GetEnv(), extraData));
        if (body.empty()) {
            NETSTACK_LOGD("GetRequestBody extraData null for post method");
            return false;
        }
        options.SetBody(body.c_str(), body.length());
        return true;
    }

    NETSTACK_LOGE("only support string arraybuffer and object");
    return false;
}

void RequestContext::ParseCaPath(napi_value optionsValue)
{
    std::string caPath = NapiUtils::GetStringPropertyUtf8(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_CA_PATH);
    if (!caPath.empty()) {
        options.SetCaPath(caPath);
    }
}

void RequestContext::ParseCaData(napi_value optionsValue)
{
    std::string caPath = NapiUtils::GetStringPropertyUtf8(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_CA_PATH);
    std::string caData = NapiUtils::GetStringPropertyUtf8(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_CA_DATA);
    if (caPath.empty() && !caData.empty() && caData.size() < CADATA_STRING_MAX_LENGTH) {
        options.SetCaData(caData);
    }
}

void RequestContext::ParseDohUrl(napi_value optionsValue)
{
    std::string dohUrl = NapiUtils::GetStringPropertyUtf8(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_DOH_URL);
    if (!dohUrl.empty()) {
        options.SetDohUrl(dohUrl);
    }
}

void RequestContext::ParseResumeFromToNumber(napi_value optionsValue)
{
    napi_env env = GetEnv();
    int64_t from = NapiUtils::GetInt64Property(env, optionsValue, HttpConstant::PARAM_KEY_RESUME_FROM);
    int64_t to = NapiUtils::GetInt64Property(env, optionsValue, HttpConstant::PARAM_KEY_RESUME_TO);
    options.SetRangeNumber(from, to);
}

void RequestContext::UrlAndOptions(napi_value urlValue, napi_value optionsValue)
{
    options.SetUrl(NapiUtils::GetStringFromValueUtf8(GetEnv(), urlValue));
    std::string customMethod;
    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_CUSTOM_METHOD)) {
        napi_value requestMethod =
            NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_CUSTOM_METHOD);
        if (NapiUtils::GetValueType(GetEnv(), requestMethod) == napi_string) {
            customMethod =
                NapiUtils::GetStringPropertyUtf8(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_CUSTOM_METHOD);
            options.SetMethod(customMethod);
        }
    }
    if (customMethod.empty() && NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_METHOD)) {
        napi_value requestMethod = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_METHOD);
        if (NapiUtils::GetValueType(GetEnv(), requestMethod) == napi_string) {
            options.SetMethod(NapiUtils::GetStringPropertyUtf8(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_METHOD));
        }
    }

    ParseNumberOptions(optionsValue);
    ParseUsingHttpProxy(optionsValue);
    ParseClientCert(optionsValue);
    ParseMaxRedirects(optionsValue);

    /* parse extra data here to recover header */
    if (!ParseExtraData(optionsValue)) {
        return;
    }

    ParseHeader(optionsValue);
    ParseCaPath(optionsValue);
    ParseCaData(optionsValue);
    ParseDohUrl(optionsValue);
    ParseResumeFromToNumber(optionsValue);
    ParseDnsServers(optionsValue);
    ParseMultiFormData(optionsValue);
    ParseCertificatePinning(optionsValue);
    ParseRemoteValidationMode(optionsValue);
    ParseTlsOption(optionsValue);
    ParseServerAuthentication(optionsValue);
    SetParseOK(true);
    ParseAddressFamily(optionsValue);
    ParseSslType(optionsValue);
    ParseClientEncCert(optionsValue);
}

bool RequestContext::IsUsingCache() const
{
    return usingCache_;
}

void RequestContext::SetCurlHeaderList(curl_slist *curlHeaderList)
{
    curlHeaderList_ = curlHeaderList;
}

curl_slist *RequestContext::GetCurlHeaderList()
{
    return curlHeaderList_;
}

void RequestContext::SetCurlHostList(curl_slist *curlHostList)
{
    curlHostList_ = curlHostList;
}

curl_slist *RequestContext::GetCurlHostList()
{
    return curlHostList_;
}

RequestContext::~RequestContext()
{
    trace_.Finish();
    if (curlHeaderList_ != nullptr) {
        curl_slist_free_all(curlHeaderList_);
    }
    if (curlHostList_ != nullptr) {
        curl_slist_free_all(curlHostList_);
    }
    if (multipart_ != nullptr) {
        curl_mime_free(multipart_);
        multipart_ = nullptr;
    }
    NETSTACK_LOGD("the destructor of request context is invoked");
}

void RequestContext::SetCacheResponse(const HttpResponse &cacheResponse)
{
    cacheResponse_ = cacheResponse;
}
void RequestContext::SetResponseByCache()
{
    response = cacheResponse_;
}

int32_t RequestContext::GetErrorCode() const
{
    auto err = BaseContext::GetErrorCode();
    if (err == PARSE_ERROR_CODE) {
        return PARSE_ERROR_CODE;
    }

    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_CODE;
    }

    if (BaseContext::IsNoAllowedHost()) {
        return HTTP_NOT_ALLOWED_HOST;
    }

    if (BaseContext::IsCleartextNotPermitted()) {
        return HTTP_CLEARTEXT_NOT_PERMITTED;
    }

    if (HTTP_ERR_MAP.find(err + HTTP_ERROR_CODE_BASE) != HTTP_ERR_MAP.end()) {
        return err + HTTP_ERROR_CODE_BASE;
    }
    return HTTP_UNKNOWN_OTHER_ERROR;
}

std::string RequestContext::GetErrorMessage() const
{
    auto err = BaseContext::GetErrorCode();
    if (err == PARSE_ERROR_CODE) {
        return PARSE_ERROR_MSG;
    }

    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_MSG;
    }

    if (BaseContext::IsNoAllowedHost()) {
        return HTTP_ERR_MAP.at(HTTP_NOT_ALLOWED_HOST);
    }

    if (BaseContext::IsCleartextNotPermitted()) {
        return HTTP_ERR_MAP.at(HTTP_CLEARTEXT_NOT_PERMITTED);
    }

    auto pos = HTTP_ERR_MAP.find(err + HTTP_ERROR_CODE_BASE);
    if (pos != HTTP_ERR_MAP.end()) {
        return pos->second;
    }
    return HTTP_ERR_MAP.at(HTTP_UNKNOWN_OTHER_ERROR);
}

void RequestContext::EnableRequestInStream()
{
    requestInStream_ = true;
}

bool RequestContext::IsRequestInStream() const
{
    return requestInStream_;
}

void RequestContext::SetDlLen(curl_off_t nowLen, curl_off_t totalLen)
{
    std::lock_guard<std::mutex> lock(dlLenLock_);
    LoadBytes dlBytes{nowLen, totalLen};
    dlBytes_.push(dlBytes);
}

void RequestContext::SetCertsPath(std::vector<std::string> &&certPathList, const std::string &certFile)
{
    certsPath_.certPathList = std::move(certPathList);
    certsPath_.certFile = certFile;
}

const CertsPath &RequestContext::GetCertsPath()
{
    return certsPath_;
}

LoadBytes RequestContext::GetDlLen()
{
    std::lock_guard<std::mutex> lock(dlLenLock_);
    LoadBytes dlBytes;
    if (!dlBytes_.empty()) {
        dlBytes.nLen = dlBytes_.front().nLen;
        dlBytes.tLen = dlBytes_.front().tLen;
        dlBytes_.pop();
    }
    return dlBytes;
}

void RequestContext::SetUlLen(curl_off_t nowLen, curl_off_t totalLen)
{
    std::lock_guard<std::mutex> lock(ulLenLock_);
    if (!ulBytes_.empty()) {
        ulBytes_.pop();
    }
    LoadBytes ulBytes{nowLen, totalLen};
    ulBytes_.push(ulBytes);
}

LoadBytes RequestContext::GetUlLen()
{
    std::lock_guard<std::mutex> lock(ulLenLock_);
    LoadBytes ulBytes;
    if (!ulBytes_.empty()) {
        ulBytes.nLen = ulBytes_.back().nLen;
        ulBytes.tLen = ulBytes_.back().tLen;
    }
    return ulBytes;
}

bool RequestContext::CompareWithLastElement(curl_off_t nowLen, curl_off_t totalLen)
{
    std::lock_guard<std::mutex> lock(ulLenLock_);
    if (ulBytes_.empty()) {
        return false;
    }
    const LoadBytes &lastElement = ulBytes_.back();
    return nowLen == lastElement.nLen && totalLen == lastElement.tLen;
}

void RequestContext::SetTempData(const void *data, size_t size)
{
    std::lock_guard<std::mutex> lock(tempDataLock_);
    std::string tempString;
    tempString.append(reinterpret_cast<const char *>(data), size);
    tempData_.push(tempString);
}

std::string RequestContext::GetTempData()
{
    std::lock_guard<std::mutex> lock(tempDataLock_);
    if (!tempData_.empty()) {
        return tempData_.front();
    }
    return {};
}

void RequestContext::PopTempData()
{
    std::lock_guard<std::mutex> lock(tempDataLock_);
    if (!tempData_.empty()) {
        tempData_.pop();
    }
}

void RequestContext::ParseDnsServers(napi_value optionsValue)
{
    napi_env env = GetEnv();
    if (!NapiUtils::HasNamedProperty(env, optionsValue, HttpConstant::PARAM_KEY_DNS_SERVERS)) {
        NETSTACK_LOGD("ParseDnsServers no data");
        return;
    }
    napi_value dnsServerValue = NapiUtils::GetNamedProperty(env, optionsValue, HttpConstant::PARAM_KEY_DNS_SERVERS);
    if (NapiUtils::GetValueType(env, dnsServerValue) != napi_object) {
        return;
    }
    uint32_t dnsLength = NapiUtils::GetArrayLength(env, dnsServerValue);
    if (dnsLength == 0) {
        return;
    }
    std::vector<std::string> dnsServers;
    uint32_t dnsSize = 0;
    for (uint32_t i = 0; i < dnsLength && dnsSize < DNS_SERVER_SIZE; i++) {
        napi_value element = NapiUtils::GetArrayElement(env, dnsServerValue, i);
        std::string dnsServer = NapiUtils::GetStringFromValueUtf8(env, element);
        if (dnsServer.length() == 0) {
            continue;
        }
        if (!CommonUtils::IsValidIPV4(dnsServer) && !CommonUtils::IsValidIPV6(dnsServer)) {
            continue;
        }
        dnsServers.push_back(dnsServer);
        dnsSize++;
    }
    if (dnsSize == 0 || dnsServers.data() == nullptr || dnsServers.empty()) {
        NETSTACK_LOGD("dnsServersArray is empty.");
        return;
    }
    options.SetDnsServers(dnsServers);
    NETSTACK_LOGD("SetDnsServers success");
}

void RequestContext::CachePerformanceTimingItem(const std::string &key, double value)
{
    performanceTimingMap_[key] = value;
}

void RequestContext::StopAndCacheNapiPerformanceTiming(const char *key)
{
    Timing::Timer &timer = timerMap_.RecieveTimer(key);
    timer.Stop();
    CachePerformanceTimingItem(key, timer.Elapsed());
}

void RequestContext::SetPerformanceTimingToResult(napi_value result)
{
    if (performanceTimingMap_.empty()) {
        NETSTACK_LOGD("Get performanceTiming data is empty.");
        return;
    }
    napi_value performanceTimingValue;
    napi_env env = GetEnv();
    napi_create_object(env, &performanceTimingValue);
    for (const auto &pair : performanceTimingMap_) {
        NapiUtils::SetDoubleProperty(env, performanceTimingValue, pair.first, pair.second);
    }
    NapiUtils::SetNamedProperty(env, result, HttpConstant::RESPONSE_PERFORMANCE_TIMING, performanceTimingValue);
}

void RequestContext::ParseClientCert(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_CLIENT_CERT)) {
        return;
    }
    napi_value clientCertValue =
        NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_CLIENT_CERT);
    napi_valuetype type = NapiUtils::GetValueType(GetEnv(), clientCertValue);
    if (type != napi_object) {
        return;
    }
    std::string cert = NapiUtils::GetStringPropertyUtf8(GetEnv(), clientCertValue, HttpConstant::HTTP_CLIENT_CERT);
    std::string certType =
        NapiUtils::GetStringPropertyUtf8(GetEnv(), clientCertValue, HttpConstant::HTTP_CLIENT_CERT_TYPE);
    std::string key = NapiUtils::GetStringPropertyUtf8(GetEnv(), clientCertValue, HttpConstant::HTTP_CLIENT_KEY);
    Secure::SecureChar keyPasswd = Secure::SecureChar(
        NapiUtils::GetStringPropertyUtf8(GetEnv(), clientCertValue, HttpConstant::HTTP_CLIENT_KEY_PASSWD));
    options.SetClientCert(cert, certType, key, keyPasswd);
}

void RequestContext::ParseMultiFormData(napi_value optionsValue)
{
    napi_env env = GetEnv();
    if (!NapiUtils::HasNamedProperty(env, optionsValue, HttpConstant::PARAM_KEY_MULTI_FORM_DATA_LIST)) {
        NETSTACK_LOGD("ParseMultiFormData multiFormDataList is null.");
        return;
    }
    napi_value multiFormDataListValue =
        NapiUtils::GetNamedProperty(env, optionsValue, HttpConstant::PARAM_KEY_MULTI_FORM_DATA_LIST);
    if (NapiUtils::GetValueType(env, multiFormDataListValue) != napi_object) {
        NETSTACK_LOGE("ParseMultiFormData multiFormDataList type is not object.");
        return;
    }
    uint32_t dataLength = NapiUtils::GetArrayLength(env, multiFormDataListValue);
    if (dataLength == 0) {
        NETSTACK_LOGD("ParseMultiFormData multiFormDataList length is 0.");
        return;
    }
    for (uint32_t i = 0; i < dataLength; i++) {
        napi_value formDataValue = NapiUtils::GetArrayElement(env, multiFormDataListValue, i);
        MultiFormData multiFormData = NapiValue2FormData(formDataValue);
        options.AddMultiFormData(multiFormData);
    }
}

MultiFormData RequestContext::NapiValue2FormData(napi_value formDataValue)
{
    napi_env env = GetEnv();
    MultiFormData multiFormData;
    multiFormData.name = NapiUtils::GetStringPropertyUtf8(env, formDataValue, HttpConstant::HTTP_MULTI_FORM_DATA_NAME);
    multiFormData.contentType =
        NapiUtils::GetStringPropertyUtf8(env, formDataValue, HttpConstant::HTTP_MULTI_FORM_DATA_CONTENT_TYPE);
    multiFormData.remoteFileName =
        NapiUtils::GetStringPropertyUtf8(env, formDataValue, HttpConstant::HTTP_MULTI_FORM_DATA_REMOTE_FILE_NAME);
    RequestContext::SaveFormData(
        env, NapiUtils::GetNamedProperty(env, formDataValue, HttpConstant::HTTP_MULTI_FORM_DATA_DATA), multiFormData);
    multiFormData.filePath =
        NapiUtils::GetStringPropertyUtf8(env, formDataValue, HttpConstant::HTTP_MULTI_FORM_DATA_FILE_PATH);
    return multiFormData;
}

CertificatePinning RequestContext::NapiValue2CertPinning(napi_value certPIN)
{
    napi_env env = GetEnv();
    CertificatePinning singleCertPIN;
    auto algorithm = NapiUtils::GetStringPropertyUtf8(env, certPIN, HttpConstant::HTTP_HASH_ALGORITHM);
    if (algorithm == "SHA-256") {
        singleCertPIN.hashAlgorithm = HashAlgorithm::SHA256;
    } else {
        singleCertPIN.hashAlgorithm = HashAlgorithm::INVALID;
    }

    singleCertPIN.publicKeyHash = NapiUtils::GetStringPropertyUtf8(env, certPIN, HttpConstant::HTTP_PUBLIC_KEY_HASH);
    return singleCertPIN;
}

void RequestContext::SaveFormData(napi_env env, napi_value dataValue, MultiFormData &multiFormData)
{
    napi_valuetype type = NapiUtils::GetValueType(env, dataValue);
    if (type == napi_string) {
        multiFormData.data = NapiUtils::GetStringFromValueUtf8(GetEnv(), dataValue);
        NETSTACK_LOGD("SaveFormData string");
    } else if (NapiUtils::ValueIsArrayBuffer(GetEnv(), dataValue)) {
        size_t length = 0;
        void *data = NapiUtils::GetInfoFromArrayBufferValue(GetEnv(), dataValue, &length);
        if (data == nullptr) {
            return;
        }
        multiFormData.data = std::string(static_cast<const char *>(data), length);
        NETSTACK_LOGD("SaveFormData ArrayBuffer");
    } else if (type == napi_object) {
        multiFormData.data = NapiUtils::GetStringFromValueUtf8(GetEnv(), NapiUtils::JsonStringify(GetEnv(), dataValue));
        NETSTACK_LOGD("SaveFormData Object");
    } else {
        NETSTACK_LOGD("only support string, ArrayBuffer and Object");
    }
}

void RequestContext::ParseCertificatePinning(napi_value optionsValue)
{
    auto env = GetEnv();
    if (!NapiUtils::HasNamedProperty(env, optionsValue, HttpConstant::PARAM_KEY_CERTIFICATE_PINNING)) {
        NETSTACK_LOGD("NO CertificatePinning option");
        return;
    }
    napi_value certificatePin =
        NapiUtils::GetNamedProperty(env, optionsValue, HttpConstant::PARAM_KEY_CERTIFICATE_PINNING);
    std::stringstream certPinBuilder;

    if (NapiUtils::IsArray(env, certificatePin)) {
        auto arrayLen = NapiUtils::GetArrayLength(env, certificatePin);
        for (uint32_t i = 0; i < arrayLen; i++) {
            napi_value certPIN = NapiUtils::GetArrayElement(env, certificatePin, i);
            CertificatePinning singleCertPIN = NapiValue2CertPinning(certPIN);
            if (singleCertPIN.hashAlgorithm == HashAlgorithm::SHA256) {
                certPinBuilder << "sha256//" << singleCertPIN.publicKeyHash << ';';
            }
        }
    } else {
        CertificatePinning singleCertPIN = NapiValue2CertPinning(certificatePin);
        if (singleCertPIN.hashAlgorithm == HashAlgorithm::SHA256) {
            certPinBuilder << "sha256//" << singleCertPIN.publicKeyHash << ';';
        }
    }

    if (!certPinBuilder.str().empty()) {
        NapiUtils::SecureData securePin(certPinBuilder.str());
        securePin.pop_back();
        options.SetCertificatePinning(securePin);
    }
}

void RequestContext::SetMultipart(curl_mime *multipart)
{
    multipart_ = multipart;
}

int32_t RequestContext::GetTaskId() const
{
    return taskId_;
}

void RequestContext::SetModuleId(uint64_t moduleId)
{
    moduleId_ = moduleId;
}

uint64_t RequestContext::GetModuleId() const
{
    return moduleId_;
}

bool RequestContext::IsAtomicService() const
{
    return isAtomicService_;
}

void RequestContext::SetAtomicService(bool isAtomicService)
{
    isAtomicService_ = isAtomicService;
}

void RequestContext::SetBundleName(const std::string &bundleName)
{
    bundleName_ = bundleName;
}

std::string RequestContext::GetBundleName() const
{
    return bundleName_;
}

void RequestContext::SetCurlHandle(CURL *handle)
{
    curlHandle_ = handle;
}

CURL *RequestContext::GetCurlHandle()
{
    return curlHandle_;
}

void RequestContext::SendNetworkProfiler()
{
#if HAS_NETMANAGER_BASE
    HttpNetworkMessage networkMessage(std::to_string(GetTaskId()), options, response, curlHandle_);
    networkProfilerUtils_->NetworkProfiling(networkMessage);
#endif
}

RequestTracer::Trace &RequestContext::GetTrace()
{
    return trace_;
}

bool RequestContext::IsRootCaVerified() const
{
    return isRootCaVerified_;
}

void RequestContext::SetRootCaVerified()
{
    isRootCaVerified_ = true;
}

bool RequestContext::IsRootCaVerifiedOk() const
{
    return isRootCaVerifiedOk_;
}

void RequestContext::SetRootCaVerifiedOk(bool ok)
{
    isRootCaVerifiedOk_ = ok;
}

void RequestContext::SetPinnedPubkey(std::string &pubkey)
{
    pinnedPubkey_ = pubkey;
}

std::string RequestContext::GetPinnedPubkey() const
{
    return pinnedPubkey_;
}

void RequestContext::IncreaseRedirectCount()
{
    redirects_ += 1;
}

bool RequestContext::IsReachRedirectLimit()
{
    return redirects_ >= options.GetMaxRedirects();
}

#ifdef HTTP_HANDOVER_FEATURE
void RequestContext::SetRequestHandoverInfo(const HttpHandoverInfo &httpHandoverInfo)
{
    if (httpHandoverInfo.handOverNum <= 0) {
        httpHandoverInfoStr_ = "no handover";
    }
    httpHandoverInfoStr_ = "HandoverNum:";
    httpHandoverInfoStr_ += std::to_string(httpHandoverInfo.handOverNum);
    httpHandoverInfoStr_ += ", handverReason:";
    switch (httpHandoverInfo.handOverReason) {
        case HandoverRequestType::INCOMING:
            httpHandoverInfoStr_ += "flowControl, flowControlTime:";
            break;
        case HandoverRequestType::NETWORKERROR:
            httpHandoverInfoStr_ += "netErr, retransTime:";
            break;
        case HandoverRequestType::UNDONE:
            httpHandoverInfoStr_ += "undone, retransTime:";
            break;
        default:
            httpHandoverInfoStr_ += "unknown type";
            break;
    }
    httpHandoverInfoStr_ += std::to_string(httpHandoverInfo.flowControlTime);
    httpHandoverInfoStr_ += ", isRead:";
    httpHandoverInfoStr_ +=
        httpHandoverInfo.readFlag == 1 ? "true" : (httpHandoverInfo.readFlag == 0 ? "false" : "error");
    httpHandoverInfoStr_ += ", isInQueue:";
    httpHandoverInfoStr_ +=
        httpHandoverInfo.inQueueFlag == 1 ? "true" : (httpHandoverInfo.inQueueFlag == 0 ? "false" : "error");
    httpHandoverInfoStr_ += ", isStream:";
    httpHandoverInfoStr_ += this->IsRequestInStream() ? "true" : "false";
}
 
std::string RequestContext::GetRequestHandoverInfo()
{
    return httpHandoverInfoStr_;
}
#endif

void RequestContext::ParseAddressFamily(napi_value optionsValue)
{
    std::string addressFamily = NapiUtils::GetStringPropertyUtf8(GetEnv(), optionsValue,
        HttpConstant::PARAM_KEY_ADDRESS_FAMILY);
    if (!addressFamily.empty()) {
        options.SetAddressFamily(addressFamily);
    }
}

void RequestContext::ParseSslType(napi_value optionsValue)
{
    napi_env env = GetEnv();
    SslType sslType;
    auto sType = NapiUtils::GetStringPropertyUtf8(env, optionsValue, HttpConstant::SSL_TYPE_TLCP);
    if (sType == "TLCP") {
        sslType = SslType::TLCP;
    } else {
        sslType = SslType::TLS;
    }
    options.SetSslType(sslType);
}

void RequestContext::ParseClientEncCert(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_CLIENT_ENC_CERT)) {
        return;
    }
    napi_value clientCertValue =
        NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_CLIENT_ENC_CERT);
    napi_valuetype type = NapiUtils::GetValueType(GetEnv(), clientCertValue);
    if (type != napi_object) {
        return;
    }
    std::string cert = NapiUtils::GetStringPropertyUtf8(GetEnv(), clientCertValue, HttpConstant::HTTP_CLIENT_CERT);
    std::string certType =
        NapiUtils::GetStringPropertyUtf8(GetEnv(), clientCertValue, HttpConstant::HTTP_CLIENT_CERT_TYPE);
    std::string key = NapiUtils::GetStringPropertyUtf8(GetEnv(), clientCertValue, HttpConstant::HTTP_CLIENT_KEY);
    Secure::SecureChar keyPasswd = Secure::SecureChar(
        NapiUtils::GetStringPropertyUtf8(GetEnv(), clientCertValue, HttpConstant::HTTP_CLIENT_KEY_PASSWD));
    options.SetClientEncCert(cert, certType, key, keyPasswd);
}

} // namespace OHOS::NetStack::Http
