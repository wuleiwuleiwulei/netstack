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

#include "http_exec.h"
#include "curl/curl.h"
#include "request_context.h"

#include <cstddef>
#include <cstring>
#include <memory>
#include <pthread.h>
#include <sstream>
#include <thread>
#include <unistd.h>
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
#include "netsys_client.h"
#endif
#include "base64_utils.h"
#include "cache_proxy.h"
#include "constant.h"
#if HAS_NETMANAGER_BASE
#include "epoll_request_handler.h"
#endif
#include "event_list.h"
#if HAS_NETMANAGER_BASE
#include "hitrace_meter.h"
#include "netstack_hisysevent.h"
#endif
#include "http_async_work.h"
#include "http_time.h"
#include "napi_utils.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "securec.h"
#include "secure_char.h"
#include "trace_events.h"
#include "hi_app_event_report.h"
#ifdef HTTP_HANDOVER_FEATURE
#include "http_handover_info.h"
#endif

#include "http_utils.h"

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

static void AsyncWorkRequestInStreamCallback(napi_env env, napi_status status, void *data)
{
    if (status != napi_ok) {
        return;
    }
    std::unique_ptr<RequestContext, decltype(&RequestContextDeleter)> context(static_cast<RequestContext *>(data),
                                                                              RequestContextDeleter);
    napi_value undefined = NapiUtils::GetUndefined(env);
    napi_value argv[EVENT_PARAM_TWO] = {nullptr};
    if (context->IsParseOK() && context->IsExecOK()) {
        context->EmitSharedManager(ON_DATA_END, std::make_pair(undefined, undefined));
        argv[EVENT_PARAM_ZERO] = undefined;
        argv[EVENT_PARAM_ONE] = HttpExec::RequestInStreamCallback(context.get());
        if (argv[EVENT_PARAM_ONE] == nullptr) {
            return;
        }
    } else {
        argv[EVENT_PARAM_ZERO] =
            NapiUtils::CreateErrorMessage(env, context->GetErrorCode(), context->GetErrorMessage());
        if (argv[EVENT_PARAM_ZERO] == nullptr) {
            return;
        }

        argv[EVENT_PARAM_ONE] = undefined;
    }

    if (context->GetDeferred() != nullptr) {
        context->GetTrace().Finish();
        if (context->IsExecOK()) {
            napi_resolve_deferred(env, context->GetDeferred(), argv[EVENT_PARAM_ONE]);
        } else {
            napi_reject_deferred(env, context->GetDeferred(), argv[EVENT_PARAM_ZERO]);
        }
        return;
    }
    napi_value func = context->GetCallback();
    if (NapiUtils::GetValueType(env, func) == napi_function) {
        (void)NapiUtils::CallFunction(env, undefined, func, EVENT_PARAM_TWO, argv);
    }
}

#if HAS_NETMANAGER_BASE
void HttpExec::SetRequestInfoCallbacks(HttpOverCurl::TransferCallbacks &callbacks)
{
    static auto startedCallback = +[](CURL *easyHandle, void *opaqueData) {
        char *url = nullptr;
        curl_easy_getinfo(easyHandle, CURLINFO_EFFECTIVE_URL, &url);
        auto context = static_cast<RequestContext *>(opaqueData);  //
        context->GetTrace().Tracepoint(TraceEvents::QUEUE);
    };

    static auto responseCallback = +[](CURLMsg *curlMessage, void *opaqueData) {
        auto context = static_cast<RequestContext *>(opaqueData);
        context->GetTrace().Tracepoint(TraceEvents::NAPI_QUEUE);
        HttpExec::HandleCurlData(curlMessage, context);
    };
    callbacks.startedCallback = startedCallback;
    callbacks.doneCallback = responseCallback;

#ifdef HTTP_HANDOVER_FEATURE
    static auto handoverInfoCallback = +[](void *opaqueData) {
        HttpHandoverStackInfo httpHandoverStackInfo;
        auto context = static_cast<RequestContext *>(opaqueData);
        if (context == nullptr) {
            NETSTACK_LOGE("handoverInfoCallback context is nullptr, error!");
            return httpHandoverStackInfo;
        }
        httpHandoverStackInfo.taskId = context->GetTaskId();
        httpHandoverStackInfo.readTimeout = context->options.GetReadTimeout();
        httpHandoverStackInfo.connectTimeout = context->options.GetConnectTimeout();
        httpHandoverStackInfo.method = context->options.GetMethod();
        httpHandoverStackInfo.requestUrl = context->options.GetUrl();
        httpHandoverStackInfo.isInStream = context->IsRequestInStream();
        httpHandoverStackInfo.isSuccess = (context->IsParseOK() && context->IsExecOK());
        return httpHandoverStackInfo;
    };
    static auto setHandoverInfoCallback = +[](HttpHandoverInfo httpHandoverInfo, void *opaqueData) {
        auto context = static_cast<RequestContext *>(opaqueData);
        if (context == nullptr) {
            NETSTACK_LOGE("setHandoverInfoCallback context is nullptr, error!");
            return;
        }
        context->SetRequestHandoverInfo(httpHandoverInfo);
    };
    callbacks.handoverInfoCallback = handoverInfoCallback;
    callbacks.setHandoverInfoCallback = setHandoverInfoCallback;
#endif
}
#endif

void HttpExec::FinalResponseProcessing(RequestContext *requestContext)
{
    std::unique_ptr<RequestContext, decltype(&RequestContextDeleter)> context(requestContext, RequestContextDeleter);
    napi_value argv[EVENT_PARAM_TWO] = { nullptr };
    auto env = context->GetEnv();
    if (context->IsParseOK() && context->IsExecOK()) {
        argv[EVENT_PARAM_ZERO] = NapiUtils::GetUndefined(env);
        argv[EVENT_PARAM_ONE] = HttpExec::RequestCallback(context.get());
        if (argv[EVENT_PARAM_ONE] == nullptr) {
            return;
        }
    } else {
        argv[EVENT_PARAM_ZERO] =
            NapiUtils::CreateErrorMessage(env, context->GetErrorCode(), context->GetErrorMessage());
        if (argv[EVENT_PARAM_ZERO] == nullptr) {
            return;
        }

        argv[EVENT_PARAM_ONE] = NapiUtils::GetUndefined(env);
    }
    napi_value undefined = NapiUtils::GetUndefined(env);
    if (context->GetDeferred() != nullptr) {
        context->GetTrace().Finish();
        if (context->IsExecOK()) {
            napi_resolve_deferred(env, context->GetDeferred(), argv[EVENT_PARAM_ONE]);
        } else {
            napi_reject_deferred(env, context->GetDeferred(), argv[EVENT_PARAM_ZERO]);
        }
        return;
    }
    napi_value func = context->GetCallback();
    if (NapiUtils::GetValueType(env, func) == napi_function) {
        (void)NapiUtils::CallFunction(env, undefined, func, EVENT_PARAM_TWO, argv);
    }
}

void HttpExec::AsyncWorkRequestCallback(napi_env env, napi_status status, void *data)
{
    if (status != napi_ok) {
        return;
    }
    if (!data) {
        return;
    }
    auto context = reinterpret_cast<RequestContext *>(data);
    if (context->magicNumber_ != MAGIC_NUMBER) {
        return;
    }
    auto handleFinalResponseProcessing = std::bind(FinalResponseProcessing, context);
#if ENABLE_HTTP_INTERCEPT
    if (HttpInterceptor::FinalResponseInterceptorCallback(context, handleFinalResponseProcessing)) {
        return;
    }
#endif
    handleFinalResponseProcessing();
}
#if HAS_NETMANAGER_BASE
bool SetTraceOptions(CURL *curl, RequestContext *context)
{
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_RESOLVER_START_DATA, context, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_RESOLVER_START_FUNCTION,
                                  +[](void *, void *, void *clientp) {
        if (!clientp) {
            NETSTACK_LOGE("resolver_start_function clientp pointer is null");
            return 0;
        }
        auto ctx = reinterpret_cast<RequestContext *>(clientp);
        ctx->GetTrace().Tracepoint(TraceEvents::DNS);
        return 0;
    }, context);

    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SOCKOPTDATA, context, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SOCKOPTFUNCTION,
                                  +[](void *clientp, curl_socket_t, curlsocktype) {
        if (!clientp) {
            NETSTACK_LOGE("sockopt_functon clientp pointer is null");
            return 0;
        }
        auto ctx = reinterpret_cast<RequestContext *>(clientp);
        ctx->GetTrace().Tracepoint(TraceEvents::TCP);
        return CURL_SOCKOPT_OK;
    }, context);

    //this option may be overriden if HTTP_MULTIPATH_CERT_ENABLE enabled
    if (context->options.GetSslType() != SslType::TLCP) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_CTX_DATA, context, context);
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_CTX_FUNCTION,
                                    +[](CURL *, void *, void *clientp) {
            if (!clientp) {
                NETSTACK_LOGE("ssl_ctx func clientp pointer is null");
                return 0;
            }
            auto ctx = reinterpret_cast<RequestContext *>(clientp);
            ctx->GetTrace().Tracepoint(TraceEvents::TLS);
            return CURL_SOCKOPT_OK;
        }, context);
    }

    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PREREQDATA, context, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PREREQFUNCTION,
                                  +[](void *clientp, char *, char *, int, int) {
        if (!clientp) {
            NETSTACK_LOGE("prereq_functon clientp pointer is null");
            return CURL_PREREQFUNC_OK;
        }
        auto ctx = reinterpret_cast<RequestContext *>(clientp);
        ctx->GetTrace().Tracepoint(TraceEvents::SENDING);
        return CURL_PREREQFUNC_OK;
    }, context);
    return true;
}
#endif

#if ENABLE_HTTP_INTERCEPT
bool HttpExec::SetFollowLocation(CURL *curl, RequestContext *context)
{
    auto interceptor = context->GetInterceptor();
    if (interceptor != nullptr && interceptor->IsRedirectionInterceptor()) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_FOLLOWLOCATION, 0L, context);
    }
    return true;
}
#endif

bool HttpExec::AddCurlHandle(CURL *handle, RequestContext *context)
{
#if HAS_NETMANAGER_BASE
    if (handle == nullptr) {
#else
    if (handle == nullptr || staticVariable_.curlMulti == nullptr) {
#endif
        NETSTACK_LOGE("handle nullptr");
        return false;
    }

#if HAS_NETMANAGER_BASE
    std::stringstream name;
    auto isDebugMode = HttpUtils::IsDebugMode();
    if (context == nullptr) {
        NETSTACK_LOGE("context nullptr");
        return false;
    }
    auto urlWithoutParam = HttpUtils::RemoveUrlParameters(context->options.GetUrl());
    name << HTTP_REQ_TRACE_NAME << "_" << std::this_thread::get_id() << (isDebugMode ? ("_" + urlWithoutParam) : "");
    SetTraceOptions(handle, context);
    SetServerSSLCertOption(handle, context);
#if ENABLE_HTTP_INTERCEPT
    HttpInterceptor::SetFollowLocation(handle, context);
#endif
    HttpOverCurl::TransferCallbacks callbacks;
    SetRequestInfoCallbacks(callbacks);
    return HttpInterceptor::ExecuteConnectNetworkInterceptor(context, handle, callbacks);
#else
    std::thread([context, handle] {
        std::lock_guard guard(staticVariable_.curlMultiMutex);
        // Do SetServerSSLCertOption here to avoid blocking the main thread.
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
        pthread_setname_np(HTTP_CLIENT_TASK_THREAD);
#else
        pthread_setname_np(pthread_self(), HTTP_CLIENT_TASK_THREAD);
#endif
        SetServerSSLCertOption(handle, context);
        staticVariable_.infoQueue.emplace(context, handle);
        staticVariable_.conditionVariable.notify_all();
    }).detach();

    return true;
#endif
}

#if !HAS_NETMANAGER_BASE
HttpExec::StaticVariable HttpExec::staticVariable_; /* NOLINT */
#endif

bool HttpExec::RequestWithoutCache(RequestContext *context)
{
#if !HAS_NETMANAGER_BASE
    if (!staticVariable_.initialized) {
        NETSTACK_LOGE("curl not init");
        return false;
    }
#endif

    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handle(curl_easy_init(), curl_easy_cleanup);
    if (!handle) {
        NETSTACK_LOGE("Failed to create fetch task");
        return false;
    }

#if HAS_NETMANAGER_BASE
    NETSTACK_CURL_EASY_SET_OPTION(handle.get(), CURLOPT_PRIVATE, context, context);
#endif

    std::vector<std::string> vec;
    std::for_each(context->options.GetHeader().begin(), context->options.GetHeader().end(),
                  [&vec](const std::pair<std::string, std::string> &p) {
                      if (!p.second.empty()) {
                          vec.emplace_back(p.first + HttpConstant::HTTP_HEADER_SEPARATOR + p.second);
                      } else {
                          vec.emplace_back(p.first + HttpConstant::HTTP_HEADER_BLANK_SEPARATOR);
                      }
                  });
    context->SetCurlHeaderList(MakeHeaders(vec));
    if (!SetOption(handle.get(), context, context->GetCurlHeaderList())) {
        NETSTACK_LOGE("set option failed");
        return false;
    }

    context->response.SetRequestTime(HttpTime::GetNowTimeGMT());
    CURL* rawHandle = handle.release();
    context->SetCurlHandle(rawHandle);

    if (!AddCurlHandle(rawHandle, context)) {
        NETSTACK_LOGE("add handle failed");
        curl_easy_cleanup(rawHandle);
        return false;
    }

    return true;
}

bool HttpExec::GetCurlDataFromHandle(CURL *handle, RequestContext *context, CURLMSG curlMsg, CURLcode result)
{
    if (curlMsg != CURLMSG_DONE) {
        NETSTACK_LOGE("taskid=%{public}d, CURLMSG %{public}s", context->GetTaskId(), std::to_string(curlMsg).c_str());
        context->SetErrorCode(NapiUtils::NETSTACK_NAPI_INTERNAL_ERROR);
        return false;
    }

    if (result != CURLE_OK) {
        context->SetErrorCode(result);
        NETSTACK_LOGE("CURLcode result %{public}s", std::to_string(result).c_str());
        return false;
    }

    context->response.SetResponseTime(HttpTime::GetNowTimeGMT());

    CURLcode code;
    if (!context->response.isApplyBlockRedirectionInterceptor_) {
        int64_t responseCode;
        code = curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &responseCode);
        if (code != CURLE_OK) {
            context->SetErrorCode(code);
            return false;
        }
        context->response.SetResponseCode(responseCode);
        NETSTACK_LOGD("responseCode is %{public}s", std::to_string(responseCode).c_str());
    }

    struct curl_slist *cookies = nullptr;
    code = curl_easy_getinfo(handle, CURLINFO_COOKIELIST, &cookies);
    if (code != CURLE_OK) {
        context->SetErrorCode(code);
        return false;
    }
#if ENABLE_HTTP_INTERCEPT
    auto interceptor = context->GetInterceptor();
    if (interceptor != nullptr && interceptor->IsRedirectionInterceptor()) {
        context->response.SetCookies("");
    }
#endif
    std::unique_ptr<struct curl_slist, decltype(&curl_slist_free_all)> cookiesHandle(cookies, curl_slist_free_all);
    while (cookies) {
        context->response.AppendCookies(cookies->data, strlen(cookies->data));
        if (cookies->next != nullptr) {
            context->response.AppendCookies(HttpConstant::HTTP_LINE_SEPARATOR,
                                            strlen(HttpConstant::HTTP_LINE_SEPARATOR));
        }
        cookies = cookies->next;
    }
    return true;
}

double HttpExec::GetTimingFromCurl(CURL *handle, CURLINFO info)
{
    curl_off_t timing;
    CURLcode result = curl_easy_getinfo(handle, info, &timing);
    if (result != CURLE_OK) {
        NETSTACK_LOGE("Failed to get timing: %{public}d, %{public}s", info, curl_easy_strerror(result));
        return 0;
    }
    return Timing::TimeUtils::Microseconds2Milliseconds(timing);
}

curl_off_t HttpExec::GetSizeFromCurl(CURL *handle, RequestContext *context)
{
    auto info = CURLINFO_SIZE_DOWNLOAD_T;
    auto method = context->options.GetMethod();
    NETSTACK_LOGD("method is %{public}s", method.c_str());
    if (MethodForPost(method)) {
        info = CURLINFO_SIZE_UPLOAD_T;
    }

    curl_off_t size = 0;
    CURLcode result = curl_easy_getinfo(handle, info, &size);
    if (result != CURLE_OK) {
        NETSTACK_LOGE("Failed to get timing: %{public}d, %{public}s", info, curl_easy_strerror(result));
        return 0;
    }
    return size;
}

void HttpExec::CacheCurlPerformanceTiming(CURL *handle, RequestContext *context)
{
    auto dnsTime = HttpExec::GetTimingFromCurl(handle, CURLINFO_NAMELOOKUP_TIME_T);
    auto connectTime = HttpExec::GetTimingFromCurl(handle, CURLINFO_CONNECT_TIME_T);
    auto tlsTime = HttpExec::GetTimingFromCurl(handle, CURLINFO_APPCONNECT_TIME_T);
    auto firstSendTime = HttpExec::GetTimingFromCurl(handle, CURLINFO_PRETRANSFER_TIME_T);
    auto firstRecvTime = HttpExec::GetTimingFromCurl(handle, CURLINFO_STARTTRANSFER_TIME_T);
    auto totalTime = HttpExec::GetTimingFromCurl(handle, CURLINFO_TOTAL_TIME_T);
    auto redirectTime = HttpExec::GetTimingFromCurl(handle, CURLINFO_REDIRECT_TIME_T);

    context->CachePerformanceTimingItem(HttpConstant::RESPONSE_DNS_TIMING, dnsTime);
    context->CachePerformanceTimingItem(HttpConstant::RESPONSE_TCP_TIMING, connectTime);
    context->CachePerformanceTimingItem(HttpConstant::RESPONSE_TLS_TIMING, tlsTime);
    context->CachePerformanceTimingItem(HttpConstant::RESPONSE_FIRST_SEND_TIMING, firstSendTime);
    context->CachePerformanceTimingItem(HttpConstant::RESPONSE_FIRST_RECEIVE_TIMING, firstRecvTime);
    context->CachePerformanceTimingItem(HttpConstant::RESPONSE_TOTAL_FINISH_TIMING, totalTime);
    context->CachePerformanceTimingItem(HttpConstant::RESPONSE_REDIRECT_TIMING, redirectTime);

    int64_t responseCode = 0;
    (void)curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &responseCode);
    long osErr = 0;
    (void)curl_easy_getinfo(handle, CURLINFO_OS_ERRNO, &osErr);

    /*
    CURL_HTTP_VERSION_NONE         0
    CURL_HTTP_VERSION_1_0          1
    CURL_HTTP_VERSION_1_1          2
    CURL_HTTP_VERSION_2            3
    */
    int64_t httpVer = CURL_HTTP_VERSION_NONE;
    (void)curl_easy_getinfo(handle, CURLINFO_HTTP_VERSION, &httpVer);
    curl_off_t size = GetSizeFromCurl(handle, context);
    char *ip = nullptr;
    curl_easy_getinfo(handle, CURLINFO_PRIMARY_IP, &ip);
    int32_t errCode = context->IsExecOK() ? 0 : context->GetErrorCode();
    char *daddr = nullptr;
    char *saddr = nullptr;
    long dport = 0;
    long sport = 0;
    curl_easy_getinfo(handle, CURLINFO_LOCAL_IP, &saddr);
    std::string anomSaddr = CommonUtils::ToAnonymousIp(saddr);
    curl_easy_getinfo(handle, CURLINFO_LOCAL_PORT, &sport);
    curl_easy_getinfo(handle, CURLINFO_PRIMARY_IP, &daddr);
    std::string anomDaddr = CommonUtils::ToAnonymousIp(daddr);
    curl_easy_getinfo(handle, CURLINFO_PRIMARY_PORT, &dport);
#ifdef HTTP_HANDOVER_FEATURE
    std::string handoverInfo = context->GetRequestHandoverInfo();
#endif
    NETSTACK_LOGI(
        "taskid=%{public}d"
        ", size:%{public}" CURL_FORMAT_CURL_OFF_T
        ", dns:%{public}.3f, connect:%{public}.3f, tls:%{public}.3f, firstSend:%{public}.3f"
        ", firstRecv:%{public}.3f, total:%{public}.3f, redirect:%{public}.3f"
#ifdef HTTP_HANDOVER_FEATURE
        ", %{public}s"
#endif
        ", errCode:%{public}d, RespCode:%{public}s, httpVer:%{public}s, method:%{public}s, osErr:%{public}ld"
        ", saddr:%{public}s, sport:%{public}ld, daddr:%{public}s, dport:%{public}ld",
        context->GetTaskId(), size, dnsTime, connectTime == 0 ? 0 : connectTime - dnsTime,
        tlsTime == 0 ? 0 : tlsTime - connectTime,
        firstSendTime == 0 ? 0 : firstSendTime - std::max({dnsTime, connectTime, tlsTime}),
        firstRecvTime == 0 ? 0 : firstRecvTime - firstSendTime, totalTime, redirectTime,
#ifdef HTTP_HANDOVER_FEATURE
        handoverInfo.c_str(),
#endif
        errCode, std::to_string(responseCode).c_str(),
        std::to_string(httpVer).c_str(), context->options.GetMethod().c_str(), osErr,
        anomSaddr.c_str(), sport, anomDaddr.c_str(), dport);
#if HAS_NETMANAGER_BASE
    if (EventReport::GetInstance().IsValid()) {
        HttpPerfInfo httpPerfInfo;
        httpPerfInfo.totalTime = totalTime;
        httpPerfInfo.size = static_cast<int64_t>(size);
        httpPerfInfo.dnsTime = dnsTime;
        httpPerfInfo.tlsTime = tlsTime == 0 ? 0 : tlsTime - connectTime;
        httpPerfInfo.tcpTime = connectTime == 0 ? 0 : connectTime - dnsTime;
        httpPerfInfo.firstRecvTime = firstRecvTime == 0 ? 0 : firstRecvTime - firstSendTime;
        httpPerfInfo.responseCode = responseCode;
        httpPerfInfo.version = std::to_string(httpVer);
        httpPerfInfo.osErr = static_cast<int64_t>(osErr);
        httpPerfInfo.errCode = errCode;
        httpPerfInfo.ipType = CommonUtils::DetectIPType((ip != nullptr) ? ip : "");
        EventReport::GetInstance().ProcessHttpPerfHiSysevent(httpPerfInfo);
    }
#endif
}

#if HAS_NETMANAGER_BASE
void HttpExec::HandleCurlData(CURLMsg *msg, RequestContext *context)
#else
void HttpExec::HandleCurlData(CURLMsg *msg)
#endif
{
    if (msg == nullptr) {
        return;
    }

    auto handle = msg->easy_handle;
    if (handle == nullptr) {
        return;
    }

#if !HAS_NETMANAGER_BASE
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
#endif
    NETSTACK_LOGD("priority = %{public}d", context->options.GetPriority());
    context->SetExecOK(GetCurlDataFromHandle(handle, context, msg->msg, msg->data.result));
    CacheCurlPerformanceTiming(handle, context);
    if (context->IsExecOK()) {
        CacheProxy proxy(context->options);
        proxy.WriteResponseToCache(context->response);
    }
    context->SendNetworkProfiler();
    if (handle) {
        (void)curl_easy_cleanup(handle);
    }
    if (context->GetSharedManager() == nullptr) {
        NETSTACK_LOGE("can not find context manager");
        return;
    }
    if (context->IsRequestInStream()) {
        NapiUtils::CreateUvQueueWorkByModuleId(
            context->GetEnv(), std::bind(AsyncWorkRequestInStreamCallback, context->GetEnv(), napi_ok, context),
            context->GetModuleId());
    } else {
        NapiUtils::CreateUvQueueWorkByModuleId(context->GetEnv(),
                                               std::bind(AsyncWorkRequestCallback, context->GetEnv(), napi_ok, context),
                                               context->GetModuleId());
    }
}

static bool ExecRequestCheck(RequestContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    if (context->IsAtomicService() &&
        !CommonUtils::IsAllowedHostname(context->GetBundleName(), CommonUtils::DOMAIN_TYPE_HTTP_REQUEST,
                                        context->options.GetUrl())) {
        context->SetNoAllowedHost(true);
        return false;
    }
    if (!CommonUtils::IsCleartextPermitted(context->options.GetUrl(), "http://")) {
        context->SetCleartextNotPermitted(true);
        return false;
    }
    return true;
}

void HttpExec::EnqueueCallback(RequestContext *context)
{
    if (context->GetSharedManager()) {
        auto env = context->GetEnv();
        auto moduleId = context->GetModuleId();
        if (context->IsRequestInStream()) {
            NapiUtils::CreateUvQueueWorkByModuleId(
                env, std::bind(AsyncWorkRequestInStreamCallback, env, napi_ok, context), moduleId);
        } else {
            NapiUtils::CreateUvQueueWorkByModuleId(
                env, std::bind(AsyncWorkRequestCallback, env, napi_ok, context), moduleId);
        }
    }
}

bool HttpExec::HandleInitialRequestPostProcessing(
    RequestContext *context, HiAppEventReport hiAppEventReport, int64_t &limitSdkReport)
{
    context->options.SetRequestTime(HttpTime::GetNowTimeGMT());
    CacheProxy proxy(context->options);

    if (context->IsUsingCache() && proxy.ReadResponseFromCache(context)) {
        auto handleCacheCheckedPostProcessing [[maybe_unused]] = std::bind(
            [](RequestContext *ctx) {
                EnqueueCallback(ctx);
                return true;
            },
            context);
        auto blockCacheCheckedPostProcessing [[maybe_unused]] = std::bind(
            [](RequestContext *ctx) {
                EnqueueCallback(ctx);
                return false;
            },
            context);
#if ENABLE_HTTP_INTERCEPT
        if (HttpInterceptor::CacheCheckedInterceptorCallback(context, handleCacheCheckedPostProcessing,
                                                             blockCacheCheckedPostProcessing)) {
            return true;
        }
#endif
        return handleCacheCheckedPostProcessing();
    }

    if (!RequestWithoutCache(context)) {
        context->SetErrorCode(NapiUtils::NETSTACK_NAPI_INTERNAL_ERROR);
        EnqueueCallback(context);
        return false;
    }

    if (limitSdkReport == 0) {
        hiAppEventReport.ReportSdkEvent(RESULT_SUCCESS, ERR_NONE);
        limitSdkReport = 1;
    }

    return true;
}

void HttpExec::ProcessResponseBodyAndEmitEvents(RequestContext *context)
{
    if (context == nullptr || !context->GetSharedManager()) {
        return;
    }
    if (context->GetSharedManager()->IsEventDestroy()) {
        context->StopAndCacheNapiPerformanceTiming(HttpConstant::RESPONSE_BODY_TIMING);
        return;
    }
    if (context->IsRequestInStream()) {
        NapiUtils::CreateUvQueueWorkByModuleId(
            context->GetEnv(), std::bind(OnDataReceive, context->GetEnv(), napi_ok, context), context->GetModuleId());
    }
    context->StopAndCacheNapiPerformanceTiming(HttpConstant::RESPONSE_BODY_TIMING);
}

void HttpExec::ProcessResponseHeadersAndEmitEvents(RequestContext *context)
{
    context->GetTrace().Tracepoint(TraceEvents::RECEIVING);
    if (context->GetSharedManager()->IsEventDestroy()) {
        context->StopAndCacheNapiPerformanceTiming(HttpConstant::RESPONSE_HEADER_TIMING);
        return;
    }
    if (CommonUtils::EndsWith(context->response.GetRawHeader(), HttpConstant::HTTP_RESPONSE_HEADER_SEPARATOR)) {
        context->response.ParseHeaders();
        if (context->GetSharedManager()) {
            auto headerMap = new std::map<std::string, std::string>(MakeHeaderWithSetCookie(context));
            context->GetSharedManager()->EmitByUvWithoutCheckShared(
                ON_HEADER_RECEIVE, headerMap, ResponseHeaderCallback);
            auto headersMap = new std::map<std::string, std::string>(MakeHeaderWithSetCookie(context));
            context->GetSharedManager()->EmitByUvWithoutCheckShared(
                ON_HEADERS_RECEIVE, headersMap, ResponseHeaderCallback);
        }
    }
    context->StopAndCacheNapiPerformanceTiming(HttpConstant::RESPONSE_HEADER_TIMING);
}

bool HttpExec::ExecRequest(RequestContext *context)
{
    HiAppEventReport hiAppEventReport("NetworkKit", "HttpRequest");
    if (!ExecRequestCheck(context)) {
        return false;
    }
    if (context->GetSharedManager()->IsEventDestroy()) {
        return false;
    }
    auto continueCallback =
        std::bind(&HandleInitialRequestPostProcessing, context, hiAppEventReport, std::ref(g_limitSdkReport));
    auto blockCallback [[maybe_unused]] = std::bind(
        [](RequestContext *ctx) {
            ProcessResponseHeadersAndEmitEvents(ctx);
            ProcessResponseBodyAndEmitEvents(ctx);
            EnqueueCallback(ctx);
        },
        context);
#if ENABLE_HTTP_INTERCEPT
    if (HttpInterceptor::InitialRequestInterceptorCallback(context, continueCallback, blockCallback)) {
        return true;
    }
#endif
    return continueCallback();
}

napi_value HttpExec::BuildRequestCallback(RequestContext *context)
{
    napi_value object = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), object) != napi_object) {
        return nullptr;
    }

    NapiUtils::SetUint32Property(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESPONSE_CODE,
                                 context->response.GetResponseCode());
    NapiUtils::SetStringPropertyUtf8(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_COOKIES,
                                     context->response.GetCookies());

    napi_value header = MakeResponseHeader(context->GetEnv(), context);
    if (NapiUtils::GetValueType(context->GetEnv(), header) == napi_object) {
        NapiUtils::SetNamedProperty(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_HEADER, header);
    }

    if (context->options.GetHttpDataType() != HttpDataType::NO_DATA_TYPE && ProcByExpectDataType(object, context)) {
        return object;
    }

    auto contentType = CommonUtils::ToLower(const_cast<std::map<std::string, std::string> &>(
        context->response.GetHeader())[HttpConstant::HTTP_CONTENT_TYPE]);
    if (contentType.find(HttpConstant::HTTP_CONTENT_TYPE_OCTET_STREAM) != std::string::npos ||
        contentType.find(HttpConstant::HTTP_CONTENT_TYPE_IMAGE) != std::string::npos) {
        void *data = nullptr;
        auto body = context->response.GetResult();
        napi_value arrayBuffer = NapiUtils::CreateArrayBuffer(context->GetEnv(), body.size(), &data);
        if (data != nullptr && arrayBuffer != nullptr) {
            if (memcpy_s(data, body.size(), body.c_str(), body.size()) != EOK) {
                NETSTACK_LOGE("memcpy_s failed!");
                return object;
            }
            NapiUtils::SetNamedProperty(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT, arrayBuffer);
        }
        NapiUtils::SetUint32Property(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT_TYPE,
                                     static_cast<uint32_t>(HttpDataType::ARRAY_BUFFER));
        return object;
    }

    /* now just support utf8 */
    NapiUtils::SetStringPropertyUtf8(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT,
                                     context->response.GetResult());
    NapiUtils::SetUint32Property(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT_TYPE,
                                 static_cast<uint32_t>(HttpDataType::STRING));
    return object;
}

napi_value HttpExec::RequestCallback(RequestContext *context)
{
    napi_value result = HttpExec::BuildRequestCallback(context);
    context->StopAndCacheNapiPerformanceTiming(HttpConstant::RESPONSE_TOTAL_TIMING);
    context->SetPerformanceTimingToResult(result);
    return result;
}

napi_value HttpExec::RequestInStreamCallback(OHOS::NetStack::Http::RequestContext *context)
{
    napi_value number = NapiUtils::CreateUint32(context->GetEnv(), context->response.GetResponseCode());
    if (NapiUtils::GetValueType(context->GetEnv(), number) != napi_number) {
        return nullptr;
    }
    return number;
}

std::string HttpExec::MakeUrl(const std::string &url, std::string param, const std::string &extraParam)
{
    if (param.empty()) {
        param += extraParam;
    } else {
        param += HttpConstant::HTTP_URL_PARAM_SEPARATOR;
        param += extraParam;
    }

    if (param.empty()) {
        return url;
    }

    return url + HttpConstant::HTTP_URL_PARAM_START + param;
}

bool HttpExec::MethodForGet(const std::string &method)
{
    return (method == HttpConstant::HTTP_METHOD_HEAD || method == HttpConstant::HTTP_METHOD_OPTIONS ||
            method == HttpConstant::HTTP_METHOD_TRACE || method == HttpConstant::HTTP_METHOD_GET ||
            method == HttpConstant::HTTP_METHOD_CONNECT);
}

bool HttpExec::MethodForPost(const std::string &method)
{
    return (method == HttpConstant::HTTP_METHOD_POST || method == HttpConstant::HTTP_METHOD_PUT ||
            method == HttpConstant::HTTP_METHOD_DELETE || method.empty());
}

bool HttpExec::EncodeUrlParam(std::string &str)
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

#if !HAS_NETMANAGER_BASE
void HttpExec::AddRequestInfo()
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
#endif

#if !HAS_NETMANAGER_BASE
void HttpExec::RunThread()
{
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(HTTP_TASK_RUN_THREAD);
#else
    pthread_setname_np(pthread_self(), HTTP_TASK_RUN_THREAD);
#endif
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

void HttpExec::SendRequest()
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

void HttpExec::ReadResponse()
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
#endif

void HttpExec::GetGlobalHttpProxyInfo(std::string &host, int32_t &port, std::string &exclusions)
{
#ifdef HTTP_PROXY_ENABLE
    char httpProxyHost[SYSPARA_MAX_SIZE] = {0};
    char httpProxyPort[SYSPARA_MAX_SIZE] = {0};
    char httpProxyExclusions[SYSPARA_MAX_SIZE] = {0};
    GetParameter(HTTP_PROXY_HOST_KEY, DEFAULT_HTTP_PROXY_HOST, httpProxyHost, sizeof(httpProxyHost));
    GetParameter(HTTP_PROXY_PORT_KEY, DEFAULT_HTTP_PROXY_PORT, httpProxyPort, sizeof(httpProxyPort));
    GetParameter(HTTP_PROXY_EXCLUSIONS_KEY, DEFAULT_HTTP_PROXY_EXCLUSION_LIST, httpProxyExclusions,
                 sizeof(httpProxyExclusions));

    host = Base64::Decode(httpProxyHost);
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

void HttpExec::GetHttpProxyInfo(RequestContext *context, std::string &host, int32_t &port, std::string &exclusions,
    NapiUtils::SecureData &username, NapiUtils::SecureData &password)
{
    if (context->options.GetUsingHttpProxyType() == UsingHttpProxyType::USE_DEFAULT) {
#ifdef HAS_NETMANAGER_BASE
        NetManagerStandard::HttpProxy httpProxy;
        NetManagerStandard::NetConnClient::GetInstance().GetDefaultHttpProxy(httpProxy);
        host = httpProxy.GetHost();
        port = httpProxy.GetPort();
        exclusions = CommonUtils::ToString(httpProxy.GetExclusionList());
        NetManagerStandard::SecureData usernameTmp = httpProxy.GetUsername();
        NetManagerStandard::SecureData passwordTmp = httpProxy.GetPassword();
        username = usernameTmp.c_str();
        password = passwordTmp.c_str();
#else
        GetGlobalHttpProxyInfo(host, port, exclusions);
        username = "";
        password = "";
#endif
    } else if (context->options.GetUsingHttpProxyType() == UsingHttpProxyType::USE_SPECIFIED) {
        context->options.GetSpecifiedHttpProxy(host, port, exclusions, username, password);
    }
}

#if !HAS_NETMANAGER_BASE
bool HttpExec::Initialize()
{
    std::lock_guard<std::mutex> lock(staticVariable_.mutexForInitialize);
    if (staticVariable_.initialized) {
        return true;
    }
    NETSTACK_LOGD("call curl_global_init");
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
#endif

bool HttpExec::IsBuiltWithOpenSSL()
{
    const auto data = curl_version_info(CURLVERSION_NOW);
    if (!data || !data->ssl_version) {
        return false;
    }

    const auto sslVersion = CommonUtils::ToLower(data->ssl_version);
    return sslVersion.find("openssl") != std::string::npos;
}

unsigned long GetTlsVersion(TlsVersion tlsVersionMin, TlsVersion tlsVersionMax)
{
    unsigned long tlsVersion = CURL_SSLVERSION_DEFAULT;
    if (tlsVersionMin == TlsVersion::DEFAULT || tlsVersionMax == TlsVersion::DEFAULT) {
        return tlsVersion;
    }
    if (tlsVersionMin > tlsVersionMax) {
        return tlsVersion;
    }
    if (tlsVersionMin == TlsVersion::TLSv1_0) {
        tlsVersion |= static_cast<unsigned long>(CURL_SSLVERSION_TLSv1_0);
    } else if (tlsVersionMin == TlsVersion::TLSv1_1) {
        tlsVersion |= static_cast<unsigned long>(CURL_SSLVERSION_TLSv1_1);
    }  else if (tlsVersionMin == TlsVersion::TLSv1_2) {
        tlsVersion |= static_cast<unsigned long>(CURL_SSLVERSION_TLSv1_2);
    }  else if (tlsVersionMin == TlsVersion::TLSv1_3) {
        tlsVersion |= static_cast<unsigned long>(CURL_SSLVERSION_TLSv1_3);
    }

    if (tlsVersionMax == TlsVersion::TLSv1_0) {
        tlsVersion |= static_cast<unsigned long>(CURL_SSLVERSION_MAX_TLSv1_0);
    } else if (tlsVersionMax == TlsVersion::TLSv1_1) {
        tlsVersion |= static_cast<unsigned long>(CURL_SSLVERSION_MAX_TLSv1_1);
    } else if (tlsVersionMax == TlsVersion::TLSv1_2) {
        tlsVersion |= static_cast<unsigned long>(CURL_SSLVERSION_MAX_TLSv1_2);
    } else if (tlsVersionMax == TlsVersion::TLSv1_3) {
        tlsVersion |= static_cast<unsigned long>(CURL_SSLVERSION_MAX_TLSv1_3);
    }

    return tlsVersion;
}

bool HttpExec::SetOtherOption(CURL *curl, OHOS::NetStack::Http::RequestContext *context)
{
    std::string url = context->options.GetUrl();
    std::string host, exclusions;
    int32_t port = 0;
    NapiUtils::SecureData username;
    NapiUtils::SecureData password;
    GetHttpProxyInfo(context, host, port, exclusions, username, password);
    if (!host.empty() && !CommonUtils::IsHostNameExcluded(url, exclusions, ",")) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PROXY, host.c_str(), context);
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PROXYPORT, port, context);
        auto curlTunnelValue = (url.find("https://") != std::string::npos) ? 1L : 0L;
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_HTTPPROXYTUNNEL, curlTunnelValue, context);
        auto proxyType = (host.find("https://") != std::string::npos) ? CURLPROXY_HTTPS : CURLPROXY_HTTP;
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PROXYTYPE, proxyType, context);
        if (!username.empty() && !password.empty()) {
            NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PROXYUSERNAME, username.c_str(), context);
            NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PROXYPASSWORD, password.c_str(), context);
        }
    }
    const auto &tlsOption = context->options.GetTlsOption();
    unsigned long tlsVersion = GetTlsVersion(tlsOption.tlsVersionMin, tlsOption.tlsVersionMax);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSLVERSION, static_cast<long>(tlsVersion), context);
    const auto &cipherSuite = tlsOption.cipherSuite;
    const auto &cipherSuiteString = ConvertCipherSuiteToCipherString(cipherSuite);
    const auto &normalString = cipherSuiteString.ciperSuiteString;
    const auto &tlsV13String = cipherSuiteString.tlsV13CiperSuiteString;
    if (tlsVersion == CURL_SSLVERSION_DEFAULT) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2, context);
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_CIPHER_LIST, TLS12_SECURITY_CIPHER_SUITE, context);
    } else if (normalString.empty() && tlsV13String.empty()) {
        NETSTACK_LOGD("no cipherSuite config");
    } else if (!normalString.empty()) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_CIPHER_LIST, normalString.c_str(), context);
        if (!tlsV13String.empty() && IsBuiltWithOpenSSL()) {
            NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_TLS13_CIPHERS, tlsV13String.c_str(), context);
        }
    } else if (!tlsV13String.empty() && IsBuiltWithOpenSSL()) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_TLS13_CIPHERS, tlsV13String.c_str(), context);
    } else {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2, context);
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_CIPHER_LIST, TLS12_SECURITY_CIPHER_SUITE, context);
    }
    if (!SetOtherFixedOption(curl, context)) {
        return false;
    }
    
    return true;
}

bool HttpExec::SetOtherFixedOption(CURL *curl, OHOS::NetStack::Http::RequestContext *context)
{
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

bool HttpExec::SetAuthOptions(CURL *curl, OHOS::NetStack::Http::RequestContext *context)
{
    long authType = CURLAUTH_ANY;
    auto authentication = context->options.GetServerAuthentication();;
    switch (authentication.authenticationType) {
        case AuthenticationType::BASIC:
            authType = CURLAUTH_BASIC;
            break;
        case AuthenticationType::NTLM:
            authType = CURLAUTH_NTLM;
            break;
        case AuthenticationType::DIGEST:
            authType = CURLAUTH_DIGEST;
            break;
        case AuthenticationType::AUTO:
        default:
            break;
    }
    auto username = authentication.credential.username;
    auto password = authentication.credential.password;
    if (!username.empty()) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_HTTPAUTH, authType, context);
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_USERNAME, username.c_str(), context);
    }
    if (!password.empty()) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PASSWORD, password.c_str(), context);
    }

    return true;
}

bool HttpExec::SetSSLCertOption(CURL *curl, OHOS::NetStack::Http::RequestContext *context)
{
    std::string cert;
    std::string certType;
    std::string key;
    Secure::SecureChar keyPasswd;
    context->options.GetClientCert(cert, certType, key, keyPasswd);
    if (cert.empty()) {
        NETSTACK_LOGD("SetSSLCertOption param is empty.");
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

CURLcode HttpExec::SslCtxFunction(CURL *curl, void *sslCtx, void *request_context)
{
    auto requestContext = static_cast<RequestContext *>(request_context);
    if (requestContext == nullptr) {
        NETSTACK_LOGE("requestContext is null");
        return CURLE_SSL_CERTPROBLEM;
    }
    CURLcode result = MultiPathSslCtxFunction(curl, sslCtx, requestContext);
    if (result != CURLE_OK) {
        return result;
    }
    if (!requestContext->GetPinnedPubkey().empty()) {
        return VerifyRootCaSslCtxFunction(curl, sslCtx, requestContext);
    }
    return CURLE_OK;
}

#ifdef HTTP_MULTIPATH_CERT_ENABLE
static bool LoadCaCertFromString(X509_STORE *store, const std::string &certData)
{
    if (!store || certData.empty() || certData.size() > static_cast<size_t>(INT_MAX)) {
        NETSTACK_LOGE("store or certData is empty, or cert size is over INT_MAX");
        return false;
    }

    auto cbio = BIO_new_mem_buf(certData.data(), static_cast<int>(certData.size()));
    if (!cbio) {
        NETSTACK_LOGE("cbio is nullptr");
        return false;
    }

    auto inf = PEM_X509_INFO_read_bio(cbio, nullptr, nullptr, nullptr);
    if (!inf) {
        NETSTACK_LOGE("read cert failed.");
        BIO_free(cbio);
        return false;
    }
    
    /* add each entry from PEM file to x509_store */
    for (int i = 0; i < static_cast<int>(sk_X509_INFO_num(inf)); ++i) {
        auto itmp = sk_X509_INFO_value(inf, i);
        if (!itmp) {
            continue;
        }
        if ((itmp->x509 && X509_STORE_add_cert(store, itmp->x509) != 1) ||
            (itmp->crl && X509_STORE_add_crl(store, itmp->crl) != 1)) {
            NETSTACK_LOGE("add caCert or crt failed");
            sk_X509_INFO_pop_free(inf, X509_INFO_free);
            BIO_free(cbio);
            return false;
        }
    }
    
    return true;
}
#endif // HTTP_MULTIPATH_CERT_ENABLE

CURLcode HttpExec::MultiPathSslCtxFunction(CURL *curl, void *sslCtx, void *request_context)
{
#ifdef HTTP_MULTIPATH_CERT_ENABLE
    auto requestContext = static_cast<RequestContext *>(request_context);
    if (requestContext == nullptr) {
        NETSTACK_LOGE("requestContext is null");
        return CURLE_SSL_CERTPROBLEM;
    }
    requestContext->GetTrace().Tracepoint(TraceEvents::TLS);
    auto &certsPath = requestContext->GetCertsPath();
    if (sslCtx == nullptr) {
        NETSTACK_LOGE("ssl_ctx is null");
        return CURLE_SSL_CERTPROBLEM;
    }

    for (const auto &path : certsPath.certPathList) {
        if (path.empty() || access(path.c_str(), F_OK) != 0) {
            NETSTACK_LOGD("certificate directory path is not exist");
            continue;
        }
        if (!SSL_CTX_load_verify_locations(static_cast<SSL_CTX *>(sslCtx), nullptr, path.c_str())) {
            NETSTACK_LOGE("loading certificates from directory error.");
            continue;
        }
    }
    if (access(certsPath.certFile.c_str(), F_OK) != 0) {
        NETSTACK_LOGD("certificate directory path is not exist");
    } else if (!SSL_CTX_load_verify_locations(static_cast<SSL_CTX *>(sslCtx), certsPath.certFile.c_str(), nullptr)) {
        NETSTACK_LOGE("loading certificates from context cert error.");
    }
    if (!requestContext->options.GetCaData().empty()) {
        auto x509Store = SSL_CTX_get_cert_store(static_cast<SSL_CTX *>(sslCtx));
        if (!x509Store || !LoadCaCertFromString(x509Store, requestContext->options.GetCaData())) {
            return CURLE_SSL_CACERT_BADFILE;
        }
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
    X509 *cert;
    int err, depth;
    SSL *ssl;

    cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    NETSTACK_LOGI("X509_STORE_CTX error code %{public}d, depth %{public}d", err, depth);

    ssl = static_cast<SSL *>(X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
    SSL_CTX *sslCtx = SSL_get_SSL_CTX(ssl);
    RequestContext *requestContext = static_cast<RequestContext *>(SSL_CTX_get_ex_data(sslCtx,
        SSL_CTX_EX_DATA_REQUEST_CONTEXT_INDEX));
    if (requestContext == nullptr) {
        NETSTACK_LOGE("requestContext is null, fail");
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
#endif

CURLcode HttpExec::VerifyRootCaSslCtxFunction(CURL *curl, void *sslCtx, void *context)
{
#ifdef HTTP_ONLY_VERIFY_ROOT_CA_ENABLE
    SSL_CTX *ctx = static_cast<SSL_CTX *>(sslCtx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, VerifyCallback);
    SSL_CTX_set_ex_data(ctx, SSL_CTX_EX_DATA_REQUEST_CONTEXT_INDEX, context);
#endif
    return CURLE_OK;
}

[[maybe_unused]] void TrustUser0AndUserCa(std::vector<std::string> &certs)
{
#ifdef HTTP_MULTIPATH_CERT_ENABLE
    if (NetManagerStandard::NetworkSecurityConfig::GetInstance().TrustUser0Ca()) {
        certs.emplace_back(USER_CERT_ROOT_PATH);
    }
    if (NetManagerStandard::NetworkSecurityConfig::GetInstance().TrustUserCa()) {
        certs.emplace_back(BASE_PATH + std::to_string(getuid() / UID_TRANSFORM_DIVISOR));
    }
#endif
}

bool HttpExec::SetServerSSLCertOption(CURL *curl, OHOS::NetStack::Http::RequestContext *context)
{
#ifndef NO_SSL_CERTIFICATION
#ifdef HAS_NETMANAGER_BASE
    auto hostname = CommonUtils::GetHostnameFromURL(context->options.GetUrl());
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    std::vector<std::string> certs;
    // add app cert path
    auto ret = NetManagerStandard::NetworkSecurityConfig::GetInstance().GetTrustAnchorsForHostName(hostname, certs);
    if (ret != 0) {
        NETSTACK_LOGE("GetTrustAnchorsForHostName error. ret [%{public}d]", ret);
    }
#ifdef HTTP_MULTIPATH_CERT_ENABLE
    if (context->options.GetCanSkipCertVerifyFlag()) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYPEER, 0L, context);
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYHOST, 0L, context);
    } else {
        // add user cert path
        TrustUser0AndUserCa(certs);
        // add system cert path
        certs.emplace_back(HttpConstant::HTTP_PREPARE_CA_PATH);
        context->SetCertsPath(std::move(certs), context->options.GetCaPath());
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYPEER, 1L, context);
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYHOST, 2L, context);
    }
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
    if (!NetManagerStandard::NetworkSecurityConfig::GetInstance().IsPinOpenMode(hostname) ||
        NetManagerStandard::NetworkSecurityConfig::GetInstance().IsPinOpenModeVerifyRootCa(hostname)) {
        std::string pins;
        auto ret1 = NetManagerStandard::NetworkSecurityConfig::GetInstance().GetPinSetForHostName(hostname, pins);
        if (ret1 != 0 || pins.empty()) {
            NETSTACK_LOGD("Get no pinset by host name[%{public}s]", hostname.c_str());
        } else if (NetManagerStandard::NetworkSecurityConfig::GetInstance().IsPinOpenModeVerifyRootCa(hostname)) {
            context->SetPinnedPubkey(pins);
        } else {
            NETSTACK_LOGD("curl set pin =[%{public}s]", pins.c_str());
            NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PINNEDPUBLICKEY, pins.c_str(), context);
        }
    }
#if defined(HTTP_MULTIPATH_CERT_ENABLE) || defined(HTTP_ONLY_VERIFY_ROOT_CA_ENABLE)
    if (context->options.GetSslType() != SslType::TLCP) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_CTX_FUNCTION, SslCtxFunction, context);
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_CTX_DATA, context, context);
    }
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
    if (!SetSslTypeAndClientEncCert(curl, context)) {
        return false;
    }

    return true;
}

bool HttpExec::SetCertPinnerOption(CURL *curl, RequestContext *context)
{
    auto certPIN = context->options.GetCertificatePinning();
    if (certPIN.empty()) {
        NETSTACK_LOGD("CertificatePinning is empty");
        return true;
    }

    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PINNEDPUBLICKEY, certPIN.c_str(), context);
    return true;
}

bool HttpExec::SetDnsOption(CURL *curl, RequestContext *context)
{
    std::vector<std::string> dnsServers = context->options.GetDnsServers();
    if (dnsServers.empty()) {
        return true;
    }
    std::string serverList;
    for (auto &server : dnsServers) {
        serverList += server + ",";
        NETSTACK_LOGD("SetDns server: %{public}s", CommonUtils::AnonymizeIp(server).c_str());
    }
    serverList.pop_back();
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_DNS_SERVERS, serverList.c_str(), context);
    return true;
}

bool HttpExec::ParseHostAndPortFromUrl(const std::string &url, std::string &host, uint16_t &port)
{
    CURLU *cu = curl_url();
    if (!cu) {
        NETSTACK_LOGE("out of memory");
        return false;
    }
    if (curl_url_set(cu, CURLUPART_URL, url.c_str(), 0)) {
        NETSTACK_LOGE("not a normalized URL");
        curl_url_cleanup(cu);
        return false;
    }
    char *chost = nullptr;
    char *cport = nullptr;

    (void)curl_url_get(cu, CURLUPART_HOST, &chost, 0);
    (void)curl_url_get(cu, CURLUPART_PORT, &cport, CURLU_DEFAULT_PORT);
    if (chost != nullptr) {
        host = chost;
        curl_free(chost);
    }
    if (cport != nullptr) {
        port = atoi(cport);
        curl_free(cport);
    }
    curl_url_cleanup(cu);
    return !host.empty();
}

bool HttpExec::SetDnsResolvOption(CURL *curl, RequestContext *context)
{
    std::string host = "";
    uint16_t port = 0;
    if (!ParseHostAndPortFromUrl(context->options.GetUrl(), host, port)) {
        NETSTACK_LOGE("get host and port failed");
        return true;
    }
#ifdef HAS_NETMANAGER_BASE
    struct addrinfo *res = nullptr;
    int ret = getaddrinfo_hook(host.c_str(), nullptr, nullptr, &res);
    if (ret < 0) {
        return true;
    }

    struct curl_slist *hostSlist = nullptr;
    for (struct addrinfo *p = res; p != nullptr; p = p->ai_next) {
        char ipstr[INET6_ADDRSTRLEN];
        void *addr = nullptr;

        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = reinterpret_cast<struct sockaddr_in *>(p->ai_addr);
            addr = &ipv4->sin_addr;
        } else {
            struct sockaddr_in6 *ipv6 = reinterpret_cast<struct sockaddr_in6 *>(p->ai_addr);
            addr = &ipv6->sin6_addr;
        }
        if (inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr)) == NULL) {
            continue;
        }
        std::string resolvHost = host + ":" + std::to_string(port) + ":" + ipstr;
        hostSlist = curl_slist_append(hostSlist, resolvHost.c_str());
    }
    freeaddrinfo(res);
    if (hostSlist == nullptr) {
        NETSTACK_LOGE("no valid ip");
        return true;
    }
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_RESOLVE, hostSlist, context);
    context->SetCurlHostList(hostSlist);
#endif
    return true;
}

bool HttpExec::SetRequestOption(CURL *curl, RequestContext *context)
{
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_HTTP_VERSION, context->options.GetHttpVersion(), context);
    const std::string range = context->options.GetRangeString();
    if (range.empty()) {
        // Some servers don't like requests that are made without a user-agent field, so we provide one
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_USERAGENT, HttpConstant::HTTP_DEFAULT_USER_AGENT, context);
    } else {
        // https://curl.se/libcurl/c/CURLOPT_RANGE.html
        if (context->options.GetMethod() == HttpConstant::HTTP_METHOD_PUT) {
            context->SetErrorCode(CURLE_RANGE_ERROR);
            NETSTACK_LOGE(
                "For HTTP PUT uploads this option should not be used, since it may conflict with other options.");
            return false;
        }
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_RANGE, range.c_str(), context);
    }
    if (!context->options.GetDohUrl().empty()) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_DOH_URL, context->options.GetDohUrl().c_str(), context);
    }

    SetCertPinnerOption(curl, context);
    SetDnsOption(curl, context);
    SetSSLCertOption(curl, context);
    SetMultiPartOption(curl, context);
    SetDnsResolvOption(curl, context);
    SetDnsCacheOption(curl, context);
    SetIpResolve(curl, context);
    SetTCPOption(curl, context);
    return true;
}

bool HttpExec::SetOption(CURL *curl, RequestContext *context, struct curl_slist *requestHeader)
{
    const std::string &method = context->options.GetMethod();

    if (context->options.GetMethod() == HttpConstant::HTTP_METHOD_HEAD) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_NOBODY, 1L, context);
    }

    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_URL, context->options.GetUrl().c_str(), context);
#ifdef HAS_NETMANAGER_BASE
    bool ipv6Enable = NetSysIsIpv6Enable(0);
    bool ipv4Enable = NetSysIsIpv4Enable(0);
    if (!ipv6Enable) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4, context);
    } else if (!ipv4Enable) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6, context);
    }
#endif
    if (!method.empty()) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_CUSTOMREQUEST, method.c_str(), context);
    }

    if (!MethodForGet(method) && !context->options.GetBody().empty()) {
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
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_MAXREDIRS, context->options.GetMaxRedirects(), context);

    /* first #undef CURL_DISABLE_COOKIES in curl config */
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_COOKIEFILE, "", context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_NOSIGNAL, 1L, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_TIMEOUT_MS, context->options.GetReadTimeout(), context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_CONNECTTIMEOUT_MS, context->options.GetConnectTimeout(), context);

    if (!SetRequestOption(curl, context)) {
        return false;
    }

    if (!SetOtherOption(curl, context)) {
        return false;
    }

    if (!SetAuthOptions(curl, context)) {
        return false;
    }
    return true;
}

size_t HttpExec::OnWritingMemoryBody(const void *data, size_t size, size_t memBytes, void *userData)
{
    auto context = static_cast<RequestContext *>(userData);
    if (context == nullptr || !context->GetSharedManager()) {
        return 0;
    }
    if (context->GetSharedManager()->IsEventDestroy()) {
        context->StopAndCacheNapiPerformanceTiming(HttpConstant::RESPONSE_BODY_TIMING);
        return 0;
    }
    if (context->IsRequestInStream()) {
        context->SetTempData(data, size * memBytes);
        NapiUtils::CreateUvQueueWorkByModuleId(
            context->GetEnv(), std::bind(OnDataReceive, context->GetEnv(), napi_ok, context), context->GetModuleId());
        context->StopAndCacheNapiPerformanceTiming(HttpConstant::RESPONSE_BODY_TIMING);
        return size * memBytes;
    }

#if ENABLE_HTTP_INTERCEPT
    if (HttpInterceptor::RedirectionInterceptorBodyCallback(context, data, size, memBytes)) {
        return size * memBytes;
    }
#endif

    if (context->response.GetResult().size() > context->options.GetMaxLimit() ||
        size * memBytes > context->options.GetMaxLimit()) {
        NETSTACK_LOGE("response data exceeds the maximum limit");
        context->StopAndCacheNapiPerformanceTiming(HttpConstant::RESPONSE_BODY_TIMING);
        return 0;
    }
    context->response.AppendResult(data, size * memBytes);
    context->StopAndCacheNapiPerformanceTiming(HttpConstant::RESPONSE_BODY_TIMING);
    return size * memBytes;
}

static void MakeSetCookieArray(napi_env env, napi_value header,
                               const std::pair<const std::basic_string<char>, std::basic_string<char>> &headerElement)
{
    std::vector<std::string> cookieVec =
        CommonUtils::Split(headerElement.second, HttpConstant::RESPONSE_KEY_SET_COOKIE_SEPARATOR);
    uint32_t index = 0;
    auto len = cookieVec.size();
    auto array = NapiUtils::CreateArray(env, len);
    for (const auto &setCookie : cookieVec) {
        auto str = NapiUtils::CreateStringUtf8(env, setCookie);
        NapiUtils::SetArrayElement(env, array, index, str);
        ++index;
    }
    NapiUtils::SetArrayProperty(env, header, HttpConstant::RESPONSE_KEY_SET_COOKIE, array);
}

static void MakeHeaderWithSetCookieArray(napi_env env, napi_value header, std::map<std::string, std::string> *headerMap)
{
    for (const auto &it : *headerMap) {
        if (!it.first.empty() && !it.second.empty()) {
            if (it.first == HttpConstant::RESPONSE_KEY_SET_COOKIE) {
                MakeSetCookieArray(env, header, it);
                continue;
            }
            NapiUtils::SetStringPropertyUtf8(env, header, it.first, it.second);
        }
    }
}

void HttpExec::ResponseHeaderCallback(uv_work_t *work, int status)
{
    (void)status;

    auto workWrapper = static_cast<UvWorkWrapperShared *>(work->data);
    napi_env env = workWrapper->env;
    auto headerMap = static_cast<std::map<std::string, std::string> *>(workWrapper->data);
    auto closeScope = [env](napi_handle_scope scope) { NapiUtils::CloseScope(env, scope); };
    std::unique_ptr<napi_handle_scope__, decltype(closeScope)> scope(NapiUtils::OpenScope(env), closeScope);
    napi_value header = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, header) == napi_object) {
        MakeHeaderWithSetCookieArray(env, header, headerMap);
    }
    std::pair<napi_value, napi_value> arg = {NapiUtils::GetUndefined(env), header};
    workWrapper->manager->Emit(workWrapper->type, arg);
    delete headerMap;
    headerMap = nullptr;
    delete workWrapper;
    workWrapper = nullptr;
    delete work;
    work = nullptr;
}

std::map<std::string, std::string> HttpExec::MakeHeaderWithSetCookie(RequestContext *context)
{
    std::map<std::string, std::string> tempMap = context->response.GetHeader();
    std::string setCookies;
    size_t loop = 0;
    for (const auto &setCookie : context->response.GetsetCookie()) {
        setCookies += setCookie;
        if (loop + 1 < context->response.GetsetCookie().size()) {
            setCookies += HttpConstant::RESPONSE_KEY_SET_COOKIE_SEPARATOR;
        }
        ++loop;
    }
    tempMap[HttpConstant::RESPONSE_KEY_SET_COOKIE] = setCookies;
    return tempMap;
}

size_t HttpExec::OnWritingMemoryHeader(const void *data, size_t size, size_t memBytes, void *userData)
{
    auto context = static_cast<RequestContext *>(userData);
    if (context == nullptr) {
        return 0;
    }
    context->GetTrace().Tracepoint(TraceEvents::RECEIVING);
    auto sharedManager = context->GetSharedManager();
    if (sharedManager == nullptr || sharedManager->IsEventDestroy()) {
        context->StopAndCacheNapiPerformanceTiming(HttpConstant::RESPONSE_HEADER_TIMING);
        return 0;
    }
    context->response.AppendRawHeader(data, size * memBytes);
    if (CommonUtils::EndsWith(context->response.GetRawHeader(), HttpConstant::HTTP_RESPONSE_HEADER_SEPARATOR)) {
        context->response.ParseHeaders();
        auto headerMap = new std::map<std::string, std::string>(MakeHeaderWithSetCookie(context));
        sharedManager->EmitByUvWithoutCheckShared(ON_HEADER_RECEIVE, headerMap, ResponseHeaderCallback);
        auto headersMap = new std::map<std::string, std::string>(MakeHeaderWithSetCookie(context));
        sharedManager->EmitByUvWithoutCheckShared(ON_HEADERS_RECEIVE, headersMap, ResponseHeaderCallback);
    }
    context->StopAndCacheNapiPerformanceTiming(HttpConstant::RESPONSE_HEADER_TIMING);
    return size * memBytes;
}

void HttpExec::OnDataReceive(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<RequestContext *>(data);
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return;
    }

    void *buffer = nullptr;
    auto tempData = context->GetTempData();
    context->PopTempData();
    if (tempData.empty()) {
        NETSTACK_LOGI("[GetTempData] tempDate is empty!");
        return;
    }
    napi_value arrayBuffer = NapiUtils::CreateArrayBuffer(context->GetEnv(), tempData.size(), &buffer);
    if (buffer == nullptr || arrayBuffer == nullptr) {
        return;
    }
    if (memcpy_s(buffer, tempData.size(), tempData.data(), tempData.size()) != EOK) {
        NETSTACK_LOGE("[CreateArrayBuffer] memory copy failed");
        return;
    }
    context->EmitSharedManager(ON_DATA_RECEIVE,
                               std::make_pair(NapiUtils::GetUndefined(context->GetEnv()), arrayBuffer));
}

void HttpExec::OnDataProgress(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<RequestContext *>(data);
    if (context == nullptr) {
        NETSTACK_LOGD("OnDataProgress context is null");
        return;
    }
    auto progress = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), progress) == napi_undefined) {
        return;
    }
    auto dlLen = context->GetDlLen();
    if (dlLen.tLen && dlLen.nLen) {
        NapiUtils::SetUint32Property(context->GetEnv(), progress, "receiveSize", static_cast<uint32_t>(dlLen.nLen));
        NapiUtils::SetUint32Property(context->GetEnv(), progress, "totalSize", static_cast<uint32_t>(dlLen.tLen));

        context->EmitSharedManager(ON_DATA_RECEIVE_PROGRESS,
                                   std::make_pair(NapiUtils::GetUndefined(context->GetEnv()), progress));
    }
}

__attribute__((no_sanitize("cfi"))) void HttpExec::OnDataUploadProgress(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<RequestContext *>(data);
    if (context == nullptr) {
        NETSTACK_LOGD("OnDataUploadProgress context is null");
        return;
    }
    auto progress = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), progress) == napi_undefined) {
        NETSTACK_LOGD("OnDataUploadProgress napi_undefined");
        return;
    }
    NapiUtils::SetUint32Property(context->GetEnv(), progress, "sendSize",
                                 static_cast<uint32_t>(context->GetUlLen().nLen));
    NapiUtils::SetUint32Property(context->GetEnv(), progress, "totalSize",
                                 static_cast<uint32_t>(context->GetUlLen().tLen));
    context->EmitSharedManager(ON_DATA_SEND_PROGRESS,
                               std::make_pair(NapiUtils::GetUndefined(context->GetEnv()), progress));
}

__attribute__((no_sanitize("cfi"))) int HttpExec::ProgressCallback(void *userData, curl_off_t dltotal, curl_off_t dlnow,
                                                                   curl_off_t ultotal, curl_off_t ulnow)
{
    auto context = static_cast<RequestContext *>(userData);
    if (context == nullptr) {
        return 0;
    }
    if (ultotal != 0 && ultotal >= ulnow && !context->CompareWithLastElement(ulnow, ultotal)) {
        context->SetUlLen(ulnow, ultotal);
        NapiUtils::CreateUvQueueWorkByModuleId(context->GetEnv(),
                                               std::bind(OnDataUploadProgress, context->GetEnv(), napi_ok, context),
                                               context->GetModuleId());
    }
    if (!context->IsRequestInStream()) {
        return 0;
    }
    if (context->GetSharedManager()->IsEventDestroy()) {
        return 0;
    }
    if (dltotal != 0) {
        context->SetDlLen(dlnow, dltotal);
        NapiUtils::CreateUvQueueWorkByModuleId(
            context->GetEnv(), std::bind(OnDataProgress, context->GetEnv(), napi_ok, context), context->GetModuleId());
    }
    return 0;
}

struct curl_slist *HttpExec::MakeHeaders(const std::vector<std::string> &vec)
{
    struct curl_slist *header = nullptr;
    std::for_each(vec.begin(), vec.end(), [&header](const std::string &s) {
        if (!s.empty()) {
            header = curl_slist_append(header, s.c_str());
        }
    });
    return header;
}

napi_value HttpExec::MakeResponseHeader(napi_env env, void *ctx)
{
    auto context = reinterpret_cast<RequestContext *>(ctx);
    if (context->magicNumber_ != MAGIC_NUMBER) {
        return NapiUtils::CreateObject(env);
    }
    (void)env;
    napi_value header = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), header) == napi_object) {
        for (const auto &it : context->response.header_) {
            if (!it.first.empty() && !it.second.empty()) {
                NapiUtils::SetStringPropertyUtf8(context->GetEnv(), header, it.first, it.second);
            }
        }
        if (!context->response.setCookie_.empty()) {
            uint32_t index = 0;
            auto len = context->response.setCookie_.size();
            auto array = NapiUtils::CreateArray(context->GetEnv(), len);
            for (const auto &setCookie : context->response.setCookie_) {
                auto str = NapiUtils::CreateStringUtf8(context->GetEnv(), setCookie);
                NapiUtils::SetArrayElement(context->GetEnv(), array, index, str);
                ++index;
            }
            NapiUtils::SetArrayProperty(context->GetEnv(), header, HttpConstant::RESPONSE_KEY_SET_COOKIE, array);
        }
    }
    return header;
}

bool HttpExec::IsUnReserved(unsigned char in)
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

bool HttpExec::ProcByExpectDataType(napi_value object, RequestContext *context)
{
    switch (context->options.GetHttpDataType()) {
        case HttpDataType::STRING: {
            NapiUtils::SetStringPropertyUtf8(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT,
                                             context->response.GetResult());
            NapiUtils::SetUint32Property(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT_TYPE,
                                         static_cast<uint32_t>(HttpDataType::STRING));
            return true;
        }
        case HttpDataType::OBJECT: {
            if (context->response.GetResult().size() > HttpConstant::MAX_JSON_PARSE_SIZE) {
                return false;
            }

            napi_value obj = NapiUtils::JsonParse(context->GetEnv(), context->response.GetResult());
            if (obj) {
                NapiUtils::SetNamedProperty(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT, obj);
                NapiUtils::SetUint32Property(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT_TYPE,
                                             static_cast<uint32_t>(HttpDataType::OBJECT));
                return true;
            }

            // parse maybe failed
            return false;
        }
        case HttpDataType::ARRAY_BUFFER: {
            void *data = nullptr;
            auto body = context->response.GetResult();
            napi_value arrayBuffer = NapiUtils::CreateArrayBuffer(context->GetEnv(), body.size(), &data);
            if (data != nullptr && arrayBuffer != nullptr) {
                if (memcpy_s(data, body.size(), body.c_str(), body.size()) < 0) {
                    NETSTACK_LOGE("[ProcByExpectDataType] memory copy failed");
                    return true;
                }
                NapiUtils::SetNamedProperty(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT, arrayBuffer);
                NapiUtils::SetUint32Property(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT_TYPE,
                                             static_cast<uint32_t>(HttpDataType::ARRAY_BUFFER));
            }
            return true;
        }
        default:
            break;
    }
    return false;
}

void HttpExec::AsyncRunRequest(RequestContext *context)
{
    HttpAsyncWork::ExecRequest(context->GetEnv(), context);
}

#if !HAS_NETMANAGER_BASE
bool HttpExec::IsInitialized()
{
    return staticVariable_.initialized;
}

void HttpExec::DeInitialize()
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
#endif

bool HttpResponseCacheExec::ExecFlush(BaseContext *context)
{
    (void)context;
    CacheProxy::FlushCache();
    return true;
}

napi_value HttpResponseCacheExec::FlushCallback(BaseContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

bool HttpResponseCacheExec::ExecDelete(BaseContext *context)
{
    (void)context;
    CacheProxy::StopCacheAndDelete();
    return true;
}

napi_value HttpResponseCacheExec::DeleteCallback(BaseContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

bool HttpExec::SetMultiPartOption(CURL *curl, RequestContext *context)
{
    auto header = context->options.GetHeader();
    auto type = CommonUtils::ToLower(header[HttpConstant::HTTP_CONTENT_TYPE]);
    if (type != HttpConstant::HTTP_CONTENT_TYPE_MULTIPART) {
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
            NETSTACK_LOGE("Failed to set multiFormData error no data and filepath at the same time");
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

void HttpExec::SetFormDataOption(MultiFormData &multiFormData, curl_mimepart *part, CURL *curl, RequestContext *context)
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
        if (!multiFormData.remoteFileName.empty()) {
            std::string fileData;
            bool isReadFile = CommonUtils::GetFileDataFromFilePath(multiFormData.filePath.c_str(), fileData);
            if (isReadFile) {
                result = curl_mime_data(part, fileData.c_str(), fileData.size());
            } else {
                result = curl_mime_filedata(part, multiFormData.filePath.c_str());
            }
        } else {
            result = curl_mime_filedata(part, multiFormData.filePath.c_str());
        }
        if (result != CURLE_OK) {
            NETSTACK_LOGE("Failed to set file data error: %{public}s", curl_easy_strerror(result));
        }
    }
}

bool HttpExec::SetDnsCacheOption(CURL *curl, RequestContext *context)
{
#ifdef HAS_NETMANAGER_BASE
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_DNS_CACHE_TIMEOUT, 0, context);
#endif
    return true;
}

bool HttpExec::SetTCPOption(CURL *curl, RequestContext *context)
{
    if (!context) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SOCKOPTDATA, &context->options, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SOCKOPTFUNCTION,
        +[](void *clientp, curl_socket_t sock, curlsocktype type) -> int {
            if (!clientp) {
                return CURL_SOCKOPT_OK;
            }
            auto resp = reinterpret_cast<HttpRequestOptions *>(clientp);
            HttpRequestOptions::TcpConfiguration config = resp->GetTCPOption();
            if (config.SetOptionToSocket(sock)) {
                NETSTACK_LOGD("SetOptionToSocket userTimeout = %{public}d", config.userTimeout_);
            }

            return CURL_SOCKOPT_OK;
        }, context);
    return true;
}

bool HttpExec::SetIpResolve(CURL *curl, RequestContext *context)
{
    std::string addressFamily = context->options.GetAddressFamily();
    if (addressFamily.empty()) {
        return true;
    }
    if (addressFamily.compare(HTTP_AF_ONLYV4) == 0) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4, context);
    } else if (addressFamily.compare(HTTP_AF_ONLYV6) == 0) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6, context);
    }
    return true;
}

bool HttpExec::SetSslTypeAndClientEncCert(CURL *curl, RequestContext *context)
{
    auto sslType = context->options.GetSslType();
    if (sslType != SslType::TLCP) {
        return true;
    } else {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLCPv1_1, context);

        if (!context->options.GetCaPath().empty()) {
            NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_CAINFO, context->options.GetCaPath().c_str(), context);
        }

        std::string encCert;
        std::string encCertType;
        std::string encKey;
        Secure::SecureChar encKeyPasswd;
        context->options.GetClientEncCert(encCert, encCertType, encKey, encKeyPasswd);

        if (encCert.empty()) {
            return false;
        }
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSLENCCERT, encCert.c_str(), context);
        if (!encKey.empty()) {
            NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSLENCKEY, encKey.c_str(), context);
        }
        if (!encCertType.empty()) {
            NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSLCERTTYPE, encCertType.c_str(), context);
        }
        if (encKeyPasswd.Length() > 0) {
            NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_KEYPASSWD, encKeyPasswd.Data(), context);
        }
    }
    return true;
}

} // namespace OHOS::NetStack::Http
