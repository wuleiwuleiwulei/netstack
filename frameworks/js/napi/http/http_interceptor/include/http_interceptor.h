/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_HTTP_INTERCEPTOR_H
#define COMMUNICATIONNETSTACK_HTTP_INTERCEPTOR_H

#include <queue>
#include <mutex>
#include <map>
#include "curl/curl.h"
#include "base_context.h"
#include "http_request_options.h"
#include "http_response.h"
#include "hi_app_event_report.h"
#include "timing.h"
#include "request_info.h"
#include "request_context.h"
#if HAS_NETMANAGER_BASE
#include "epoll_request_handler.h"
#include "netstack_log.h"
#endif

namespace OHOS::NetStack::Http {

class RequestContext;
using RequestInterceptor = std::function<void(RequestContext *, std::function<bool()>, std::function<void()>)>;
using RedirectionInterceptor = std::function<void(
    RequestContext *, std::function<void()>, std::function<void()>, HttpOverCurl::RedirectionInterceptorInfo *)>;
using FinalResponseInterceptor = std::function<void(RequestContext *, std::function<void()>)>;

class HttpInterceptor {
public:
    friend class HttpExec;

    HttpInterceptor() = delete;

    explicit HttpInterceptor(const std::map<std::string, napi_ref> &interceptorRefs)
    {
        SetInterceptorRefs(interceptorRefs);
    }

    ~HttpInterceptor();

    bool IsInitialRequestInterceptor() const;
    bool IsRedirectionInterceptor() const;
    bool IsFinalResponseInterceptor() const;
    bool IsCacheCheckedInterceptor() const;
    bool IsConnectNetworkInterceptor() const;

    const RequestInterceptor &GetInitialRequestInterceptorCallback() const;
    const RedirectionInterceptor &GetRedirectionInterceptorCallback() const;
    const FinalResponseInterceptor &GetFinalResponseInterceptorCallback() const;
    const RequestInterceptor &GetCacheCheckedInterceptorCallback() const;
    const RequestInterceptor &GetConnectNetworkInterceptorCallback() const;

#if HAS_NETMANAGER_BASE
    static bool ExecuteConnectNetworkInterceptor(RequestContext *context, CURL *handle,
                                                 HttpOverCurl::TransferCallbacks callbacks);
#endif
    static bool SetFollowLocation(CURL *handle, RequestContext *context);

    static bool FinalResponseInterceptorCallback(RequestContext *context,
                                                 std::function<void()> handleFinalResponseProcessing);

    static bool CacheCheckedInterceptorCallback(RequestContext *context,
                                                std::function<bool()> handleCacheCheckedPostProcessing,
                                                std::function<void()> blockCacheCheckedPostProcessing);

    static bool InitialRequestInterceptorCallback(RequestContext *context, std::function<bool()> continueCallback,
                                                  std::function<void()> blockCallback);

    static bool RedirectionInterceptorBodyCallback(RequestContext *context, const void *data, size_t size,
                                                   size_t memBytes);

private:
    struct InitialRequestInterceptorHandle {
        std::function<bool()> after;
        RequestContext *context;
        std::function<void()> block;
        napi_value reqContext;
        napi_value resContext;
        ~InitialRequestInterceptorHandle() = default;
    };
    struct CacheCheckedInterceptorHandle {
        std::function<bool()> after;
        RequestContext *context;
        std::function<void()> block;
        napi_value reqContext;
        napi_value resContext;
        ~CacheCheckedInterceptorHandle() = default;
    };
    struct FinalResponseInterceptorHandle {
        std::function<void()> after;
        RequestContext *context;
        napi_value reqContext;
        napi_value resContext;
        ~FinalResponseInterceptorHandle() = default;
    };
    struct RedirectionInterceptorHandle {
        std::function<void()> handleRedirect;
        std::function<void()> handleCompletion;
        RequestContext *context;
        HttpOverCurl::RedirectionInterceptorInfo *handleInfo;
        napi_value reqContext;
        napi_value resContext;
        RedirectionInterceptorHandle(std::function<void()> redirect, std::function<void()> completion,
            HttpOverCurl::RedirectionInterceptorInfo *info, napi_value requestContext, napi_value responseContext)
            : handleRedirect(std::move(redirect)), handleCompletion(std::move(completion)), context(nullptr),
              handleInfo(info), reqContext(requestContext), resContext(responseContext)
        {
        }
        ~RedirectionInterceptorHandle() = default;
    };

    RequestInterceptor initialRequestInterceptorCallback_ = nullptr;
    RedirectionInterceptor redirectionInterceptorCallback_ = nullptr;
    FinalResponseInterceptor finalResponseInterceptorCallback_ = nullptr;
    RequestInterceptor cacheCheckedInterceptorCallback_ = nullptr;
    RequestInterceptor connectNetworkInterceptorCallback_ = nullptr;

    void SetInterceptorRefs(std::map<std::string, napi_ref> interceptorRefs);

    void SetInitialRequestInterceptor();
    void SetRedirectionInterceptor();
    void SetFinalResponseInterceptor();
    void SetCacheCheckedInterceptor();
    void SetConnectNetworkInterceptor();

    static void ApplyContinueInitialRequestInterceptor(napi_env env, InitialRequestInterceptorHandle *handle);
    static void ApplyBlockInitialRequestInterceptor(napi_env env, InitialRequestInterceptorHandle *handle);
    static napi_value CreateRequestContextInitialRequestInterceptor(napi_env env, RequestContext *context);
    static napi_value CreateResponseContextInitialRequestInterceptor(napi_env env, RequestContext *context);
    static void HandlePromiseThenInitialRequestInterceptor(
        napi_env env, InitialRequestInterceptorHandle *handle, napi_value promise);
    static void HandlePromiseInitialRequestInterceptor(napi_env env, InitialRequestInterceptorHandle *handle);

    static void ApplyContinueRedirectionInterceptor(napi_env env, RedirectionInterceptorHandle *handle);
    static void ApplyBlockRedirectionInterceptor(napi_env env, RedirectionInterceptorHandle *handle);
    static napi_value CreateRequestContextRedirectionInterceptor(
        napi_env env, RequestContext *context, HttpOverCurl::RedirectionInterceptorInfo *handleInfo);
    static napi_value CreateResponseContextRedirectionInterceptor(
        napi_env env, RequestContext *context, HttpOverCurl::RedirectionInterceptorInfo *handleInfo);
    static void HandlePromiseThenRedirectionInterceptor(
        napi_env env, RedirectionInterceptorHandle *handle, napi_value promise);
    static void HandlePromiseRedirectionInterceptor(napi_env env, RedirectionInterceptorHandle *handle);

    static void ApplyContinueFinalResponseInterceptor(napi_env env, FinalResponseInterceptorHandle *handle);
    static void ApplyBlockFinalResponseInterceptor(napi_env env, FinalResponseInterceptorHandle *handle);
    static napi_value CreateRequestContextFinalResponseInterceptor(napi_env env, RequestContext *context);
    static napi_value CreateResponseContextFinalResponseInterceptor(napi_env env, RequestContext *context);
    static void HandlePromiseThenFinalResponseInterceptor(
        napi_env env, FinalResponseInterceptorHandle *handle, napi_value promise);
    static void HandlePromiseFinalResponseInterceptor(napi_env env, FinalResponseInterceptorHandle *handle);

    static void ApplyContinueCacheCheckedInterceptor(napi_env env, CacheCheckedInterceptorHandle *handle);
    static void ApplyBlockCacheCheckedInterceptor(napi_env env, CacheCheckedInterceptorHandle *handle);
    static napi_value CreateRequestContextCacheCheckedInterceptor(napi_env env, RequestContext *context);
    static napi_value CreateResponseContextCacheCheckedInterceptor(napi_env env, RequestContext *context);
    static void HandlePromiseThenCacheCheckedInterceptor(
        napi_env env, CacheCheckedInterceptorHandle *handle, napi_value promise);
    static void HandlePromiseCacheCheckedInterceptor(napi_env env, CacheCheckedInterceptorHandle *handle);

    static void ApplyContinueConnectNetworkInterceptor(napi_env env, InitialRequestInterceptorHandle *handle);
    static void SetCurlPostFields(CURL *easyHander, const void *data, size_t length);
    static void ApplyBlockConnectNetworkInterceptor(napi_env env, InitialRequestInterceptorHandle *handle);
    static napi_value CreateRequestContextConnectNetworkInterceptor(napi_env env, RequestContext *context);
    static napi_value CreateResponseContextConnectNetworkInterceptor(napi_env env, RequestContext *context);
    static void HandlePromiseThenConnectNetworkInterceptor(
        napi_env env, InitialRequestInterceptorHandle *handle, napi_value promise);
    static void HandlePromiseConnectNetworkInterceptor(napi_env env, InitialRequestInterceptorHandle *handle);
};
} // namespace OHOS::NetStack::Http

#endif /* COMMUNICATIONNETSTACK_HTTP_INTERCEPTOR_H */
