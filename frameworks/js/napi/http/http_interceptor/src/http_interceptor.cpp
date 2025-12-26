/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "http_interceptor.h"

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

inline void INTERCEPTOR_TRACE_START(const std::string &interceptorType)
{
    NETSTACK_LOGI("Interceptor [%{public}s] START", interceptorType.c_str());
}

inline void INTERCEPTOR_TRACE_END(const std::string &interceptorType, const std::string &result)
{
    NETSTACK_LOGI("Interceptor [%{public}s] END, result: %{public}s", interceptorType.c_str(), result.c_str());
}

inline void INTERCEPTOR_TRACE_ERROR(const std::string &interceptorType, const std::string &error)
{
    NETSTACK_LOGE("Interceptor [%{public}s] ERROR, error: %{public}s", interceptorType.c_str(), error.c_str());
}

inline bool NetStackCurlEasySetOption(CURL *handle, CURLoption opt, void *data,
                                      OHOS::NetStack::Http::RequestContext *asyncContext)
{
    CURLcode result = curl_easy_setopt(handle, opt, data);
    if (result != CURLE_OK) {
        const char *err = curl_easy_strerror(result);
        NETSTACK_LOGE("Failed to set option: %{public}d, %{public}s %{public}d", static_cast<int>(opt), err,
                      static_cast<int>(result));
        asyncContext->SetErrorCode(result);
        return false;
    }
    return true;
}

namespace OHOS::NetStack::Http {

HttpInterceptor::~HttpInterceptor() { }

bool HttpInterceptor::IsInitialRequestInterceptor() const
{
    return static_cast<bool>(initialRequestInterceptorCallback_);
}

bool HttpInterceptor::IsRedirectionInterceptor() const
{
    return static_cast<bool>(redirectionInterceptorCallback_);
}

bool HttpInterceptor::IsFinalResponseInterceptor() const
{
    return static_cast<bool>(finalResponseInterceptorCallback_);
}

bool HttpInterceptor::IsCacheCheckedInterceptor() const
{
    return static_cast<bool>(cacheCheckedInterceptorCallback_);
}

bool HttpInterceptor::IsConnectNetworkInterceptor() const
{
    return static_cast<bool>(connectNetworkInterceptorCallback_);
}

void HttpInterceptor::SetInterceptorRefs(std::map<std::string, napi_ref> interceptorRefs)
{
    for (const auto &[key, ref] : interceptorRefs) {
        if (ref == nullptr) {
            continue;
        }
        if (key == HttpConstant::INTERCEPTOR_INITIAL_REQUEST) {
            SetInitialRequestInterceptor();
        } else if (key == HttpConstant::INTERCEPTOR_REDIRECTION) {
            SetRedirectionInterceptor();
        } else if (key == HttpConstant::INTERCEPTOR_FINAL_RESPONSE) {
            SetFinalResponseInterceptor();
        } else if (key == HttpConstant::INTERCEPTOR_READ_CACHE) {
            SetCacheCheckedInterceptor();
        } else if (key == HttpConstant::INTERCEPTOR_CONNECT_NETWORK) {
            SetConnectNetworkInterceptor();
        }
    }
}

const RequestInterceptor &HttpInterceptor::GetInitialRequestInterceptorCallback() const
{
    return initialRequestInterceptorCallback_;
}

const RedirectionInterceptor &HttpInterceptor::GetRedirectionInterceptorCallback() const
{
    return redirectionInterceptorCallback_;
}

const FinalResponseInterceptor &HttpInterceptor::GetFinalResponseInterceptorCallback() const
{
    return finalResponseInterceptorCallback_;
}

const RequestInterceptor &HttpInterceptor::GetCacheCheckedInterceptorCallback() const
{
    return cacheCheckedInterceptorCallback_;
}

const RequestInterceptor &HttpInterceptor::GetConnectNetworkInterceptorCallback() const
{
    return connectNetworkInterceptorCallback_;
}

// InitialRequestInterceptor
void HttpInterceptor::ApplyContinueInitialRequestInterceptor(napi_env env, InitialRequestInterceptorHandle *handle)
{
    INTERCEPTOR_TRACE_START("INITIAL_REQUEST_CONTINUE");
    auto newUrl = NapiUtils::GetStringFromValueUtf8(env, NapiUtils::GetNamedProperty(env, handle->reqContext, "url"));
    handle->context->options.SetUrl(newUrl);
    NETSTACK_LOGD("RequestContext::ApplyRequest: updated URL = %{public}s", newUrl.c_str());

    napi_value newHeadObj = NapiUtils::GetNamedProperty(env, handle->reqContext, "header");
    if (newHeadObj != nullptr) {
        for (const auto &key : NapiUtils::GetPropertyNames(env, newHeadObj)) {
            std::string value =
                NapiUtils::GetStringFromValueUtf8(env, NapiUtils::GetNamedProperty(env, newHeadObj, key.c_str()));
            handle->context->options.SetHeader(key, value);
            NETSTACK_LOGD("Updated header: %{public}s = %{public}s", key.c_str(), value.c_str());
        }
    }

    napi_value bodyValue = NapiUtils::GetNamedProperty(env, handle->reqContext, "body");
    if (bodyValue == nullptr) {
        handle->context->options.ReplaceBody("", 0);
        NETSTACK_LOGD("Body is null, using empty body");
    } else {
        napi_valuetype bodyType = NapiUtils::GetValueType(env, bodyValue);
        if (bodyType == napi_string) {
            std::string bodyStr = NapiUtils::GetStringFromValueUtf8(env, bodyValue);
            handle->context->options.ReplaceBody(bodyStr.data(), bodyStr.size());
            NETSTACK_LOGD("Updated string body, length=%{public}zu", bodyStr.size());
        } else if (NapiUtils::ValueIsArrayBuffer(env, bodyValue)) {
            size_t bufferLength = 0;
            void *bufferData = NapiUtils::GetInfoFromArrayBufferValue(env, bodyValue, &bufferLength);
            if (bufferData != nullptr && bufferLength > 0) {
                handle->context->options.ReplaceBody(bufferData, bufferLength);
                NETSTACK_LOGD("Updated array buffer body, length=%{public}zu", bufferLength);
            } else {
                INTERCEPTOR_TRACE_ERROR("INITIAL_REQUEST", "Invalid array buffer data or length");
            }
        } else {
            INTERCEPTOR_TRACE_ERROR("INITIAL_REQUEST", "Unsupported body type");
        }
    }

    INTERCEPTOR_TRACE_END("INITIAL_REQUEST", "CONTINUE");
    handle->after();
}

void HttpInterceptor::ApplyBlockInitialRequestInterceptor(napi_env env, InitialRequestInterceptorHandle *handle)
{
    INTERCEPTOR_TRACE_START("INITIAL_REQUEST_BLOCK");
    napi_value resContext = handle->resContext;

    if (NapiUtils::HasNamedProperty(env, resContext, "header")) {
        std::string headerRawStr =
            NapiUtils::GetStringFromValueUtf8(env, NapiUtils::GetNamedProperty(env, resContext, "header"));
        if (!headerRawStr.empty()) {
            bool hasSeparator = CommonUtils::EndsWith(headerRawStr, HttpConstant::HTTP_RESPONSE_HEADER_SEPARATOR);
            if (!hasSeparator) {
                headerRawStr += HttpConstant::HTTP_RESPONSE_HEADER_SEPARATOR;
            }
        }
        handle->context->response.SetRawHeader(headerRawStr);
        NETSTACK_LOGD("Set raw header, length=%{public}zu", headerRawStr.size());
    }

    if (NapiUtils::HasNamedProperty(env, resContext, "responseCode")) {
        uint32_t code =
            NapiUtils::GetUint32FromValue(env, NapiUtils::GetNamedProperty(env, resContext, "responseCode"));
        handle->context->response.SetResponseCode(code);
        NETSTACK_LOGD("Set response code: %{public}u", code);
    }

    if (NapiUtils::HasNamedProperty(env, resContext, "result")) {
        std::string result =
            NapiUtils::GetStringFromValueUtf8(env, NapiUtils::GetNamedProperty(env, resContext, "result"));
        handle->context->response.SetResult(result);
        NETSTACK_LOGD("Set response result, length=%{public}zu", result.size());
    }

    if (NapiUtils::HasNamedProperty(env, resContext, "cookies")) {
        std::string cookies =
            NapiUtils::GetStringFromValueUtf8(env, NapiUtils::GetNamedProperty(env, resContext, "cookies"));
        handle->context->response.SetCookies(cookies);
        NETSTACK_LOGD("Set cookies: %{public}s", cookies.c_str());
    }

    handle->context->response.ParseHeaders();
    NETSTACK_LOGD("Parsed response headers");
    INTERCEPTOR_TRACE_END("INITIAL_REQUEST", "BLOCK");
    handle->block();
}

napi_value HttpInterceptor::CreateRequestContextInitialRequestInterceptor(napi_env env, RequestContext *context)
{
    napi_value reqContext = NapiUtils::CreateObject(env);
    if (reqContext == nullptr) {
        INTERCEPTOR_TRACE_ERROR("INITIAL_REQUEST", "Failed to create reqContext object");
        return nullptr;
    }

    std::string url = context->options.GetUrl();
    NapiUtils::SetNamedProperty(env, reqContext, "url", NapiUtils::CreateStringUtf8(env, url));

    napi_value headerObj = NapiUtils::CreateObject(env);
    const auto &headers = context->options.GetHeader();
    NETSTACK_LOGD("RequestContext::SetInitialRequestInterceptor: headers count = %{public}zu", headers.size());
    for (const auto &[key, value] : headers) {
        napi_value val = NapiUtils::CreateStringUtf8(env, value);
        NapiUtils::SetNamedProperty(env, headerObj, key, val);
    }
    NapiUtils::SetNamedProperty(env, reqContext, "header", headerObj);

    std::string body = context->options.GetBody();
    NapiUtils::SetNamedProperty(env, reqContext, "body", NapiUtils::CreateStringUtf8(env, body));

    return reqContext;
}

napi_value HttpInterceptor::CreateResponseContextInitialRequestInterceptor(napi_env env, RequestContext *context)
{
    napi_value resContext = NapiUtils::CreateObject(env);
    if (resContext == nullptr) {
        INTERCEPTOR_TRACE_ERROR("INITIAL_REQUEST", "Failed to create resContext object");
        return nullptr;
    }
    return resContext;
}

void HttpInterceptor::HandlePromiseThenInitialRequestInterceptor(
    napi_env env, InitialRequestInterceptorHandle *handle, napi_value promise)
{
    napi_value thenFunc = NapiUtils::GetNamedProperty(env, promise, "then");
    if (thenFunc == nullptr) {
        INTERCEPTOR_TRACE_ERROR("INITIAL_REQUEST", "Promise.then is not a function");
        delete handle;
        return;
    }

    napi_value onResolve = NapiUtils::CreateFunction(
        env, "onResolve",
        [](napi_env env, napi_callback_info info) -> napi_value {
            NETSTACK_LOGD("RequestContext::onResolve: start");

            size_t argc = 1;
            napi_value args[1];
            napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
            bool result = NapiUtils::GetBooleanFromValue(env, args[0]);

            void *data;
            napi_get_cb_info(env, info, nullptr, nullptr, nullptr, &data);
            auto *handle = static_cast<InitialRequestInterceptorHandle *>(data);

            if (result) {
                ApplyContinueInitialRequestInterceptor(env, handle);
            } else {
                ApplyBlockInitialRequestInterceptor(env, handle);
            }

            delete handle;
            return nullptr;
        },
        handle);

    napi_value onReject = NapiUtils::CreateFunction(
        env, "onReject",
        [](napi_env env, napi_callback_info info) -> napi_value {
            INTERCEPTOR_TRACE_ERROR("INITIAL_REQUEST", "interceptor promise rejected");
            void *data;
            napi_get_cb_info(env, info, nullptr, nullptr, nullptr, &data);
            auto *handle = static_cast<InitialRequestInterceptorHandle *>(data);
            delete handle;
            return nullptr;
        },
        handle);

    napi_value argv1[] = { onResolve, onReject };
    constexpr size_t thenCallArgc = 2;
    NapiUtils::CallFunction(env, promise, thenFunc, thenCallArgc, argv1);
}

void HttpInterceptor::HandlePromiseInitialRequestInterceptor(napi_env env, InitialRequestInterceptorHandle *handle)
{
    auto context = handle->context;

    napi_value interceptorRef = NapiUtils::GetReference(env, context->interceptorRefs_["INITIAL_REQUEST"]);
    if (interceptorRef == nullptr) {
        INTERCEPTOR_TRACE_ERROR("INITIAL_REQUEST", "Interceptor reference is null");
        delete handle;
        return;
    }

    napi_value interceptorHandle;
    napi_status status = napi_get_named_property(env, interceptorRef, "interceptorHandle", &interceptorHandle);
    if (status != napi_ok) {
        INTERCEPTOR_TRACE_ERROR("INITIAL_REQUEST", "Invalid interceptorHandle");
        delete handle;
        return;
    }

    napi_value argv[] = { handle->reqContext, handle->resContext };
    napi_value promise = NapiUtils::CallFunction(env, interceptorRef, interceptorHandle, 2, argv);
    if (promise == nullptr) {
        INTERCEPTOR_TRACE_ERROR("INITIAL_REQUEST", "Interceptor did not return a valid promise");
        delete handle;
        return;
    }

    HandlePromiseThenInitialRequestInterceptor(env, handle, promise);
    NETSTACK_LOGD("RequestContext::SetInitialRequestInterceptor: finished setup");
}

void HttpInterceptor::SetInitialRequestInterceptor()
{
    initialRequestInterceptorCallback_ = [](RequestContext *context, std::function<bool()> after,
                                             std::function<void()> block) {
        napi_env env = context->GetEnv();
        INTERCEPTOR_TRACE_START("INITIAL_REQUEST");

        napi_value reqContext = CreateRequestContextInitialRequestInterceptor(env, context);
        if (reqContext == nullptr) {
            NETSTACK_LOGE("Failed to create reqContext object");
            return;
        }

        napi_value resContext = CreateResponseContextInitialRequestInterceptor(env, context);
        if (resContext == nullptr) {
            NETSTACK_LOGE("Failed to create resContext object");
            return;
        }

        auto *handle =
            new InitialRequestInterceptorHandle { std::move(after), context, std::move(block), reqContext, resContext };
        HandlePromiseInitialRequestInterceptor(env, handle);
    };
}

// RedirectionInterceptor
void HttpInterceptor::ApplyContinueRedirectionInterceptor(napi_env env, RedirectionInterceptorHandle *handle)
{
    INTERCEPTOR_TRACE_START("REDIRECTION_CONTINUE");
    auto handleInfo = handle->handleInfo;
    auto urlValue = NapiUtils::GetNamedProperty(env, handle->reqContext, "url");
    if (urlValue != nullptr) {
        auto newUrl = NapiUtils::GetStringFromValueUtf8(env, urlValue);
        *handleInfo->location = newUrl;
        NETSTACK_LOGD("NetStack_RedirectInterceptor: URL updated successfully. Old: %{public}s, New: %{public}s",
            handleInfo->location ? handleInfo->location->c_str() : "null", newUrl.c_str());
    }

    if (napi_value newHeadObj = NapiUtils::GetNamedProperty(env, handle->reqContext, "header")) {
        for (const auto &key : NapiUtils::GetPropertyNames(env, newHeadObj)) {
            std::string value =
                NapiUtils::GetStringFromValueUtf8(env, NapiUtils::GetNamedProperty(env, newHeadObj, key.c_str()));
            handle->context->options.SetHeader(key, value);
            NETSTACK_LOGD("Updated header: %{public}s = %{public}s", key.c_str(), value.c_str());
        }
    }

    napi_value bodyValue = NapiUtils::GetNamedProperty(env, handle->reqContext, "body");
    if (bodyValue != nullptr) {
        napi_valuetype bodyType = NapiUtils::GetValueType(env, bodyValue);
        if (bodyType == napi_string) {
            std::string bodyStr = NapiUtils::GetStringFromValueUtf8(env, bodyValue);
            handle->context->options.ReplaceBody(bodyStr.data(), bodyStr.size());
            NETSTACK_LOGD("updated string body, length=%{public}zu", bodyStr.size());
        } else if (NapiUtils::ValueIsArrayBuffer(env, bodyValue)) {
            size_t bufferLength = 0;
            void *bufferData = NapiUtils::GetInfoFromArrayBufferValue(env, bodyValue, &bufferLength);
            if (bufferData != nullptr && bufferLength > 0) {
                handle->context->options.ReplaceBody(bufferData, bufferLength);
                NETSTACK_LOGD("updated array buffer body, length=%{public}zu", bufferLength);
            } else {
                INTERCEPTOR_TRACE_ERROR("REDIRECTION", "invalid array buffer data or length");
            }
        } else {
            INTERCEPTOR_TRACE_ERROR("REDIRECTION", "unsupported body type");
        }
    } else {
        NETSTACK_LOGD("body is null, using empty body");
        handle->context->options.ReplaceBody("", 0);
    }
    INTERCEPTOR_TRACE_END("REDIRECTION", "CONTINUE");
    handle->handleRedirect();
}

void HttpInterceptor::ApplyBlockRedirectionInterceptor(napi_env env, RedirectionInterceptorHandle *handle)
{
    INTERCEPTOR_TRACE_START("REDIRECTION_BLOCK");
    if (NapiUtils::HasNamedProperty(env, handle->resContext, "header")) {
        napi_value headerValue = NapiUtils::GetNamedProperty(env, handle->resContext, "header");
        std::string headerRawStr = NapiUtils::GetStringFromValueUtf8(env, headerValue);
        handle->context->response.SetRawHeader(headerRawStr);
        NETSTACK_LOGD("Set raw header, length=%{public}zu", headerRawStr.size());
    }

    if (NapiUtils::HasNamedProperty(env, handle->resContext, "responseCode")) {
        napi_value codeValue = NapiUtils::GetNamedProperty(env, handle->resContext, "responseCode");
        uint32_t responseCode = NapiUtils::GetUint32FromValue(env, codeValue);
        handle->context->response.SetResponseCode(responseCode);
        handle->context->response.isApplyBlockRedirectionInterceptor_ = true;
        NETSTACK_LOGD("Set response code: %{public}u", responseCode);
    }

    if (NapiUtils::HasNamedProperty(env, handle->resContext, "result")) {
        napi_value resultValue = NapiUtils::GetNamedProperty(env, handle->resContext, "result");
        std::string resultStr = NapiUtils::GetStringFromValueUtf8(env, resultValue);
        handle->context->response.SetResult(resultStr);
        NETSTACK_LOGD("Set response result, length=%{public}zu", resultStr.size());
    }

    if (NapiUtils::HasNamedProperty(env, handle->resContext, "cookies")) {
        napi_value cookiesValue = NapiUtils::GetNamedProperty(env, handle->resContext, "cookies");
        std::string cookiesStr = NapiUtils::GetStringFromValueUtf8(env, cookiesValue);
        handle->context->response.SetCookies(cookiesStr);
        NETSTACK_LOGD("Set cookies: %{public}s", cookiesStr.c_str());
    }

    handle->context->response.ParseHeaders();
    NETSTACK_LOGD("Parsed response headers");
    INTERCEPTOR_TRACE_END("REDIRECTION", "BLOCK");
    handle->handleCompletion();
}

napi_value HttpInterceptor::CreateRequestContextRedirectionInterceptor(
    napi_env env, RequestContext *context, HttpOverCurl::RedirectionInterceptorInfo *handleInfo)
{
    napi_value reqContext = NapiUtils::CreateObject(env);

    napi_value urlValue = NapiUtils::CreateStringUtf8(env, *handleInfo->location);
    if (urlValue != nullptr) {
        NapiUtils::SetNamedProperty(env, reqContext, "url", urlValue);
    }

    napi_value headerObj = NapiUtils::CreateObject(env);
    const std::map<std::string, std::string> &headers = context->options.GetHeader();
    NETSTACK_LOGD("redirectionInterceptorRunner_ run headers.size %{public}d", headers.size());
    for (const auto &[key, value] : headers) {
        napi_value headerValue = NapiUtils::CreateStringUtf8(env, value);
        if (headerValue != nullptr) {
            NapiUtils::SetNamedProperty(env, headerObj, key, headerValue);
        }
    }
    NapiUtils::SetNamedProperty(env, reqContext, "header", headerObj);

    std::string body = context->options.GetBody();
    napi_value bodyValue = NapiUtils::CreateStringUtf8(env, body);
    if (bodyValue != nullptr) {
        NapiUtils::SetNamedProperty(env, reqContext, "body", bodyValue);
    }
    return reqContext;
}

napi_value HttpInterceptor::CreateResponseContextRedirectionInterceptor(
    napi_env env, RequestContext *context, HttpOverCurl::RedirectionInterceptorInfo *handleInfo)
{
    napi_value resContext = NapiUtils::CreateObject(env);
    const std::map<std::string, std::string> &responseHeaders = context->response.GetHeader();
    napi_value responseHeaderObj = NapiUtils::CreateObject(env);
    if (!responseHeaders.empty()) {
        for (const auto &[key, value] : responseHeaders) {
            napi_value val = NapiUtils::CreateStringUtf8(env, value);
            NapiUtils::SetNamedProperty(env, responseHeaderObj, key, val);
        }
    }
    NapiUtils::SetNamedProperty(env, resContext, "header", responseHeaderObj);

    std::string responseResult = context->response.GetResult();
    NapiUtils::SetNamedProperty(env, resContext, "result", NapiUtils::CreateStringUtf8(env, responseResult));

    HttpExec::GetCurlDataFromHandle(handleInfo->message->easy_handle, context, CURLMSG_DONE, CURLE_OK);
    uint32_t responseCode = context->response.GetResponseCode();
    NapiUtils::SetNamedProperty(env, resContext, "responseCode", NapiUtils::CreateUint32(env, responseCode));

    std::string responseCookies = context->response.GetCookies();
    NapiUtils::SetNamedProperty(env, resContext, "cookies", NapiUtils::CreateStringUtf8(env, responseCookies));

    return resContext;
}

void HttpInterceptor::HandlePromiseThenRedirectionInterceptor(
    napi_env env, RedirectionInterceptorHandle *handle, napi_value promise)
{
    napi_value thenFunc = NapiUtils::GetNamedProperty(env, promise, "then");
    if (thenFunc == nullptr) {
        INTERCEPTOR_TRACE_ERROR("REDIRECTION", "Promise.then is not a function");
        delete handle->handleInfo;
        delete handle;
        return;
    }

    napi_value onResolve = NapiUtils::CreateFunction(
        env, "onResolve",
        [](napi_env env, napi_callback_info info) -> napi_value {
            NETSTACK_LOGD("RequestContext::onResolve: start");

            size_t argc = 1;
            napi_value args[1];
            napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
            bool result = NapiUtils::GetBooleanFromValue(env, args[0]);

            void *data;
            napi_get_cb_info(env, info, nullptr, nullptr, nullptr, &data);
            auto *handle = static_cast<RedirectionInterceptorHandle *>(data);

            if (result) {
                ApplyContinueRedirectionInterceptor(env, handle);
            } else {
                ApplyBlockRedirectionInterceptor(env, handle);
            }
            delete handle->handleInfo;
            delete handle;
            return nullptr;
        },
        handle);

    napi_value onReject = NapiUtils::CreateFunction(
        env, "onReject",
        [](napi_env env, napi_callback_info info) -> napi_value {
            INTERCEPTOR_TRACE_ERROR("REDIRECTION", "interceptor promise rejected");
            void *data;
            napi_get_cb_info(env, info, nullptr, nullptr, nullptr, &data);
            auto *handle = static_cast<RedirectionInterceptorHandle *>(data);
            delete handle->handleInfo;
            delete handle;
            return nullptr;
        },
        handle);

    napi_value argv1[] = { onResolve, onReject };
    constexpr size_t thenCallArgc = 2;
    NapiUtils::CallFunction(env, promise, thenFunc, thenCallArgc, argv1);
}

void HttpInterceptor::HandlePromiseRedirectionInterceptor(napi_env env, RedirectionInterceptorHandle *handle)
{
    auto context = handle->context;

    napi_value interceptorRef = NapiUtils::GetReference(env, context->interceptorRefs_["REDIRECTION"]);
    if (interceptorRef == nullptr) {
        INTERCEPTOR_TRACE_ERROR("REDIRECTION", "Interceptor reference is null");
        delete handle->handleInfo;
        delete handle;
        return;
    }

    napi_value interceptorHandle;
    napi_status status = napi_get_named_property(env, interceptorRef, "interceptorHandle", &interceptorHandle);
    if (status != napi_ok) {
        INTERCEPTOR_TRACE_ERROR("REDIRECTION", "Invalid interceptorHandle");
        delete handle->handleInfo;
        delete handle;
        return;
    }
    napi_value argv[] = { handle->reqContext, handle->resContext };
    napi_value promise = NapiUtils::CallFunction(env, interceptorRef, interceptorHandle, 2, argv);
    if (promise == nullptr) {
        INTERCEPTOR_TRACE_ERROR("REDIRECTION", "Interceptor did not return a valid promise");
        delete handle->handleInfo;
        delete handle;
        return;
    }
    HandlePromiseThenRedirectionInterceptor(env, handle, promise);
    NETSTACK_LOGD("RequestContext::SetRedirectionInterceptor: finished setup");
}

void HttpInterceptor::SetRedirectionInterceptor()
{
    redirectionInterceptorCallback_ = [](RequestContext *context, std::function<void()> handleRedirect,
                                          std::function<void()> handleCompletion,
                                          HttpOverCurl::RedirectionInterceptorInfo *handleInfo) {
        napi_env env = context->GetEnv();
        INTERCEPTOR_TRACE_START("REDIRECTION");

        napi_value reqContext = CreateRequestContextRedirectionInterceptor(env, context, handleInfo);
        if (reqContext == nullptr) {
            INTERCEPTOR_TRACE_ERROR("REDIRECTION", "Failed to create reqContext object");
            delete handleInfo;
            return;
        }

        napi_value resContext = CreateResponseContextRedirectionInterceptor(env, context, handleInfo);
        if (resContext == nullptr) {
            INTERCEPTOR_TRACE_ERROR("REDIRECTION", "Failed to create resContext object");
            delete handleInfo;
            return;
        }
        auto *handle = new RedirectionInterceptorHandle { std::move(handleRedirect), std::move(handleCompletion),
            handleInfo, reqContext, resContext };
        handle->context = context;
        HandlePromiseRedirectionInterceptor(env, handle);
    };
}

// FinalResponseInterceptor
void HttpInterceptor::ApplyContinueFinalResponseInterceptor(napi_env env, FinalResponseInterceptorHandle *handle)
{
    INTERCEPTOR_TRACE_START("FINAL_RESPONSE_CONTINUE");
    auto newUrl = NapiUtils::GetStringFromValueUtf8(env, NapiUtils::GetNamedProperty(env, handle->reqContext, "url"));
    NETSTACK_LOGD("finalResponseInterceptor updated url:%{public}s", newUrl.c_str());
    handle->context->options.SetUrl(newUrl);

    napi_value newHeadObj = NapiUtils::GetNamedProperty(env, handle->reqContext, "header");
    if (newHeadObj != nullptr) {
        std::vector<std::string> headerKeys = NapiUtils::GetPropertyNames(env, newHeadObj);
        for (const auto &key : headerKeys) {
            std::string value =
                NapiUtils::GetStringFromValueUtf8(env, NapiUtils::GetNamedProperty(env, newHeadObj, key.c_str()));
            handle->context->options.SetHeader(key, value);
            NETSTACK_LOGD("Updated header: %{public}s = %{public}s", key.c_str(), value.c_str());
        }
    }

    napi_value bodyValue = NapiUtils::GetNamedProperty(env, handle->reqContext, "body");
    if (bodyValue != nullptr) {
        napi_valuetype bodyType = NapiUtils::GetValueType(env, bodyValue);
        if (bodyType == napi_string) {
            std::string bodyStr = NapiUtils::GetStringFromValueUtf8(env, bodyValue);
            handle->context->options.ReplaceBody(bodyStr.data(), bodyStr.size());
            NETSTACK_LOGD("updated string body, length=%{public}zu", bodyStr.size());
        } else if (NapiUtils::ValueIsArrayBuffer(env, bodyValue)) {
            size_t bufferLength = 0;
            void *bufferData = NapiUtils::GetInfoFromArrayBufferValue(env, bodyValue, &bufferLength);
            if (bufferData != nullptr && bufferLength > 0) {
                handle->context->options.ReplaceBody(bufferData, bufferLength);
                NETSTACK_LOGD("updated array buffer body, length=%{public}zu", bufferLength);
            } else {
                INTERCEPTOR_TRACE_ERROR("FINAL_RESPONSE", "invalid array buffer data or length");
            }
        } else {
            INTERCEPTOR_TRACE_ERROR("FINAL_RESPONSE", "unsupported body type");
        }
    } else {
        NETSTACK_LOGD("body is null, using empty body");
        handle->context->options.ReplaceBody("", 0);
    }
    INTERCEPTOR_TRACE_END("FINAL_RESPONSE", "CONTINUE");
}

void HttpInterceptor::ApplyBlockFinalResponseInterceptor(napi_env env, FinalResponseInterceptorHandle *handle)
{
    INTERCEPTOR_TRACE_START("FINAL_RESPONSE_BLOCK");
    if (NapiUtils::HasNamedProperty(env, handle->resContext, "header")) {
        napi_value headerValue = NapiUtils::GetNamedProperty(env, handle->resContext, "header");
        std::string headerRawStr = NapiUtils::GetStringFromValueUtf8(env, headerValue);
        handle->context->response.SetRawHeader(headerRawStr);
        NETSTACK_LOGD("Set raw header, length=%{public}zu", headerRawStr.size());
    }

    if (NapiUtils::HasNamedProperty(env, handle->resContext, "responseCode")) {
        napi_value codeValue = NapiUtils::GetNamedProperty(env, handle->resContext, "responseCode");
        uint32_t responseCode = NapiUtils::GetUint32FromValue(env, codeValue);
        handle->context->response.SetResponseCode(responseCode);
        NETSTACK_LOGD("Set response code: %{public}u", responseCode);
    }

    if (NapiUtils::HasNamedProperty(env, handle->resContext, "result")) {
        napi_value resultValue = NapiUtils::GetNamedProperty(env, handle->resContext, "result");
        std::string resultStr = NapiUtils::GetStringFromValueUtf8(env, resultValue);
        handle->context->response.SetResult(resultStr);
        NETSTACK_LOGD("Set response result, length=%{public}zu", resultStr.size());
    }

    if (NapiUtils::HasNamedProperty(env, handle->resContext, "cookies")) {
        napi_value cookiesValue = NapiUtils::GetNamedProperty(env, handle->resContext, "cookies");
        std::string cookiesStr = NapiUtils::GetStringFromValueUtf8(env, cookiesValue);
        handle->context->response.SetCookies(cookiesStr);
        NETSTACK_LOGD("Set cookies: %{public}s", cookiesStr.c_str());
    }

    handle->context->response.ParseHeaders();
    NETSTACK_LOGD("Parsed response headers done");
    INTERCEPTOR_TRACE_END("FINAL_RESPONSE", "BLOCK");
}

napi_value HttpInterceptor::CreateRequestContextFinalResponseInterceptor(napi_env env, RequestContext *context)
{
    napi_value reqContext = NapiUtils::CreateObject(env);
    std::string url = context->options.GetUrl();
    NapiUtils::SetNamedProperty(env, reqContext, "url", NapiUtils::CreateStringUtf8(env, url));
    napi_value headerObj = NapiUtils::CreateObject(env);
    const std::map<std::string, std::string> &headers = context->options.GetHeader();
    NETSTACK_LOGD("finalResponseInterceptorRunner_ run headers.size %{public}d", headers.size());
    if (!headers.empty()) {
        for (const auto &[key, value] : headers) {
            napi_value val = NapiUtils::CreateStringUtf8(env, value);
            NapiUtils::SetNamedProperty(env, headerObj, key.c_str(), val);
        }
    }
    NapiUtils::SetNamedProperty(env, reqContext, "header", headerObj);
    std::string body = context->options.GetBody();
    NapiUtils::SetNamedProperty(env, reqContext, "body", NapiUtils::CreateStringUtf8(env, body));
    return reqContext;
}

napi_value HttpInterceptor::CreateResponseContextFinalResponseInterceptor(napi_env env, RequestContext *context)
{
    napi_value resContext = HttpExec::RequestCallback(context);
    return resContext;
}

void HttpInterceptor::HandlePromiseThenFinalResponseInterceptor(
    napi_env env, FinalResponseInterceptorHandle *handle, napi_value promise)
{
    napi_value thenFunc = NapiUtils::GetNamedProperty(env, promise, "then");
    if (thenFunc == nullptr) {
        INTERCEPTOR_TRACE_ERROR("FINAL_RESPONSE", "Promise.then is not a function");
        delete handle;
        return;
    }

    napi_value onResolve = NapiUtils::CreateFunction(
        env, "onResolve",
        [](napi_env env, napi_callback_info info) -> napi_value {
            NETSTACK_LOGD("RequestContext::onResolve: start");

            size_t argc = 1;
            napi_value args[1];
            napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
            bool result = NapiUtils::GetBooleanFromValue(env, args[0]);

            void *data;
            napi_get_cb_info(env, info, nullptr, nullptr, nullptr, &data);
            auto *handle = static_cast<FinalResponseInterceptorHandle *>(data);

            if (result) {
                ApplyContinueFinalResponseInterceptor(env, handle);
            } else {
                ApplyBlockFinalResponseInterceptor(env, handle);
            }
            handle->after();
            delete handle;
            return nullptr;
        },
        handle);

    napi_value onReject = NapiUtils::CreateFunction(
        env, "onReject",
        [](napi_env env, napi_callback_info info) -> napi_value {
            INTERCEPTOR_TRACE_ERROR("FINAL_RESPONSE", "interceptor promise rejected");
            void *data;
            napi_get_cb_info(env, info, nullptr, nullptr, nullptr, &data);
            auto *handle = static_cast<FinalResponseInterceptorHandle *>(data);
            delete handle;
            return nullptr;
        },
        handle);

    napi_value argv1[] = { onResolve, onReject };
    constexpr size_t thenCallArgc = 2;
    NapiUtils::CallFunction(env, promise, thenFunc, thenCallArgc, argv1);
}

void HttpInterceptor::HandlePromiseFinalResponseInterceptor(napi_env env, FinalResponseInterceptorHandle *handle)
{
    auto context = handle->context;

    napi_value interceptorRef = NapiUtils::GetReference(env, context->interceptorRefs_["FINAL_RESPONSE"]);
    if (interceptorRef == nullptr) {
        INTERCEPTOR_TRACE_ERROR("FINAL_RESPONSE", "Interceptor reference is null");
        delete handle;
        return;
    }

    napi_value interceptorHandle;
    napi_status status = napi_get_named_property(env, interceptorRef, "interceptorHandle", &interceptorHandle);
    if (status != napi_ok) {
        INTERCEPTOR_TRACE_ERROR("FINAL_RESPONSE", "Invalid interceptorHandle");
        delete handle;
        return;
    }
    napi_value argv[] = { handle->reqContext, handle->resContext };
    napi_value promise = NapiUtils::CallFunction(env, interceptorRef, interceptorHandle, 2, argv);
    if (promise == nullptr) {
        INTERCEPTOR_TRACE_ERROR("FINAL_RESPONSE", "Interceptor did not return a valid promise");
        delete handle;
        return;
    }

    HandlePromiseThenFinalResponseInterceptor(env, handle, promise);
    NETSTACK_LOGD("RequestContext::SetFinalResponseInterceptor: finished setup");
}

void HttpInterceptor::SetFinalResponseInterceptor()
{
    finalResponseInterceptorCallback_ = [](RequestContext *context, std::function<void()> after) {
        napi_env env = context->GetEnv();
        INTERCEPTOR_TRACE_START("FINAL_RESPONSE");

        napi_value reqContext = CreateRequestContextFinalResponseInterceptor(env, context);
        if (reqContext == nullptr) {
            INTERCEPTOR_TRACE_ERROR("FINAL_RESPONSE", "Failed to create reqContext object");
            return;
        }

        napi_value resContext = CreateResponseContextFinalResponseInterceptor(env, context);
        if (resContext == nullptr) {
            INTERCEPTOR_TRACE_ERROR("FINAL_RESPONSE", "Failed to create resContext object");
            return;
        }

        auto *handle = new FinalResponseInterceptorHandle { std::move(after), context, reqContext, resContext };

        HandlePromiseFinalResponseInterceptor(env, handle);
    };
}

// CacheCheckedInterceptor
void HttpInterceptor::ApplyContinueCacheCheckedInterceptor(napi_env env, CacheCheckedInterceptorHandle *handle)
{
    INTERCEPTOR_TRACE_START("READ_CACHE_CONTINUE");
    auto newUrl = NapiUtils::GetStringFromValueUtf8(env, NapiUtils::GetNamedProperty(env, handle->reqContext, "url"));
    NETSTACK_LOGD("cacheCheckedInterceptor updated url:%{public}s", newUrl.c_str());
    handle->context->options.SetUrl(newUrl);

    napi_value newHeadObj = NapiUtils::GetNamedProperty(env, handle->reqContext, "header");
    if (newHeadObj != nullptr) {
        std::vector<std::string> headerKeys = NapiUtils::GetPropertyNames(env, newHeadObj);
        for (const auto &key : headerKeys) {
            std::string value =
                NapiUtils::GetStringFromValueUtf8(env, NapiUtils::GetNamedProperty(env, newHeadObj, key.c_str()));
            handle->context->options.SetHeader(key, value);
            NETSTACK_LOGD("Updated header: %{public}s = %{public}s", key.c_str(), value.c_str());
        }
    }

    napi_value bodyValue = NapiUtils::GetNamedProperty(env, handle->reqContext, "body");
    if (bodyValue != nullptr) {
        napi_valuetype bodyType = NapiUtils::GetValueType(env, bodyValue);
        if (bodyType == napi_string) {
            std::string bodyStr = NapiUtils::GetStringFromValueUtf8(env, bodyValue);
            handle->context->options.ReplaceBody(bodyStr.data(), bodyStr.size());
            NETSTACK_LOGD("updated string body, length=%{public}zu", bodyStr.size());
        } else if (NapiUtils::ValueIsArrayBuffer(env, bodyValue)) {
            size_t bufferLength = 0;
            void *bufferData = NapiUtils::GetInfoFromArrayBufferValue(env, bodyValue, &bufferLength);
            if (bufferData != nullptr && bufferLength > 0) {
                handle->context->options.ReplaceBody(bufferData, bufferLength);
                NETSTACK_LOGD("updated array buffer body, length=%{public}zu", bufferLength);
            } else {
                INTERCEPTOR_TRACE_ERROR("READ_CACHE", "invalid array buffer data or length");
            }
        } else {
            INTERCEPTOR_TRACE_ERROR("READ_CACHE", "unsupported body type");
        }
    } else {
        NETSTACK_LOGD("body is null, using empty body");
        handle->context->options.ReplaceBody("", 0);
    }
    INTERCEPTOR_TRACE_END("READ_CACHE", "CONTINUE");
    handle->after();
}

void HttpInterceptor::ApplyBlockCacheCheckedInterceptor(napi_env env, CacheCheckedInterceptorHandle *handle)
{
    INTERCEPTOR_TRACE_START("READ_CACHE_BLOCK");
    if (NapiUtils::HasNamedProperty(env, handle->resContext, "header")) {
        napi_value headerValue = NapiUtils::GetNamedProperty(env, handle->resContext, "header");
        std::string headerRawStr = NapiUtils::GetStringFromValueUtf8(env, headerValue);
        handle->context->response.SetRawHeader(headerRawStr);
        NETSTACK_LOGD("Set raw header, length=%{public}zu", headerRawStr.size());
    }

    if (NapiUtils::HasNamedProperty(env, handle->resContext, "responseCode")) {
        napi_value codeValue = NapiUtils::GetNamedProperty(env, handle->resContext, "responseCode");
        uint32_t responseCode = NapiUtils::GetUint32FromValue(env, codeValue);
        handle->context->response.SetResponseCode(responseCode);
        NETSTACK_LOGD("Set response code: %{public}u", responseCode);
    }

    if (NapiUtils::HasNamedProperty(env, handle->resContext, "result")) {
        napi_value resultValue = NapiUtils::GetNamedProperty(env, handle->resContext, "result");
        std::string resultStr = NapiUtils::GetStringFromValueUtf8(env, resultValue);
        handle->context->response.SetResult(resultStr);
        NETSTACK_LOGD("Set response result, length=%{public}zu", resultStr.size());
    }

    if (NapiUtils::HasNamedProperty(env, handle->resContext, "cookies")) {
        napi_value cookiesValue = NapiUtils::GetNamedProperty(env, handle->resContext, "cookies");
        std::string cookiesStr = NapiUtils::GetStringFromValueUtf8(env, cookiesValue);
        handle->context->response.SetCookies(cookiesStr);
        NETSTACK_LOGD("Set cookies: %{public}s", cookiesStr.c_str());
    }

    handle->context->response.ParseHeaders();
    NETSTACK_LOGD("Parsed response headers");
    INTERCEPTOR_TRACE_END("READ_CACHE", "BLOCK");
    handle->block();
}

napi_value HttpInterceptor::CreateRequestContextCacheCheckedInterceptor(napi_env env, RequestContext *context)
{
    napi_value reqContext = NapiUtils::CreateObject(context->GetEnv());
    std::string url = context->options.GetUrl();
    NapiUtils::SetNamedProperty(
        context->GetEnv(), reqContext, "url", NapiUtils::CreateStringUtf8(context->GetEnv(), url));

    napi_value headerObj = NapiUtils::CreateObject(context->GetEnv());
    const std::map<std::string, std::string> &headers = context->options.GetHeader();
    NETSTACK_LOGD("cacheCheckedInterceptorRunner_ run headers.size %{public}d", headers.size());
    if (!headers.empty()) {
        std::for_each(
            headers.begin(), headers.end(), [&context, &headerObj](const std::pair<std::string, std::string> &p) {
                napi_value value = NapiUtils::CreateStringUtf8(context->GetEnv(), p.second);
                NapiUtils::SetNamedProperty(context->GetEnv(), headerObj, p.first, value);
            });
    }
    NapiUtils::SetNamedProperty(context->GetEnv(), reqContext, "header", headerObj);
    std::string body = context->options.GetBody();
    NapiUtils::SetNamedProperty(
        context->GetEnv(), reqContext, "body", NapiUtils::CreateStringUtf8(context->GetEnv(), body));
    return reqContext;
}

napi_value HttpInterceptor::CreateResponseContextCacheCheckedInterceptor(napi_env env, RequestContext *context)
{
    napi_value resContext = HttpExec::RequestCallback(context);
    return resContext;
}

void HttpInterceptor::HandlePromiseThenCacheCheckedInterceptor(
    napi_env env, CacheCheckedInterceptorHandle *handle, napi_value promise)
{
    napi_value thenFunc = NapiUtils::GetNamedProperty(env, promise, "then");
    if (thenFunc == nullptr) {
        INTERCEPTOR_TRACE_ERROR("READ_CACHE", "Promise.then is not a function");
        delete handle;
        return;
    }

    napi_value onResolve = NapiUtils::CreateFunction(
        env, "onResolve",
        [](napi_env env, napi_callback_info info) -> napi_value {
            NETSTACK_LOGD("RequestContext::onResolve: start");

            size_t argc = 1;
            napi_value args[1];
            napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
            bool result = NapiUtils::GetBooleanFromValue(env, args[0]);

            void *data;
            napi_get_cb_info(env, info, nullptr, nullptr, nullptr, &data);
            auto *handle = static_cast<CacheCheckedInterceptorHandle *>(data);

            if (result) {
                ApplyContinueCacheCheckedInterceptor(env, handle);
            } else {
                ApplyBlockCacheCheckedInterceptor(env, handle);
            }
            delete handle;
            return nullptr;
        },
        handle);

    napi_value onReject = NapiUtils::CreateFunction(
        env, "onReject",
        [](napi_env env, napi_callback_info info) -> napi_value {
            INTERCEPTOR_TRACE_ERROR("READ_CACHE", "interceptor promise rejected");
            void *data;
            napi_get_cb_info(env, info, nullptr, nullptr, nullptr, &data);
            auto *handle = static_cast<CacheCheckedInterceptorHandle *>(data);
            delete handle;
            return nullptr;
        },
        handle);

    napi_value argv1[] = { onResolve, onReject };
    constexpr size_t thenCallArgc = 2;
    NapiUtils::CallFunction(env, promise, thenFunc, thenCallArgc, argv1);
}

void HttpInterceptor::HandlePromiseCacheCheckedInterceptor(napi_env env, CacheCheckedInterceptorHandle *handle)
{
    auto context = handle->context;

    napi_value interceptorRef = NapiUtils::GetReference(env, context->interceptorRefs_["READ_CACHE"]);
    if (interceptorRef == nullptr) {
        INTERCEPTOR_TRACE_ERROR("READ_CACHE", "Interceptor reference is null");
        delete handle;
        return;
    }

    napi_value interceptorHandle;
    napi_status status = napi_get_named_property(env, interceptorRef, "interceptorHandle", &interceptorHandle);
    if (status != napi_ok) {
        INTERCEPTOR_TRACE_ERROR("READ_CACHE", "Invalid interceptorHandle");
        delete handle;
        return;
    }
    napi_value argv[] = { handle->reqContext, handle->resContext };
    napi_value promise = NapiUtils::CallFunction(env, interceptorRef, interceptorHandle, 2, argv);
    if (promise == nullptr) {
        INTERCEPTOR_TRACE_ERROR("READ_CACHE", "Interceptor did not return a valid promise");
        delete handle;
        return;
    }
    HandlePromiseThenCacheCheckedInterceptor(env, handle, promise);
    NETSTACK_LOGD("RequestContext::SetInitialRequestInterceptor: finished setup");
}

void HttpInterceptor::SetCacheCheckedInterceptor()
{
    cacheCheckedInterceptorCallback_ = [](RequestContext *context, std::function<bool()> after,
                                           std::function<void()> block) {
        napi_env env = context->GetEnv();
        INTERCEPTOR_TRACE_START("READ_CACHE");

        napi_value reqContext = CreateRequestContextCacheCheckedInterceptor(env, context);
        if (reqContext == nullptr) {
            INTERCEPTOR_TRACE_ERROR("READ_CACHE", "Failed to create reqContext object");
            return;
        }

        napi_value resContext = CreateResponseContextCacheCheckedInterceptor(env, context);
        if (resContext == nullptr) {
            INTERCEPTOR_TRACE_ERROR("READ_CACHE", "Failed to create resContext object");
            return;
        }

        auto *handle =
            new CacheCheckedInterceptorHandle { std::move(after), context, std::move(block), reqContext, resContext };

        HandlePromiseCacheCheckedInterceptor(env, handle);
    };
}

void HttpInterceptor::SetCurlPostFields(CURL *easyHander, const void *data, size_t length)
{
    curl_easy_setopt(easyHander, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(easyHander, CURLOPT_POSTFIELDSIZE, length);
}

// ConnectNetworkInterceptor
void HttpInterceptor::ApplyContinueConnectNetworkInterceptor(napi_env env, InitialRequestInterceptorHandle *handle)
{
    INTERCEPTOR_TRACE_START("CONNECT_NETWORK_CONTINUE");
    CURL *easyHander = handle->context->GetCurlHandle();

    auto newUrl = NapiUtils::GetStringFromValueUtf8(env, NapiUtils::GetNamedProperty(env, handle->reqContext, "url"));
    NETSTACK_LOGD("connectNetworkInterceptor updated url:%{public}s", newUrl.c_str());
    curl_easy_setopt(easyHander, CURLOPT_URL, newUrl.c_str());
    handle->context->options.SetUrl(newUrl);

    napi_value newHeadObj = NapiUtils::GetNamedProperty(env, handle->reqContext, "header");
    if (newHeadObj != nullptr) {
        std::vector<std::string> headerKeys = NapiUtils::GetPropertyNames(env, newHeadObj);
        curl_slist *headers = nullptr;
        for (const auto &key : headerKeys) {
            std::string value =
                NapiUtils::GetStringFromValueUtf8(env, NapiUtils::GetNamedProperty(env, newHeadObj, key.c_str()));
            std::string headerLine = key + ": " + value;
            headers = curl_slist_append(headers, headerLine.c_str());
            handle->context->options.SetHeader(key, value);
            NETSTACK_LOGD("Updated header: %{public}s = %{public}s", key.c_str(), value.c_str());
        }
        curl_easy_setopt(easyHander, CURLOPT_HTTPHEADER, headers);
    }

    napi_value bodyValue = NapiUtils::GetNamedProperty(env, handle->reqContext, "body");
    if (bodyValue != nullptr) {
        napi_valuetype bodyType = NapiUtils::GetValueType(env, bodyValue);
        if (bodyType == napi_string) {
            std::string bodyStr = NapiUtils::GetStringFromValueUtf8(env, bodyValue);
            SetCurlPostFields(easyHander, bodyStr.c_str(), bodyStr.size());
            handle->context->options.ReplaceBody(bodyStr.data(), bodyStr.size());
            NETSTACK_LOGD("updated string body, length=%{public}zu", bodyStr.size());
        } else if (NapiUtils::ValueIsArrayBuffer(env, bodyValue)) {
            size_t bufferLength = 0;
            void *bufferData = NapiUtils::GetInfoFromArrayBufferValue(env, bodyValue, &bufferLength);
            if (bufferData != nullptr && bufferLength > 0) {
                SetCurlPostFields(easyHander, bufferData, bufferLength);
                handle->context->options.ReplaceBody(bufferData, bufferLength);
                NETSTACK_LOGD("updated array buffer body, length=%{public}zu", bufferLength);
            } else {
                INTERCEPTOR_TRACE_ERROR("CONNECT_NETWORK", "invalid array buffer data or length");
            }
        } else {
            INTERCEPTOR_TRACE_ERROR("CONNECT_NETWORK", "unsupported body type");
        }
    } else {
        NETSTACK_LOGD("body is null, using empty body");
        SetCurlPostFields(easyHander, "", 0);
        handle->context->options.ReplaceBody("", 0);
    }
    INTERCEPTOR_TRACE_END("CONNECT_NETWORK", "CONTINUE");
    handle->after();
}

void HttpInterceptor::ApplyBlockConnectNetworkInterceptor(napi_env env, InitialRequestInterceptorHandle *handle)
{
    INTERCEPTOR_TRACE_START("CONNECT_NETWORK_BLOCK");
    if (NapiUtils::HasNamedProperty(env, handle->resContext, "header")) {
        napi_value headerValue = NapiUtils::GetNamedProperty(env, handle->resContext, "header");
        std::string headerRawStr = NapiUtils::GetStringFromValueUtf8(env, headerValue);
        handle->context->response.SetRawHeader(headerRawStr);
        NETSTACK_LOGD("Set raw header, length=%{public}zu", headerRawStr.size());
    }

    if (NapiUtils::HasNamedProperty(env, handle->resContext, "responseCode")) {
        napi_value codeValue = NapiUtils::GetNamedProperty(env, handle->resContext, "responseCode");
        uint32_t responseCode = NapiUtils::GetUint32FromValue(env, codeValue);
        handle->context->response.SetResponseCode(responseCode);
        NETSTACK_LOGD("Set response code: %{public}u", responseCode);
    }

    if (NapiUtils::HasNamedProperty(env, handle->resContext, "result")) {
        napi_value resultValue = NapiUtils::GetNamedProperty(env, handle->resContext, "result");
        std::string resultStr = NapiUtils::GetStringFromValueUtf8(env, resultValue);
        handle->context->response.SetResult(resultStr);
        NETSTACK_LOGD("Set response result, length=%{public}zu", resultStr.size());
    }

    if (NapiUtils::HasNamedProperty(env, handle->resContext, "cookies")) {
        napi_value cookiesValue = NapiUtils::GetNamedProperty(env, handle->resContext, "cookies");
        std::string cookiesStr = NapiUtils::GetStringFromValueUtf8(env, cookiesValue);
        handle->context->response.SetCookies(cookiesStr);
        NETSTACK_LOGD("Set cookies: %{public}s", cookiesStr.c_str());
    }

    handle->context->response.ParseHeaders();
    NETSTACK_LOGD("Parsed response headers");

    INTERCEPTOR_TRACE_END("CONNECT_NETWORK", "BLOCK");
    handle->block();
}

napi_value HttpInterceptor::CreateRequestContextConnectNetworkInterceptor(napi_env env, RequestContext *context)
{
    napi_value reqContext = NapiUtils::CreateObject(context->GetEnv());
    std::string url = context->options.GetUrl();
    NapiUtils::SetNamedProperty(
        context->GetEnv(), reqContext, "url", NapiUtils::CreateStringUtf8(context->GetEnv(), url));

    napi_value headerObj = NapiUtils::CreateObject(context->GetEnv());
    const std::map<std::string, std::string> &headers = context->options.GetHeader();
    NETSTACK_LOGD("connectNetworkInterceptorRunner_ run headers.size %{public}d", headers.size());
    if (!headers.empty()) {
        std::for_each(
            headers.begin(), headers.end(), [&context, &headerObj](const std::pair<std::string, std::string> &p) {
                napi_value value = NapiUtils::CreateStringUtf8(context->GetEnv(), p.second);
                NapiUtils::SetNamedProperty(context->GetEnv(), headerObj, p.first, value);
            });
    }
    NapiUtils::SetNamedProperty(context->GetEnv(), reqContext, "header", headerObj);
    std::string body = context->options.GetBody();
    NapiUtils::SetNamedProperty(
        context->GetEnv(), reqContext, "body", NapiUtils::CreateStringUtf8(context->GetEnv(), body));
    return reqContext;
}

napi_value HttpInterceptor::CreateResponseContextConnectNetworkInterceptor(napi_env env, RequestContext *context)
{
    napi_value resContext = HttpExec::RequestCallback(context);
    return resContext;
}

void HttpInterceptor::HandlePromiseThenConnectNetworkInterceptor(
    napi_env env, InitialRequestInterceptorHandle *handle, napi_value promise)
{
    napi_value thenFunc = NapiUtils::GetNamedProperty(env, promise, "then");
    if (thenFunc == nullptr) {
        INTERCEPTOR_TRACE_ERROR("CONNECT_NETWORK", "Promise.then is not a function");
        delete handle;
        return;
    }

    napi_value onResolve = NapiUtils::CreateFunction(
        env, "onResolve",
        [](napi_env env, napi_callback_info info) -> napi_value {
            NETSTACK_LOGD("RequestContext::onResolve: start");

            size_t argc = 1;
            napi_value args[1];
            napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
            bool result = NapiUtils::GetBooleanFromValue(env, args[0]);

            void *data;
            napi_get_cb_info(env, info, nullptr, nullptr, nullptr, &data);
            auto *handle = static_cast<InitialRequestInterceptorHandle *>(data);

            if (result) {
                ApplyContinueConnectNetworkInterceptor(env, handle);
            } else {
                ApplyBlockConnectNetworkInterceptor(env, handle);
            }
            delete handle;
            return nullptr;
        },
        handle);

    napi_value onReject = NapiUtils::CreateFunction(
        env, "onReject",
        [](napi_env env, napi_callback_info info) -> napi_value {
            INTERCEPTOR_TRACE_ERROR("CONNECT_NETWORK", "interceptor promise rejected");
            void *data;
            napi_get_cb_info(env, info, nullptr, nullptr, nullptr, &data);
            auto *handle = static_cast<InitialRequestInterceptorHandle *>(data);
            delete handle;
            return nullptr;
        },
        handle);

    napi_value argv1[] = { onResolve, onReject };
    constexpr size_t thenCallArgc = 2;
    NapiUtils::CallFunction(env, promise, thenFunc, thenCallArgc, argv1);
}

void HttpInterceptor::HandlePromiseConnectNetworkInterceptor(napi_env env, InitialRequestInterceptorHandle *handle)
{
    auto context = handle->context;

    napi_value interceptorRef = NapiUtils::GetReference(env, context->interceptorRefs_["CONNECT_NETWORK"]);
    if (interceptorRef == nullptr) {
        INTERCEPTOR_TRACE_ERROR("CONNECT_NETWORK", "Interceptor reference is null");
        delete handle;
        return;
    }

    napi_value interceptorHandle;
    napi_status status = napi_get_named_property(env, interceptorRef, "interceptorHandle", &interceptorHandle);
    if (status != napi_ok) {
        INTERCEPTOR_TRACE_ERROR("CONNECT_NETWORK", "Invalid interceptorHandle");
        delete handle;
        return;
    }
    napi_value argv[] = { handle->reqContext, handle->resContext };
    napi_value promise = NapiUtils::CallFunction(env, interceptorRef, interceptorHandle, 2, argv);
    if (promise == nullptr) {
        INTERCEPTOR_TRACE_ERROR("CONNECT_NETWORK", "Interceptor did not return a valid promise");
        delete handle;
        return;
    }
    HandlePromiseThenConnectNetworkInterceptor(env, handle, promise);
    NETSTACK_LOGD("RequestContext::SetConnectNetworkInterceptor: finished setup");
}

void HttpInterceptor::SetConnectNetworkInterceptor()
{
    connectNetworkInterceptorCallback_ = [](RequestContext *context, std::function<bool()> after,
                                             std::function<void()> block) {
        napi_env env = context->GetEnv();
        INTERCEPTOR_TRACE_START("CONNECT_NETWORK");

        napi_value reqContext = CreateRequestContextConnectNetworkInterceptor(env, context);
        if (reqContext == nullptr) {
            INTERCEPTOR_TRACE_ERROR("CONNECT_NETWORK", "Failed to create reqContext object");
            return;
        }

        napi_value resContext = CreateResponseContextConnectNetworkInterceptor(env, context);
        if (resContext == nullptr) {
            INTERCEPTOR_TRACE_ERROR("CONNECT_NETWORK", "Failed to create resContext object");
            return;
        }

        auto *handle =
            new InitialRequestInterceptorHandle { std::move(after), context, std::move(block), reqContext, resContext };

        HandlePromiseConnectNetworkInterceptor(env, handle);
    };
}

#if HAS_NETMANAGER_BASE
bool HttpInterceptor::ExecuteConnectNetworkInterceptor(Http::RequestContext *context, CURL *handle,
                                                       HttpOverCurl::TransferCallbacks callbacks)
{
    std::function<bool()> continueCallback = std::bind(
        [](CURL *handle, HttpOverCurl::TransferCallbacks callbacks, Http::RequestContext *context) -> bool {
            static HttpOverCurl::EpollRequestHandler requestHandler;
            requestHandler.Process(handle, callbacks, context);
            return true;
        },
        handle, callbacks, context);
#if ENABLE_HTTP_INTERCEPT
    std::function<void()> blockCallback = std::bind(
        [](Http::RequestContext *context) {
            Http::HttpExec::ProcessResponseHeadersAndEmitEvents(context);
            Http::HttpExec::ProcessResponseBodyAndEmitEvents(context);
            Http::HttpExec::EnqueueCallback(context);
        },
        context);
    auto interceptor = context->GetInterceptor();
    if (interceptor != nullptr && interceptor->IsConnectNetworkInterceptor()) {
        auto interceptorCallback = interceptor->GetConnectNetworkInterceptorCallback();
        auto interceptorWork = std::bind(interceptorCallback, context, continueCallback, blockCallback);
        NapiUtils::CreateUvQueueWorkByModuleId(context->GetEnv(), interceptorWork, context->GetModuleId());
        NETSTACK_LOGD("HttpExec: connectNetworkInterceptorCallback_ executed successfully");
        return true;
    }
#endif
    return continueCallback();
}
#endif

bool HttpInterceptor::FinalResponseInterceptorCallback(RequestContext *context,
                                                       std::function<void()> handleFinalResponseProcessing)
{
    auto interceptor = context->GetInterceptor();
    if (interceptor != nullptr && interceptor->IsFinalResponseInterceptor()) {
        auto interceptorCallback = interceptor->GetFinalResponseInterceptorCallback();
        interceptorCallback(context, handleFinalResponseProcessing);
        NETSTACK_LOGD("Final response interceptor callback invoked successfully.");
        return true;
    }
    return false;
}

bool HttpInterceptor::CacheCheckedInterceptorCallback(RequestContext *context,
                                                      std::function<bool()> handleCacheCheckedPostProcessing,
                                                      std::function<void()> blockCacheCheckedPostProcessing)
{
    auto interceptor = context->GetInterceptor();
    if (interceptor != nullptr && interceptor->IsCacheCheckedInterceptor()) {
        auto interceptorCallback = interceptor->GetCacheCheckedInterceptorCallback();
        interceptorCallback(context, handleCacheCheckedPostProcessing, blockCacheCheckedPostProcessing);
        NETSTACK_LOGD("HttpInterceptor: Cache checked interceptor callback executed successfully.");
        return true;
    }
    return false;
}

bool HttpInterceptor::InitialRequestInterceptorCallback(RequestContext *context, std::function<bool()> continueCallback,
                                                        std::function<void()> blockCallback)
{
    auto interceptor = context->GetInterceptor();
    if (interceptor != nullptr && interceptor->IsInitialRequestInterceptor()) {
        auto interceptorCallback = interceptor->GetInitialRequestInterceptorCallback();
        interceptorCallback(context, continueCallback, blockCallback);
        NETSTACK_LOGD("HttpInterceptor: Initial request interceptor callback invoked successfully");
        return true;
    }
    return false;
}

bool HttpInterceptor::RedirectionInterceptorBodyCallback(RequestContext *context, const void *data, size_t size,
                                                         size_t memBytes)
{
    auto interceptor = context->GetInterceptor();
    if (interceptor != nullptr && interceptor->IsRedirectionInterceptor()) {
        int statusCode = context->response.GetResponseCode();
        if (statusCode >= HTTP_STATUS_REDIRECT_START && statusCode < HTTP_STATUS_CLIENT_ERROR_START) {
            context->response.SetResult(const_cast<char *>(static_cast<const char *>(data)));
            return true;
        }
    }
    return false;
}

bool HttpInterceptor::SetFollowLocation(CURL *handle, RequestContext *context)
{
    auto interceptor = context->GetInterceptor();
    if (interceptor != nullptr && interceptor->IsRedirectionInterceptor()) {
        return NetStackCurlEasySetOption(handle, CURLOPT_FOLLOWLOCATION, 0L, context);
    }
    return true;
}

} // namespace OHOS::NetStack::Http
