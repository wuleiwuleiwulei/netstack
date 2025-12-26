/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "http_module.h"

#include "cache_proxy.h"
#include "constant.h"
#include "event_list.h"
#include "http_async_work.h"
#include "http_exec.h"

#include "module_template.h"
#include "netstack_log.h"
#include "netstack_common_utils.h"
#include "trace_events.h"
#include "hi_app_event_report.h"

#define DECLARE_RESPONSE_CODE(code) \
    DECLARE_NAPI_STATIC_PROPERTY(#code, NapiUtils::CreateUint32(env, static_cast<uint32_t>(ResponseCode::code)))

#define DECLARE_REQUEST_METHOD(method) \
    DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::method, NapiUtils::CreateStringUtf8(env, HttpConstant::method))

#define DECLARE_HTTP_PROTOCOL(protocol) \
    DECLARE_NAPI_STATIC_PROPERTY(#protocol, NapiUtils::CreateUint32(env, static_cast<uint32_t>(HttpProtocol::protocol)))

namespace OHOS::NetStack::Http {
static constexpr const char *FLUSH_ASYNC_WORK_NAME = "ExecFlush";

static constexpr const char *DELETE_ASYNC_WORK_NAME = "ExecDelete";

static constexpr const char *HTTP_MODULE_NAME = "net.http";

static thread_local uint64_t g_moduleId;

static bool g_appIsAtomicService = false;

static std::string g_appBundleName;

static std::once_flag g_isAtomicServiceFlag;

napi_value HttpModuleExports::InitHttpModule(napi_env env, napi_value exports)
{
    DefineHttpRequestClass(env, exports);
    DefineHttpResponseCacheClass(env, exports);
    DefineHttpInterceptorChainClass(env, exports);
    InitHttpProperties(env, exports);
    g_moduleId = NapiUtils::CreateUvHandlerQueue(env);
    NapiUtils::SetEnvValid(env);
    std::call_once(g_isAtomicServiceFlag, []() {
        g_appIsAtomicService = CommonUtils::IsAtomicService(g_appBundleName);
        NETSTACK_LOGI("IsAtomicService bundleName is %{public}s, isAtomicService is %{public}d",
                      g_appBundleName.c_str(), g_appIsAtomicService);
    });
    auto envWrapper = new (std::nothrow)napi_env;
    if (envWrapper == nullptr) {
        return exports;
    }
    *envWrapper = env;
    napi_add_env_cleanup_hook(env, NapiUtils::HookForEnvCleanup, envWrapper);
    return exports;
}

napi_value HttpModuleExports::CreateHttp(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::NewInstanceWithManagerWrapper(
        env, info, INTERFACE_HTTP_REQUEST, [](napi_env, void *data, void *) {
            NETSTACK_LOGD("http request handle is finalized");
            auto wrapper = reinterpret_cast<EventManagerWrapper *>(data);
            delete wrapper;
        });
}

napi_value HttpModuleExports::CreateHttpResponseCache(napi_env env, napi_callback_info info)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));
    if (paramsCount != 1 || NapiUtils::GetValueType(env, params[0]) != napi_number) {
        CacheProxy::RunCache();
    } else {
        size_t size = NapiUtils::GetUint32FromValue(env, params[0]);
        CacheProxy::RunCacheWithSize(size);
    }

    return ModuleTemplate::NewInstanceNoManager(env, info, INTERFACE_HTTP_RESPONSE_CACHE, [](napi_env, void *, void *) {
        NETSTACK_LOGI("http response cache handle is finalized");
    });
}

void HttpModuleExports::DefineHttpRequestClass(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(HttpRequest::FUNCTION_REQUEST, HttpRequest::Request),
        DECLARE_NAPI_FUNCTION(HttpRequest::FUNCTION_REQUEST_IN_STREAM, HttpRequest::RequestInStream),
        DECLARE_NAPI_FUNCTION(HttpRequest::FUNCTION_DESTROY, HttpRequest::Destroy),
        DECLARE_NAPI_FUNCTION(HttpRequest::FUNCTION_ON, HttpRequest::On),
        DECLARE_NAPI_FUNCTION(HttpRequest::FUNCTION_ONCE, HttpRequest::Once),
        DECLARE_NAPI_FUNCTION(HttpRequest::FUNCTION_OFF, HttpRequest::Off),
    };
    ModuleTemplate::DefineClass(env, exports, properties, INTERFACE_HTTP_REQUEST);
}

void HttpModuleExports::DefineHttpResponseCacheClass(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(HttpResponseCache::FUNCTION_FLUSH, HttpResponseCache::Flush),
        DECLARE_NAPI_FUNCTION(HttpResponseCache::FUNCTION_DELETE, HttpResponseCache::Delete),
    };
    ModuleTemplate::DefineClass(env, exports, properties, INTERFACE_HTTP_RESPONSE_CACHE);
}

void HttpModuleExports::DefineHttpInterceptorChainClass(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(HttpInterceptorChain::FUNCTION_GETCHAIN, HttpInterceptorChain::GetChain),
        DECLARE_NAPI_FUNCTION(HttpInterceptorChain::FUNCTION_ADDCHAIN, HttpInterceptorChain::AddChain),
        DECLARE_NAPI_FUNCTION(HttpInterceptorChain::FUNCTION_APPLY, HttpInterceptorChain::Apply),
    };
    ModuleTemplate::DefineClassNew(
        env, exports, properties, INTERFACE_HTTP_INTERCEPTOR_CHAIN,
        [](napi_env env, napi_callback_info info) -> napi_value {
            HttpInterceptorChain *chain = new HttpInterceptorChain(env);
            napi_value thisVal;
            napi_get_cb_info(env, info, nullptr, nullptr, &thisVal, nullptr);
            napi_wrap(
                env, thisVal, reinterpret_cast<void *>(chain),
                [](napi_env env, void *data, void *hint) { delete static_cast<HttpInterceptorChain *>(data); }, nullptr,
                nullptr);
            return thisVal;
        });
    std::initializer_list<napi_property_descriptor> typeProperties = {
        DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::INTERCEPTOR_INITIAL_REQUEST,
            NapiUtils::CreateStringUtf8(env, HttpConstant::INTERCEPTOR_INITIAL_REQUEST)),
        DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::INTERCEPTOR_REDIRECTION,
            NapiUtils::CreateStringUtf8(env, HttpConstant::INTERCEPTOR_REDIRECTION)),
        DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::INTERCEPTOR_CACHE_CHECKED,
            NapiUtils::CreateStringUtf8(env, HttpConstant::INTERCEPTOR_READ_CACHE)),
        DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::INTERCEPTOR_NETWORK_CONNECT,
            NapiUtils::CreateStringUtf8(env, HttpConstant::INTERCEPTOR_CONNECT_NETWORK)),
        DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::INTERCEPTOR_FINAL_RESPONSE,
            NapiUtils::CreateStringUtf8(env, HttpConstant::INTERCEPTOR_FINAL_RESPONSE)),
    };
    napi_value interceptorType = NapiUtils::CreateObject(env);
    NapiUtils::DefineProperties(env, interceptorType, typeProperties);
    NapiUtils::SetNamedProperty(env, exports, HttpConstant::INTERCEPTOR_TYPE, interceptorType);
}

void HttpModuleExports::InitHttpProperties(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(FUNCTION_CREATE_HTTP, CreateHttp),
        DECLARE_NAPI_FUNCTION(FUNCTION_CREATE_HTTP_RESPONSE_CACHE, CreateHttpResponseCache),
    };
    NapiUtils::DefineProperties(env, exports, properties);

    InitRequestMethod(env, exports);
    InitResponseCode(env, exports);
    InitCertType(env, exports);
    InitHttpProtocol(env, exports);
    InitHttpDataType(env, exports);
    InitTlsVersion(env, exports);
    InitAddressFamily(env, exports);
    InitSslType(env, exports);
    InitClientEncCert(env, exports);
}

void HttpModuleExports::InitRequestMethod(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_REQUEST_METHOD(HTTP_METHOD_OPTIONS), DECLARE_REQUEST_METHOD(HTTP_METHOD_GET),
        DECLARE_REQUEST_METHOD(HTTP_METHOD_HEAD),    DECLARE_REQUEST_METHOD(HTTP_METHOD_POST),
        DECLARE_REQUEST_METHOD(HTTP_METHOD_PUT),     DECLARE_REQUEST_METHOD(HTTP_METHOD_DELETE),
        DECLARE_REQUEST_METHOD(HTTP_METHOD_TRACE),   DECLARE_REQUEST_METHOD(HTTP_METHOD_CONNECT),
    };

    napi_value requestMethod = NapiUtils::CreateObject(env);
    NapiUtils::DefineProperties(env, requestMethod, properties);

    NapiUtils::SetNamedProperty(env, exports, INTERFACE_REQUEST_METHOD, requestMethod);
}

void HttpModuleExports::InitResponseCode(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_RESPONSE_CODE(OK),
        DECLARE_RESPONSE_CODE(CREATED),
        DECLARE_RESPONSE_CODE(ACCEPTED),
        DECLARE_RESPONSE_CODE(NOT_AUTHORITATIVE),
        DECLARE_RESPONSE_CODE(NO_CONTENT),
        DECLARE_RESPONSE_CODE(RESET),
        DECLARE_RESPONSE_CODE(PARTIAL),
        DECLARE_RESPONSE_CODE(MULT_CHOICE),
        DECLARE_RESPONSE_CODE(MOVED_PERM),
        DECLARE_RESPONSE_CODE(MOVED_TEMP),
        DECLARE_RESPONSE_CODE(SEE_OTHER),
        DECLARE_RESPONSE_CODE(NOT_MODIFIED),
        DECLARE_RESPONSE_CODE(USE_PROXY),
        DECLARE_RESPONSE_CODE(BAD_REQUEST),
        DECLARE_RESPONSE_CODE(UNAUTHORIZED),
        DECLARE_RESPONSE_CODE(PAYMENT_REQUIRED),
        DECLARE_RESPONSE_CODE(FORBIDDEN),
        DECLARE_RESPONSE_CODE(NOT_FOUND),
        DECLARE_RESPONSE_CODE(BAD_METHOD),
        DECLARE_RESPONSE_CODE(NOT_ACCEPTABLE),
        DECLARE_RESPONSE_CODE(PROXY_AUTH),
        DECLARE_RESPONSE_CODE(CLIENT_TIMEOUT),
        DECLARE_RESPONSE_CODE(CONFLICT),
        DECLARE_RESPONSE_CODE(GONE),
        DECLARE_RESPONSE_CODE(LENGTH_REQUIRED),
        DECLARE_RESPONSE_CODE(PRECON_FAILED),
        DECLARE_RESPONSE_CODE(ENTITY_TOO_LARGE),
        DECLARE_RESPONSE_CODE(REQ_TOO_LONG),
        DECLARE_RESPONSE_CODE(UNSUPPORTED_TYPE),
        DECLARE_RESPONSE_CODE(RANGE_NOT_SATISFIABLE),
        DECLARE_RESPONSE_CODE(INTERNAL_ERROR),
        DECLARE_RESPONSE_CODE(NOT_IMPLEMENTED),
        DECLARE_RESPONSE_CODE(BAD_GATEWAY),
        DECLARE_RESPONSE_CODE(UNAVAILABLE),
        DECLARE_RESPONSE_CODE(GATEWAY_TIMEOUT),
        DECLARE_RESPONSE_CODE(VERSION),
    };

    napi_value responseCode = NapiUtils::CreateObject(env);
    NapiUtils::DefineProperties(env, responseCode, properties);

    NapiUtils::SetNamedProperty(env, exports, INTERFACE_RESPONSE_CODE, responseCode);
}

void HttpModuleExports::InitTlsVersion(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::TLS_VERSION_1_0,
            NapiUtils::CreateUint32(env, static_cast<uint32_t>(TlsVersion::TLSv1_0))),
        DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::TLS_VERSION_1_1,
            NapiUtils::CreateUint32(env, static_cast<uint32_t>(TlsVersion::TLSv1_1))),
        DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::TLS_VERSION_1_2,
            NapiUtils::CreateUint32(env, static_cast<uint32_t>(TlsVersion::TLSv1_2))),
        DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::TLS_VERSION_1_3,
            NapiUtils::CreateUint32(env, static_cast<uint32_t>(TlsVersion::TLSv1_3))),
    };

    napi_value tlsVersion = NapiUtils::CreateObject(env);
    NapiUtils::DefineProperties(env, tlsVersion, properties);

    NapiUtils::SetNamedProperty(env, exports, INTERFACE_TLS_VERSION, tlsVersion);
}

void HttpModuleExports::InitHttpProtocol(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_HTTP_PROTOCOL(HTTP1_1),
        DECLARE_HTTP_PROTOCOL(HTTP2),
        DECLARE_HTTP_PROTOCOL(HTTP3),
    };

    napi_value httpProtocol = NapiUtils::CreateObject(env);
    NapiUtils::DefineProperties(env, httpProtocol, properties);

    NapiUtils::SetNamedProperty(env, exports, INTERFACE_HTTP_PROTOCOL, httpProtocol);
}

void HttpModuleExports::InitCertType(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::HTTP_CERT_TYPE_PEM,
                                     NapiUtils::CreateStringUtf8(env, HttpConstant::HTTP_CERT_TYPE_PEM)),
        DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::HTTP_CERT_TYPE_DER,
                                     NapiUtils::CreateStringUtf8(env, HttpConstant::HTTP_CERT_TYPE_DER)),
        DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::HTTP_CERT_TYPE_P12,
                                     NapiUtils::CreateStringUtf8(env, HttpConstant::HTTP_CERT_TYPE_P12)),
    };
    napi_value httpCertType = NapiUtils::CreateObject(env);
    NapiUtils::DefineProperties(env, httpCertType, properties);
    NapiUtils::SetNamedProperty(env, exports, INTERFACE_CERT_TYPE, httpCertType);
}

void HttpModuleExports::InitHttpDataType(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_STATIC_PROPERTY("STRING",
                                     NapiUtils::CreateUint32(env, static_cast<uint32_t>(HttpDataType::STRING))),
        DECLARE_NAPI_STATIC_PROPERTY("OBJECT",
                                     NapiUtils::CreateUint32(env, static_cast<uint32_t>(HttpDataType::OBJECT))),
        DECLARE_NAPI_STATIC_PROPERTY("ARRAY_BUFFER",
                                     NapiUtils::CreateUint32(env, static_cast<uint32_t>(HttpDataType::ARRAY_BUFFER))),
    };
    napi_value httpDataType = NapiUtils::CreateObject(env);
    NapiUtils::DefineProperties(env, httpDataType, properties);
    NapiUtils::SetNamedProperty(env, exports, INTERFACE_HTTP_DATA_TYPE, httpDataType);
}

napi_value HttpModuleExports::HttpRequest::Request(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithOutAsyncWorkWithManagerWrapper<RequestContext>(
        env, info,
        [](napi_env, napi_value, RequestContext *context) -> bool {
#if !HAS_NETMANAGER_BASE
            if (!HttpExec::Initialize()) {
                return false;
            }
#endif
            context->GetTrace().Tracepoint(TraceEvents::FETCH);
            context->SetModuleId(g_moduleId);
            context->SetAtomicService(g_appIsAtomicService);
            context->SetBundleName(g_appBundleName);
            HttpExec::AsyncRunRequest(context);
            return context->IsExecOK();
        },
        "Request", HttpAsyncWork::ExecRequest, HttpAsyncWork::RequestCallback);
}

napi_value HttpModuleExports::HttpRequest::RequestInStream(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithOutAsyncWorkWithManagerWrapper<RequestContext>(
        env, info,
        [](napi_env, napi_value, RequestContext *context) -> bool {
#if !HAS_NETMANAGER_BASE
            if (!HttpExec::Initialize()) {
                return false;
            }
#endif
            context->GetTrace().Tracepoint(TraceEvents::FETCH);
            context->SetModuleId(g_moduleId);
            context->SetAtomicService(g_appIsAtomicService);
            context->SetBundleName(g_appBundleName);
            context->EnableRequestInStream();
            HttpExec::AsyncRunRequest(context);
            return true;
        },
        "RequestInStream", HttpAsyncWork::ExecRequest, HttpAsyncWork::RequestCallback);
}

napi_value HttpModuleExports::HttpRequest::Destroy(napi_env env, napi_callback_info info)
{
    HiAppEventReport hiAppEventReport("NetworkKit", "HttpDestroy");
    napi_value thisVal = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVal, nullptr));
    EventManagerWrapper *wrapper = nullptr;
    auto napiRet = napi_unwrap(env, thisVal, reinterpret_cast<void **>(&wrapper));
    if (napiRet != napi_ok) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napi_ret is %{public}d", napiRet);
        return NapiUtils::GetUndefined(env);
    }

    if (!wrapper) {
        return NapiUtils::GetUndefined(env);
    }
    auto manager = wrapper->sharedManager;
    if (!manager) {
        return NapiUtils::GetUndefined(env);
    }
    if (manager->IsEventDestroy()) {
        NETSTACK_LOGD("js object has been destroyed");
        return NapiUtils::GetUndefined(env);
    }
    manager->SetEventDestroy(true);
    manager->DeleteEventReference(env);
    if (g_limitSdkReport == 0) {
        hiAppEventReport.ReportSdkEvent(RESULT_SUCCESS, ERR_NONE);
        g_limitSdkReport = 1;
    }
    return NapiUtils::GetUndefined(env);
}

napi_value HttpModuleExports::HttpRequest::On(napi_env env, napi_callback_info info)
{
    ModuleTemplate::OnManagerWrapper(
        env, info, {ON_HEADERS_RECEIVE, ON_DATA_RECEIVE, ON_DATA_END, ON_DATA_RECEIVE_PROGRESS, ON_DATA_SEND_PROGRESS},
        false);
    return ModuleTemplate::OnManagerWrapper(env, info, {ON_HEADER_RECEIVE}, true);
}

napi_value HttpModuleExports::HttpRequest::Once(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::OnceManagerWrapper(env, info, {ON_HEADER_RECEIVE, ON_HEADERS_RECEIVE}, false);
}

napi_value HttpModuleExports::HttpRequest::Off(napi_env env, napi_callback_info info)
{
    ModuleTemplate::OffManagerWrapper(
        env, info, {ON_HEADERS_RECEIVE, ON_DATA_RECEIVE, ON_DATA_END, ON_DATA_RECEIVE_PROGRESS, ON_DATA_SEND_PROGRESS});
    return ModuleTemplate::OffManagerWrapper(env, info, {ON_HEADER_RECEIVE});
}

napi_value HttpModuleExports::HttpResponseCache::Flush(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithManagerWrapper<BaseContext>(
        env, info, FLUSH_ASYNC_WORK_NAME, nullptr, HttpAsyncWork::ExecFlush, HttpAsyncWork::FlushCallback);
}

napi_value HttpModuleExports::HttpResponseCache::Delete(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithManagerWrapper<BaseContext>(
        env, info, DELETE_ASYNC_WORK_NAME, nullptr, HttpAsyncWork::ExecDelete, HttpAsyncWork::DeleteCallback);
}

napi_value HttpModuleExports::HttpInterceptorChain::GetChain(napi_env env, napi_callback_info info)
{
    napi_value this_arg;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &this_arg, nullptr);
    if (status != napi_ok) {
        NETSTACK_LOGE("Failed to get cb info in GetChain");
        return NapiUtils::CreateArray(env, 0);
    }
    HttpInterceptorChain *chain = nullptr;
    status = napi_unwrap(env, this_arg, reinterpret_cast<void **>(&chain));
    if (status != napi_ok || chain == nullptr) {
        NETSTACK_LOGE("Failed to unwrap HttpInterceptorChain in GetChain");
        return NapiUtils::CreateArray(env, 0);
    }

    if (chain->chain_.empty()) {
        return NapiUtils::CreateArray(env, 0);
    }

    napi_value result = NapiUtils::CreateArray(env, chain->chain_.size());
    for (size_t i = 0; i < chain->chain_.size(); ++i) {
        HttpInterceptor *interceptor = chain->chain_[i];
        if (interceptor == nullptr) {
            NETSTACK_LOGE("Null interceptor in chain during GetChain");
            return NapiUtils::CreateArray(env, 0);
        }
        napi_value interceptorInstance = interceptor->GetInstance(env);
        NapiUtils::SetArrayElement(env, result, i, interceptorInstance);
    }
    return result;
}

napi_value HttpModuleExports::HttpInterceptorChain::AddChain(napi_env env, napi_callback_info info)
{
    napi_value rs = NapiUtils::GetBoolean(env, false);
    size_t argc = 1;
    napi_value args[1];
    napi_value this_arg;
    napi_status status = napi_get_cb_info(env, info, &argc, args, &this_arg, nullptr);
    if (status != napi_ok || argc != 1) {
        NETSTACK_LOGE("Invalid args in AddChain");
        NapiUtils::ThrowError(env, "2300801", "Parameter type not supported by the interceptor");
        return rs;
    }

    HttpInterceptorChain *chain = nullptr;
    status = napi_unwrap(env, this_arg, reinterpret_cast<void **>(&chain));
    if (status != napi_ok || chain == nullptr) {
        NETSTACK_LOGE("Failed to unwrap chain in AddChain");
        NapiUtils::ThrowError(env, "2300999", "Internal error");
        return rs;
    }

    if (!NapiUtils::IsArray(env, args[0])) {
        NETSTACK_LOGE("Non-array argument in AddChain");
        NapiUtils::ThrowError(env, "2300801", "Parameter type not supported by the interceptor");
        return rs;
    }

    uint32_t length = NapiUtils::GetArrayLength(env, args[0]);
    for (uint32_t i = 0; i < length; ++i) {
        napi_value interceptor = NapiUtils::GetArrayElement(env, args[0], i);
        std::string type = NapiUtils::GetStringPropertyUtf8(env, interceptor, "interceptorType");
        if (type.empty()) {
            NETSTACK_LOGE("Empty interceptor type in AddChain");
            NapiUtils::ThrowError(env, "2300999", "Internal error");
            return rs;
        }
        for (const auto &existing : chain->chain_) {
            if (existing->interceptorType_ == type) {
                NETSTACK_LOGE("Duplicate interceptor type: %{public}s in AddChain", type.c_str());
                NapiUtils::ThrowError(env, "2300802", "Duplicated interceptor type in the chain");
                return rs;
            }
        }
        HttpInterceptor *newInterceptor = new HttpInterceptor(env, type, interceptor);
        chain->chain_.push_back(newInterceptor);
    }
    return NapiUtils::GetBoolean(env, true);
}

napi_value HttpModuleExports::HttpInterceptorChain::Apply(napi_env env, napi_callback_info info)
{
    napi_value rs = NapiUtils::GetBoolean(env, false);
    size_t argc = 1;
    napi_value args[1];
    napi_value this_arg;
    napi_status status = napi_get_cb_info(env, info, &argc, args, &this_arg, nullptr);
    if (status != napi_ok || argc != 1) {
        NETSTACK_LOGE("Failed to get cb info in Apply");
        NapiUtils::ThrowError(env, "2300801", "Parameter type not supported by the interceptor");
        return rs;
    }
    HttpInterceptorChain *chain = nullptr;
    status = napi_unwrap(env, this_arg, reinterpret_cast<void **>(&chain));
    if (status != napi_ok || chain == nullptr) {
        NETSTACK_LOGE("Failed to unwrap chain in Apply");
        NapiUtils::ThrowError(env, "2300999", "Internal error");
        return rs;
    }

    if (chain->chain_.empty()) {
        NETSTACK_LOGE("Empty chain in Apply");
        return rs;
    }

    if (NapiUtils::GetValueType(env, args[0]) != napi_object) {
        NETSTACK_LOGE("Non-object argument in Apply");
        NapiUtils::ThrowError(env, "2300801", "Parameter type not supported by the interceptor");
        return rs;
    }

    std::map<std::string, napi_ref> interceptorRefs;
    for (size_t i = 0; i < chain->chain_.size(); ++i) {
        HttpInterceptor *interceptor = chain->chain_[i];
        if (interceptor == nullptr) {
            NETSTACK_LOGE("Null interceptor in chain during Apply");
            NapiUtils::ThrowError(env, "2300999", "Internal error");
            return rs;
        }
        napi_value interceptorInstance = interceptor->GetInstance(env);
        napi_ref ref;
        if (napi_create_reference(env, interceptorInstance, 1, &ref) == napi_ok) {
            interceptorRefs.insert({ interceptor->interceptorType_, ref });
        }
    }
    return ModuleTemplate::InterceptorChainApply(env, info, interceptorRefs);
}

static napi_module g_httpModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = HttpModuleExports::InitHttpModule,
    .nm_modname = HTTP_MODULE_NAME,
    .nm_priv = nullptr,
    .reserved = {nullptr},
};

extern "C" __attribute__((constructor)) void RegisterHttpModule(void)
{
    napi_module_register(&g_httpModule);
}

void HttpModuleExports::InitAddressFamily(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::HTTP_ADDRESS_FAMILY_UNSPEC,
                                     NapiUtils::CreateStringUtf8(env, HttpConstant::HTTP_ADDRESS_FAMILY_UNSPEC)),
        DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::HTTP_ADDRESS_FAMILY_ONLYV4,
                                     NapiUtils::CreateStringUtf8(env, HttpConstant::HTTP_ADDRESS_FAMILY_ONLYV4)),
        DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::HTTP_ADDRESS_FAMILY_ONLYV6,
                                     NapiUtils::CreateStringUtf8(env, HttpConstant::HTTP_ADDRESS_FAMILY_ONLYV6)),
    };
    napi_value httpAddressFamily = NapiUtils::CreateObject(env);
    NapiUtils::DefineProperties(env, httpAddressFamily, properties);
    NapiUtils::SetNamedProperty(env, exports, INTERFACE_ADDRESS_FAMILY, httpAddressFamily);
}

void HttpModuleExports::InitSslType(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_STATIC_PROPERTY("TLS", NapiUtils::CreateUint32(env, static_cast<uint32_t>(SslType::TLS))),
        DECLARE_NAPI_STATIC_PROPERTY("TLCP", NapiUtils::CreateUint32(env, static_cast<uint32_t>(SslType::TLCP)))
    };

    napi_value sslType = NapiUtils::CreateObject(env);
    NapiUtils::DefineProperties(env, sslType, properties);
    NapiUtils::SetNamedProperty(env, exports, INTERFACE_SSL_TYPE, sslType);
}

void HttpModuleExports::InitClientEncCert(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::HTTP_CERT_TYPE_PEM,
                                     NapiUtils::CreateStringUtf8(env, HttpConstant::HTTP_CERT_TYPE_PEM)),
        DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::HTTP_CERT_TYPE_DER,
                                     NapiUtils::CreateStringUtf8(env, HttpConstant::HTTP_CERT_TYPE_DER)),
        DECLARE_NAPI_STATIC_PROPERTY(HttpConstant::HTTP_CERT_TYPE_P12,
                                     NapiUtils::CreateStringUtf8(env, HttpConstant::HTTP_CERT_TYPE_P12)),
    };
    napi_value httpEncCertType = NapiUtils::CreateObject(env);
    NapiUtils::DefineProperties(env, httpEncCertType, properties);
    NapiUtils::SetNamedProperty(env, exports, INTERFACE_CLIENT_ENC_CERT, httpEncCertType);
}
} // namespace OHOS::NetStack::Http
