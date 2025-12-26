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

#include "module_template.h"

#include <algorithm>
#include <functional>
#include <initializer_list>
#include <memory>
#include <new>
#include <string>

#include "event_manager.h"
#include "netstack_log.h"
#ifndef CROSS_PLATFORM
#include "hi_app_event_report.h"
#endif

namespace OHOS::NetStack::ModuleTemplate {
static constexpr const int EVENT_PARAM_NUM = 2;
static constexpr const char *INTERFACE_LOCAL_SOCKET = "LocalSocket";
static constexpr const char *INTERFACE_TLS_SOCKET = "TLSSocket";
static constexpr const char *INTERFACE_WEB_SOCKET = "WebSocket";
static constexpr const char *INTERFACE_HTTP_REQUEST = "OHOS_NET_HTTP_HttpRequest";
static constexpr const char *INTERFACE_WEB_SOCKET_SERVER = "WebSocketServer";
static constexpr const char *EVENT_MANAGER = "EVENT_MANAGER";

napi_value OnManagerWrapper(napi_env env, napi_callback_info info, const std::initializer_list<std::string> &events,
                            bool asyncCallback)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    if (paramsCount != EVENT_PARAM_NUM || NapiUtils::GetValueType(env, params[0]) != napi_string ||
        NapiUtils::GetValueType(env, params[1]) != napi_function) {
        NETSTACK_LOGE("on off once interface para: [string, function]");
        napi_throw_error(env, std::to_string(PARSE_ERROR_CODE).c_str(), PARSE_ERROR_MSG);
        return NapiUtils::GetUndefined(env);
    }

    std::string event = NapiUtils::GetStringFromValueUtf8(env, params[0]);
    if (std::find(events.begin(), events.end(), event) == events.end()) {
        return NapiUtils::GetUndefined(env);
    }

    EventManagerWrapper *wrapper = nullptr;
    auto napiRet = napi_unwrap(env, thisVal, reinterpret_cast<void **>(&wrapper));
    if (napiRet != napi_ok) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napiRet is %{public}d", napiRet);
        return NapiUtils::GetUndefined(env);
    }
    if (wrapper == nullptr) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napiRet is %{public}d", napiRet);
        return NapiUtils::GetUndefined(env);
    }
    auto manager = wrapper->sharedManager;
    if (manager == nullptr) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napiRet is %{public}d", napiRet);
        return NapiUtils::GetUndefined(env);
    }
    if (manager != nullptr) {
        manager->AddListener(env, event, params[1], false, asyncCallback);
    }

    return NapiUtils::GetUndefined(env);
}

napi_value OnceManagerWrapper(napi_env env, napi_callback_info info, const std::initializer_list<std::string> &events,
                              bool asyncCallback)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    if (paramsCount != EVENT_PARAM_NUM || NapiUtils::GetValueType(env, params[0]) != napi_string ||
        NapiUtils::GetValueType(env, params[1]) != napi_function) {
        NETSTACK_LOGE("on off once interface para: [string, function]");
        return NapiUtils::GetUndefined(env);
    }

    std::string event = NapiUtils::GetStringFromValueUtf8(env, params[0]);
    if (std::find(events.begin(), events.end(), event) == events.end()) {
        return NapiUtils::GetUndefined(env);
    }

    EventManagerWrapper *wrapper = nullptr;
    auto napiRet = napi_unwrap(env, thisVal, reinterpret_cast<void **>(&wrapper));
    if (napiRet != napi_ok) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napiRet is %{public}d", napiRet);
        return NapiUtils::GetUndefined(env);
    }
    if (wrapper == nullptr) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napiRet is %{public}d", napiRet);
        return NapiUtils::GetUndefined(env);
    }
    auto manager = wrapper->sharedManager;
    if (manager != nullptr) {
        manager->AddListener(env, event, params[1], true, asyncCallback);
    }

    return NapiUtils::GetUndefined(env);
}

napi_value OffManagerWrapper(napi_env env, napi_callback_info info, const std::initializer_list<std::string> &events)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    if ((paramsCount != 1 && paramsCount != EVENT_PARAM_NUM) ||
        NapiUtils::GetValueType(env, params[0]) != napi_string) {
        NETSTACK_LOGE("on off once interface para: [string, function?]");
        napi_throw_error(env, std::to_string(PARSE_ERROR_CODE).c_str(), PARSE_ERROR_MSG);
        return NapiUtils::GetUndefined(env);
    }

    if (paramsCount == EVENT_PARAM_NUM && NapiUtils::GetValueType(env, params[1]) != napi_function) {
        NETSTACK_LOGE("on off once interface para: [string, function]");
        napi_throw_error(env, std::to_string(PARSE_ERROR_CODE).c_str(), PARSE_ERROR_MSG);
        return NapiUtils::GetUndefined(env);
    }

    std::string event = NapiUtils::GetStringFromValueUtf8(env, params[0]);
    if (std::find(events.begin(), events.end(), event) == events.end()) {
        return NapiUtils::GetUndefined(env);
    }

    EventManagerWrapper *wrapper = nullptr;
    auto napiRet = napi_unwrap(env, thisVal, reinterpret_cast<void **>(&wrapper));
    if (napiRet != napi_ok) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napiRet is %{public}d", napiRet);
        return NapiUtils::GetUndefined(env);
    }
    if (wrapper == nullptr) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napiRet is %{public}d", napiRet);
        return NapiUtils::GetUndefined(env);
    }
    auto manager = wrapper->sharedManager;
    if (manager == nullptr) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napiRet is %{public}d", napiRet);
        return NapiUtils::GetUndefined(env);
    }
    if (manager != nullptr) {
        if (paramsCount == EVENT_PARAM_NUM) {
            manager->DeleteListener(event, params[1]);
        } else {
            manager->DeleteListener(event);
        }
    }

    return NapiUtils::GetUndefined(env);
}

napi_value OnSharedManager(napi_env env, napi_callback_info info, const std::initializer_list<std::string> &events,
                           bool asyncCallback)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    if (paramsCount != EVENT_PARAM_NUM || NapiUtils::GetValueType(env, params[0]) != napi_string ||
        NapiUtils::GetValueType(env, params[1]) != napi_function) {
        NETSTACK_LOGE("on off once interface para: [string, function]");
        napi_throw_error(env, std::to_string(PARSE_ERROR_CODE).c_str(), PARSE_ERROR_MSG);
        return NapiUtils::GetUndefined(env);
    }

    std::string event = NapiUtils::GetStringFromValueUtf8(env, params[0]);
    if (std::find(events.begin(), events.end(), event) == events.end()) {
        return NapiUtils::GetUndefined(env);
    }

    std::shared_ptr<EventManager> *sharedManager = nullptr;
    auto napiRet = napi_unwrap(env, thisVal, reinterpret_cast<void **>(&sharedManager));
    if (napiRet != napi_ok) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napiRet is %{public}d", napiRet);
        return NapiUtils::GetUndefined(env);
    }
    if (sharedManager == nullptr) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napiRet is %{public}d", napiRet);
        return NapiUtils::GetUndefined(env);
    }
    auto manager = *sharedManager;
    if (manager == nullptr) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napiRet is %{public}d", napiRet);
        return NapiUtils::GetUndefined(env);
    }
    if (manager != nullptr) {
        manager->AddListener(env, event, params[1], false, asyncCallback);
    }

    return NapiUtils::GetUndefined(env);
}

napi_value OnceSharedManager(napi_env env, napi_callback_info info, const std::initializer_list<std::string> &events,
                             bool asyncCallback)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    if (paramsCount != EVENT_PARAM_NUM || NapiUtils::GetValueType(env, params[0]) != napi_string ||
        NapiUtils::GetValueType(env, params[1]) != napi_function) {
        NETSTACK_LOGE("on off once interface para: [string, function]");
        return NapiUtils::GetUndefined(env);
    }

    std::string event = NapiUtils::GetStringFromValueUtf8(env, params[0]);
    if (std::find(events.begin(), events.end(), event) == events.end()) {
        return NapiUtils::GetUndefined(env);
    }

    std::shared_ptr<EventManager> *sharedManager = nullptr;
    auto napiRet = napi_unwrap(env, thisVal, reinterpret_cast<void **>(&sharedManager));
    if (napiRet != napi_ok) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napiRet is %{public}d", napiRet);
        return NapiUtils::GetUndefined(env);
    }
    if (sharedManager == nullptr) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napiRet is %{public}d", napiRet);
        return NapiUtils::GetUndefined(env);
    }
    auto manager = *sharedManager;
    if (manager != nullptr) {
        manager->AddListener(env, event, params[1], true, asyncCallback);
    }

    return NapiUtils::GetUndefined(env);
}

napi_value OffSharedManager(napi_env env, napi_callback_info info, const std::initializer_list<std::string> &events)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    if ((paramsCount != 1 && paramsCount != EVENT_PARAM_NUM) ||
        NapiUtils::GetValueType(env, params[0]) != napi_string) {
        NETSTACK_LOGE("on off once interface para: [string, function?]");
        napi_throw_error(env, std::to_string(PARSE_ERROR_CODE).c_str(), PARSE_ERROR_MSG);
        return NapiUtils::GetUndefined(env);
    }

    if (paramsCount == EVENT_PARAM_NUM && NapiUtils::GetValueType(env, params[1]) != napi_function) {
        NETSTACK_LOGE("on off once interface para: [string, function]");
        napi_throw_error(env, std::to_string(PARSE_ERROR_CODE).c_str(), PARSE_ERROR_MSG);
        return NapiUtils::GetUndefined(env);
    }

    std::string event = NapiUtils::GetStringFromValueUtf8(env, params[0]);
    if (std::find(events.begin(), events.end(), event) == events.end()) {
        return NapiUtils::GetUndefined(env);
    }

    std::shared_ptr<EventManager> *sharedManager = nullptr;
    auto napiRet = napi_unwrap(env, thisVal, reinterpret_cast<void **>(&sharedManager));
    if (napiRet != napi_ok) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napiRet is %{public}d", napiRet);
        return NapiUtils::GetUndefined(env);
    }
    if (sharedManager == nullptr) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napiRet is %{public}d", napiRet);
        return NapiUtils::GetUndefined(env);
    }
    auto manager = *sharedManager;
    if (manager == nullptr) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napiRet is %{public}d", napiRet);
        return NapiUtils::GetUndefined(env);
    }
    if (manager != nullptr) {
        if (paramsCount == EVENT_PARAM_NUM) {
            manager->DeleteListener(event, params[1]);
        } else {
            manager->DeleteListener(event);
        }
    }

    return NapiUtils::GetUndefined(env);
}

void CleanUpWithSharedManager(void* data)
{
    auto sharedManager = reinterpret_cast<std::shared_ptr<EventManager> *>(data);
    if (sharedManager == nullptr || *sharedManager == nullptr) {
        return;
    }
    auto manager = *sharedManager;
    auto env = manager->env_;
    napi_value obj = nullptr;
    void* result = nullptr;
    napi_get_named_property(env, NapiUtils::GetGlobal(env), manager->className_.c_str(), &obj);
    napi_remove_wrap(env, obj, &result);
}

void DefineClass(napi_env env, napi_value exports, const std::initializer_list<napi_property_descriptor> &properties,
                 const std::string &className)
{
    auto constructor = [](napi_env env, napi_callback_info info) -> napi_value {
        napi_value thisVal = nullptr;
        NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVal, nullptr));

        return thisVal;
    };

    napi_value jsConstructor = nullptr;

    napi_property_descriptor descriptors[properties.size()];
    std::copy(properties.begin(), properties.end(), descriptors);

    NAPI_CALL_RETURN_VOID(env, napi_define_class(env, className.c_str(), NAPI_AUTO_LENGTH, constructor, nullptr,
                                                 properties.size(), descriptors, &jsConstructor));
    (void)exports;
    auto global = NapiUtils::GetGlobal(env);
    NapiUtils::SetNamedProperty(env, global, className, jsConstructor);
}

void DefineClassNew(napi_env env, napi_value exports, const std::initializer_list<napi_property_descriptor> &properties,
    const std::string &className, napi_callback constructor)
{
    napi_value jsConstructor = nullptr;

    napi_property_descriptor descriptors[properties.size()];
    std::copy(properties.begin(), properties.end(), descriptors);

    NAPI_CALL_RETURN_VOID(env,
        napi_define_class(env, className.c_str(), NAPI_AUTO_LENGTH, constructor, nullptr, properties.size(),
            descriptors, &jsConstructor));
    NapiUtils::SetNamedProperty(env, exports, className, jsConstructor);
}

napi_value InterceptorChainApply(
    napi_env env, napi_callback_info info, const std::map<std::string, napi_ref> &interceptorReferences)
{
    size_t argCount = 1;
    napi_value args[1];
    napi_status status = napi_get_cb_info(env, info, &argCount, args, nullptr, nullptr);
    if (status != napi_ok) {
        NETSTACK_LOGE("InterceptorChainApply failed to get callback info, napi_status: %{public}d", status);
        NapiUtils::ThrowError(env, "2300999", "Internal error");
        return NapiUtils::GetBoolean(env, false);
    }

    EventManagerWrapper *wrapper = nullptr;
    status = napi_unwrap(env, args[0], reinterpret_cast<void **>(&wrapper));
    if (status != napi_ok) {
        NETSTACK_LOGE("InterceptorChainApply failed to unwrap wrapper, napi_status: %{public}d", status);
        NapiUtils::ThrowError(env, "2300999", "Internal error");
        return NapiUtils::GetBoolean(env, false);
    }

    if (wrapper == nullptr) {
        NETSTACK_LOGE("InterceptorChainApply unwrap succeeded but wrapper is nullptr");
        NapiUtils::ThrowError(env, "2300999", "Internal error");
        return NapiUtils::GetBoolean(env, false);
    }

    NETSTACK_LOGD("InterceptorChainApply interceptor reference count: %{public}zu", interceptorReferences.size());
    wrapper->eventManager.interceptorRefs_ = interceptorReferences;
    return NapiUtils::GetBoolean(env, true);
}

napi_value NewInstanceWithManagerWrapper(napi_env env, napi_callback_info info, const std::string &className,
                                         Finalizer finalizer)
{
    NETSTACK_LOGD("create new instance for %{public}s", className.c_str());
    napi_value thisVal = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVal, nullptr));

    auto global = NapiUtils::GetGlobal(env);
    napi_value jsConstructor = NapiUtils::GetNamedProperty(env, global, className);
    if (NapiUtils::GetValueType(env, jsConstructor) == napi_undefined) {
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_new_instance(env, jsConstructor, 0, nullptr, &result));

    auto wrapper = new EventManagerWrapper;
    auto manager = std::make_shared<EventManager>();
    wrapper->sharedManager = manager;
    if (className == INTERFACE_HTTP_REQUEST || className == INTERFACE_LOCAL_SOCKET ||
        className == INTERFACE_TLS_SOCKET || className == INTERFACE_WEB_SOCKET ||
        className == INTERFACE_WEB_SOCKET_SERVER) {
        NETSTACK_LOGD("create reference for %{public}s", className.c_str());
        manager->CreateEventReference(env, thisVal);
    }
    napi_wrap(env, result, reinterpret_cast<void *>(wrapper), finalizer, nullptr, nullptr);

    return result;
}

napi_value NewInstanceWithSharedManager(napi_env env, napi_callback_info info, const std::string &className,
                                        Finalizer finalizer)
{
    NETSTACK_LOGD("create new instance for %{public}s", className.c_str());
    #ifndef CROSS_PLATFORM
    HiAppEventReport hiAppEventReport("NetworkKit", "WebsocketConstructLocalSocketInstance");
    #endif
    napi_value thisVal = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVal, nullptr));

    auto global = NapiUtils::GetGlobal(env);
    napi_value jsConstructor = NapiUtils::GetNamedProperty(env, global, className);
    if (NapiUtils::GetValueType(env, jsConstructor) == napi_undefined) {
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_new_instance(env, jsConstructor, 0, nullptr, &result));

    auto sharedManager = new (std::nothrow) std::shared_ptr<EventManager>();
    if (sharedManager == nullptr) {
        return result;
    }
    auto manager = std::make_shared<EventManager>();
    manager->env_ = env;
    manager->className_ = className + EVENT_MANAGER;
    manager->finalizer_ = finalizer;
    *sharedManager = manager;
    if (className == INTERFACE_HTTP_REQUEST || className == INTERFACE_LOCAL_SOCKET ||
        className == INTERFACE_TLS_SOCKET || className == INTERFACE_WEB_SOCKET ||
        className == INTERFACE_WEB_SOCKET_SERVER) {
        NETSTACK_LOGD("create reference for %{public}s", className.c_str());
        manager->CreateEventReference(env, thisVal);
    }
    napi_wrap(env, result, reinterpret_cast<void *>(sharedManager),
        [](napi_env env, void *data, void *hint) {
            napi_remove_env_cleanup_hook(env, CleanUpWithSharedManager, data);
            auto sharedManager = reinterpret_cast<std::shared_ptr<EventManager> *>(data);
            if (sharedManager == nullptr || *sharedManager == nullptr || (*sharedManager)->finalizer_ == nullptr) {
                return;
            }
            auto manager = *sharedManager;
            manager->finalizer_(env, data, hint);
        },
        nullptr, nullptr);
    napi_set_named_property(env, global, manager->className_.c_str(), result);
    napi_add_env_cleanup_hook(env, CleanUpWithSharedManager, reinterpret_cast<void *>(sharedManager));
    #ifndef CROSS_PLATFORM
    hiAppEventReport.ReportSdkEvent(RESULT_SUCCESS, ERR_NONE);
    #endif
    return result;
}

napi_value NewInstanceNoManager(napi_env env, napi_callback_info info, const std::string &name, Finalizer finalizer)
{
    napi_value thisVal = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVal, nullptr));
    (void)thisVal;
    auto global = NapiUtils::GetGlobal(env);
    napi_value jsConstructor = NapiUtils::GetNamedProperty(env, global, name);
    if (NapiUtils::GetValueType(env, jsConstructor) == napi_undefined) {
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_new_instance(env, jsConstructor, 0, nullptr, &result));

    return result;
}
} // namespace OHOS::NetStack::ModuleTemplate
