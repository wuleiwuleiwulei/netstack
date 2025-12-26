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

#ifndef COMMUNICATIONNETSTACK_NETSTACK_MODULE_TEMPLATE_H
#define COMMUNICATIONNETSTACK_NETSTACK_MODULE_TEMPLATE_H

#include <cstddef>
#include <map>
#include <initializer_list>
#include <iosfwd>
#include <type_traits>
#include <vector>

#include "base_async_work.h"
#include "base_context.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_utils.h"
#include "netstack_log.h"

namespace OHOS::NetStack {
class EventManager;
struct EventManagerWrapper;
} // namespace OHOS::NetStack

#define MAX_PARAM_NUM 64

namespace OHOS::NetStack::ModuleTemplate {

template <class Context>
napi_value InterfaceWithManagerWrapper(napi_env env, napi_callback_info info, const std::string &asyncWorkName,
                                       bool (*Work)(napi_env, napi_value, Context *), AsyncWorkExecutor executor,
                                       AsyncWorkCallback callback)
{
    NETSTACK_LOGI("js invoke %{public}s", asyncWorkName.c_str());
    static_assert(std::is_base_of<BaseContext, Context>::value);

    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    EventManagerWrapper *wrapper = nullptr;
    auto napi_ret = napi_unwrap(env, thisVal, reinterpret_cast<void **>(&wrapper));
    if (napi_ret != napi_ok) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napi_ret is %{public}d", napi_ret);
        return NapiUtils::GetUndefined(env);
    }

    std::shared_ptr<EventManager> sharedManager = nullptr;
    if (wrapper) {
        sharedManager = wrapper->sharedManager;
    }
    auto context = new (std::nothrow) Context(env, sharedManager);
    if (!context) {
        NETSTACK_LOGE("new context is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    context->ParseParams(params, paramsCount);
    if (context->IsNeedThrowException()) { // only api9 or later need throw exception.
        napi_throw_error(env, std::to_string(context->GetErrorCode()).c_str(), context->GetErrorMessage().c_str());
        delete context;
        context = nullptr;
        return NapiUtils::GetUndefined(env);
    }
    if (Work != nullptr) {
        if (!Work(env, thisVal, context)) {
            NETSTACK_LOGE("work failed error code = %{public}d", context->GetErrorCode());
        }
    }

    context->CreateReference(thisVal);
    context->CreateAsyncWork(asyncWorkName, executor, callback);
    if (NapiUtils::GetValueType(env, context->GetCallback()) != napi_function && context->IsNeedPromise()) {
        NETSTACK_LOGD("%{public}s create promise", asyncWorkName.c_str());
        return context->CreatePromise();
    }
    return NapiUtils::GetUndefined(env);
}

template <class Context>
napi_value InterfaceWithSharedManager(napi_env env, napi_callback_info info, const std::string &asyncWorkName,
                                      bool (*Work)(napi_env, napi_value, Context *), AsyncWorkExecutor executor,
                                      AsyncWorkCallback callback)
{
    NETSTACK_LOGI("js invoke %{public}s", asyncWorkName.c_str());
    static_assert(std::is_base_of<BaseContext, Context>::value);

    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    std::shared_ptr<EventManager> *sharedManager = nullptr;
    auto napi_ret = napi_unwrap(env, thisVal, reinterpret_cast<void **>(&sharedManager));
    if (napi_ret != napi_ok) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napi_ret is %{public}d", napi_ret);
        return NapiUtils::GetUndefined(env);
    }
    std::shared_ptr<EventManager> manager = nullptr;
    if (sharedManager != nullptr && *sharedManager != nullptr) {
        manager = *sharedManager;
    }

    auto context = new (std::nothrow) Context(env, manager);
    if (!context) {
        NETSTACK_LOGE("new context is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    context->ParseParams(params, paramsCount);
    if (context->IsNeedThrowException()) { // only api9 or later need throw exception.
        napi_throw_error(env, std::to_string(context->GetErrorCode()).c_str(), context->GetErrorMessage().c_str());
        delete context;
        context = nullptr;
        return NapiUtils::GetUndefined(env);
    }
    if (Work != nullptr) {
        if (!Work(env, thisVal, context)) {
            NETSTACK_LOGE("work failed error code = %{public}d", context->GetErrorCode());
        }
    }

    context->CreateReference(thisVal);
    context->CreateAsyncWork(asyncWorkName, executor, callback);
    if (NapiUtils::GetValueType(env, context->GetCallback()) != napi_function && context->IsNeedPromise()) {
        NETSTACK_LOGD("%{public}s create promise", asyncWorkName.c_str());
        return context->CreatePromise();
    }
    return NapiUtils::GetUndefined(env);
}

template <class Context>
napi_value InterfaceWithOutAsyncWorkWithManagerWrapper(napi_env env, napi_callback_info info,
                                                       bool (*Work)(napi_env, napi_value, Context *),
                                                       const std::string &asyncWorkName, AsyncWorkExecutor executor,
                                                       AsyncWorkCallback callback)
{
    static_assert(std::is_base_of<BaseContext, Context>::value);

    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    EventManagerWrapper *wrapper = nullptr;
    auto napi_ret = napi_unwrap(env, thisVal, reinterpret_cast<void **>(&wrapper));
    if (napi_ret != napi_ok) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napi_ret is %{public}d", napi_ret);
        return NapiUtils::GetUndefined(env);
    }

    std::shared_ptr<EventManager> sharedManager = nullptr;
    if (wrapper) {
        sharedManager = wrapper->sharedManager;
    }
    auto context = new (std::nothrow) Context(env, sharedManager);
    if (!context) {
        NETSTACK_LOGE("new context is nullptr");
        return NapiUtils::GetUndefined(env);
    }
#if ENABLE_HTTP_INTERCEPT
    context->SetInterceptorRefs(wrapper->eventManager.interceptorRefs_);
#endif
    context->ParseParams(params, paramsCount);
    napi_value ret = NapiUtils::GetUndefined(env);
    if (NapiUtils::GetValueType(env, context->GetCallback()) != napi_function && context->IsNeedPromise()) {
        NETSTACK_LOGD("%{public}s is invoked in promise mode", asyncWorkName.c_str());
        ret = context->CreatePromise();
    } else {
        NETSTACK_LOGD("%{public}s is invoked in callback mode", asyncWorkName.c_str());
    }
    context->CreateReference(thisVal);
    if (Work != nullptr) {
        if (!Work(env, thisVal, context)) {
            NETSTACK_LOGE("work failed error code = %{public}d", context->GetErrorCode());
        }
    }
    if (!context->IsParseOK() || context->IsPermissionDenied() || context->IsNoAllowedHost() ||
        context->IsCleartextNotPermitted() || context->GetSharedManager()->IsEventDestroy()) {
        context->CreateAsyncWork(asyncWorkName, executor, callback);
    }
    return ret;
}

template <class Context>
napi_value InterfaceWithOutAsyncWorkWithSharedManager(napi_env env, napi_callback_info info,
                                                      bool (*Work)(napi_env, napi_value, Context *),
                                                      const std::string &asyncWorkName, AsyncWorkExecutor executor,
                                                      AsyncWorkCallback callback)
{
    static_assert(std::is_base_of<BaseContext, Context>::value);

    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    std::shared_ptr<EventManager> *sharedManager = nullptr;
    auto napi_ret = napi_unwrap(env, thisVal, reinterpret_cast<void **>(&sharedManager));
    if (napi_ret != napi_ok) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napi_ret is %{public}d", napi_ret);
        return NapiUtils::GetUndefined(env);
    }
    std::shared_ptr<EventManager> manager = nullptr;
    if (sharedManager != nullptr && *sharedManager != nullptr) {
        manager = *sharedManager;
    }

    auto context = new (std::nothrow) Context(env, manager);
    if (!context) {
        NETSTACK_LOGE("new context is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    context->ParseParams(params, paramsCount);
    napi_value ret = NapiUtils::GetUndefined(env);
    if (NapiUtils::GetValueType(env, context->GetCallback()) != napi_function && context->IsNeedPromise()) {
        NETSTACK_LOGD("%{public}s is invoked in promise mode", asyncWorkName.c_str());
        ret = context->CreatePromise();
    } else {
        NETSTACK_LOGD("%{public}s is invoked in callback mode", asyncWorkName.c_str());
    }
    context->CreateReference(thisVal);
    if (Work != nullptr) {
        if (!Work(env, thisVal, context)) {
            NETSTACK_LOGE("work failed error code = %{public}d", context->GetErrorCode());
        }
    }
    if (!context->IsParseOK() || context->IsPermissionDenied() || context->IsNoAllowedHost() ||
        context->IsCleartextNotPermitted() || context->GetSharedManager()->IsEventDestroy()) {
        context->CreateAsyncWork(asyncWorkName, executor, callback);
    }
    return ret;
}

template <napi_value (*MakeJsValue)(napi_env, void *)> static void CallbackTemplate(uv_work_t *work, int status)
{
    (void)status;

    auto workWrapper = static_cast<UvWorkWrapperShared *>(work->data);
    napi_env env = workWrapper->env;
    auto closeScope = [env](napi_handle_scope scope) { NapiUtils::CloseScope(env, scope); };
    std::unique_ptr<napi_handle_scope__, decltype(closeScope)> scope(NapiUtils::OpenScope(env), closeScope);

    napi_value obj = MakeJsValue(env, workWrapper->data);

    std::pair<napi_value, napi_value> arg = {NapiUtils::GetUndefined(workWrapper->env), obj};
    workWrapper->manager->Emit(workWrapper->type, arg);

    delete workWrapper;
    delete work;
}

template <napi_value (*MakeJsValue)(napi_env, const std::shared_ptr<EventManager> &)>
static void CallbackTemplateWithSharedManager(uv_work_t *work, int status)
{
    (void)status;

    auto workWrapper = static_cast<UvWorkWrapperShared *>(work->data);
    napi_env env = workWrapper->env;
    auto closeScope = [env](napi_handle_scope scope) { NapiUtils::CloseScope(env, scope); };
    std::unique_ptr<napi_handle_scope__, decltype(closeScope)> scope(NapiUtils::OpenScope(env), closeScope);

    napi_value obj = MakeJsValue(env, workWrapper->manager);

    std::pair<napi_value, napi_value> arg = {NapiUtils::GetUndefined(workWrapper->env), obj};
    workWrapper->manager->Emit(workWrapper->type, arg);

    delete workWrapper;
    delete work;
}

void CleanUpWithSharedManager(void* data);

void DefineClass(napi_env env, napi_value exports, const std::initializer_list<napi_property_descriptor> &properties,
                 const std::string &className);

void DefineClassNew(napi_env env, napi_value exports, const std::initializer_list<napi_property_descriptor> &properties,
    const std::string &className, napi_callback constructor);

napi_value InterceptorChainApply(
    napi_env env, napi_callback_info info, const std::map<std::string, napi_ref> &interceptorReferences);

napi_value NewInstanceNoManager(napi_env env, napi_callback_info info, const std::string &name, Finalizer finalizer);

napi_value NewInstanceWithSharedManager(napi_env env, napi_callback_info info, const std::string &className,
                                        Finalizer finalizer);

napi_value NewInstanceWithManagerWrapper(napi_env env, napi_callback_info info, const std::string &className,
                                         Finalizer finalizer);

napi_value OnSharedManager(napi_env env, napi_callback_info info, const std::initializer_list<std::string> &events,
                           bool asyncCallback);

napi_value OnceSharedManager(napi_env env, napi_callback_info info, const std::initializer_list<std::string> &events,
                             bool asyncCallback);

napi_value OffSharedManager(napi_env env, napi_callback_info info, const std::initializer_list<std::string> &events);

napi_value OnManagerWrapper(napi_env env, napi_callback_info info, const std::initializer_list<std::string> &events,
                            bool asyncCallback);

napi_value OnceManagerWrapper(napi_env env, napi_callback_info info, const std::initializer_list<std::string> &events,
                              bool asyncCallback);

napi_value OffManagerWrapper(napi_env env, napi_callback_info info, const std::initializer_list<std::string> &events);
} // namespace OHOS::NetStack::ModuleTemplate
#endif /* COMMUNICATIONNETSTACK_NETSTACK_MODULE_TEMPLATE_H */
