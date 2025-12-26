/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <string>

#include "cert_context.h"
#include "cleartext_context.h"
#include "net_ssl_async_work.h"
#include "net_ssl_exec.h"
#include "net_ssl_module.h"

#include "js_native_api.h"
#include "module_template.h"
#include "netstack_log.h"
#if HAS_NETMANAGER_BASE
#include "net_conn_client.h"
#include "network_security_config.h"
#endif // HAS_NETMANAGER_BASE

namespace OHOS::NetStack::Ssl {
static constexpr const char *NET_SSL_MODULE_NAME = "net.networkSecurity";

#ifdef MAC_PLATFORM
static constexpr const char *VERIFY_ASYNC_WORK_NAME = "ExecVerify";
#endif

struct AsyncCallbackInfo {
    napi_env env;
    napi_async_work asyncWork;
    napi_deferred deferred;
};

napi_value NetSslModuleExports::InitNetSslModule(napi_env env, napi_value exports)
{
    InitSslProperties(env, exports);
    NapiUtils::SetEnvValid(env);
    auto envWrapper = new (std::nothrow)napi_env;
    if (envWrapper == nullptr) {
        return exports;
    }
    *envWrapper = env;
    napi_add_env_cleanup_hook(env, NapiUtils::HookForEnvCleanup, envWrapper);
    return exports;
}

void NetSslModuleExports::InitSslProperties(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION("certVerification", VerifyCertification),
        DECLARE_NAPI_FUNCTION("certVerificationSync", VerifyCertificationSync),
        DECLARE_NAPI_FUNCTION("isCleartextPermitted", IsCleartextPermitted),
        DECLARE_NAPI_FUNCTION("isCleartextPermittedByHostName", IsCleartextPermittedByHostName)};
    NapiUtils::DefineProperties(env, exports, properties);

    InitCertType(env, exports);
}

void NetSslModuleExports::InitCertType(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_STATIC_PROPERTY("CERT_TYPE_PEM", NapiUtils::CreateUint32(env, CERT_TYPE_PEM)),
        DECLARE_NAPI_STATIC_PROPERTY("CERT_TYPE_DER", NapiUtils::CreateUint32(env, CERT_TYPE_DER))};

    napi_value certType = NapiUtils::CreateObject(env);
    NapiUtils::DefineProperties(env, certType, properties);
    NapiUtils::SetNamedProperty(env, exports, "CertType", certType);
}

napi_value NetSslModuleExports::VerifyCertification(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithOutAsyncWorkWithSharedManager<CertContext>(
        env, info,
        [](napi_env, napi_value, CertContext *context) -> bool {
            SslExec::AsyncRunVerify(context);
            return context->IsExecOK();
        },
        "VerifyCertification", NetSslAsyncWork::ExecVerify, NetSslAsyncWork::VerifyCallback);
}

napi_value NetSslModuleExports::VerifyCertificationSync(napi_env env, napi_callback_info info)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));
    std::shared_ptr<EventManager> manager = nullptr;
    auto context = std::make_unique<CertContext>(env, manager);
    context->ParseParams(params, paramsCount);
    if (context->GetErrorCode() != PARSE_ERROR_CODE) {
        if (context->GetCertBlobClient() == nullptr) {
            context->SetErrorCode(NetStackVerifyCertification(context->GetCertBlob()));
            NETSTACK_LOGD("verifyResult is %{public}d\n", context->GetErrorCode());
        } else {
            context->SetErrorCode(NetStackVerifyCertification(context->GetCertBlob(), context->GetCertBlobClient()));
            NETSTACK_LOGD("verifyResult is %{public}d\n", context->GetErrorCode());
        }
    }

    napi_value verifyResult;
    napi_status status = napi_create_int32(env, context->GetErrorCode(), &verifyResult);
    if (status != napi_ok) {
        return nullptr;
    }
    return verifyResult;
}

static napi_module g_sslModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = NetSslModuleExports::InitNetSslModule,
    .nm_modname = NET_SSL_MODULE_NAME,
    .nm_priv = nullptr,
    .reserved = {nullptr},
};

extern "C" __attribute__((constructor)) void RegisterSslModule(void)
{
    napi_module_register(&g_sslModule);
}

napi_value NetSslModuleExports::IsCleartextPermitted(napi_env env, napi_callback_info info)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));
    std::shared_ptr<EventManager> manager = nullptr;
    auto context = std::make_unique<CleartextContext>(env, manager);
    if (!context) {
        return NapiUtils::GetUndefined(env);
    }
    context->ParseParams(params, paramsCount);
    if (context->IsParseOK()) {
#if HAS_NETMANAGER_BASE
        using namespace OHOS::NetManagerStandard;
        int32_t ret = NetworkSecurityConfig::GetInstance().IsCleartextPermitted(context->isCleartextPermitted_);
        if (ret != NETMANAGER_SUCCESS) {
            context->SetErrorCode(ret);
            napi_throw_error(env, std::to_string(context->GetErrorCode()).c_str(), context->GetErrorMessage().c_str());
            return NapiUtils::GetUndefined(env);
        }
#else
        context->isCleartextPermitted_ = true;
#endif
        NETSTACK_LOGD("isCleartextPermitted is %{public}d\n", context->isCleartextPermitted_);
    } else {
        napi_throw_error(env, std::to_string(context->GetErrorCode()).c_str(), context->GetErrorMessage().c_str());
        return NapiUtils::GetUndefined(env);
    }
    return NapiUtils::GetBoolean(context->GetEnv(), context->isCleartextPermitted_);
}

napi_value NetSslModuleExports::IsCleartextPermittedByHostName(napi_env env, napi_callback_info info)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));
    std::shared_ptr<EventManager> manager = nullptr;
    auto context = std::make_unique<CleartextForHostContext>(env, manager);
    if (!context) {
        return NapiUtils::GetUndefined(env);
    }
    context->ParseParams(params, paramsCount);
    if (context->IsParseOK()) {
#if HAS_NETMANAGER_BASE
        using namespace OHOS::NetManagerStandard;
        int32_t ret = NetworkSecurityConfig::GetInstance().IsCleartextPermitted(context->hostname_,
            context->isCleartextPermitted_);
        if (ret != NETMANAGER_SUCCESS) {
            context->SetErrorCode(ret);
            napi_throw_error(env, std::to_string(context->GetErrorCode()).c_str(), context->GetErrorMessage().c_str());
            return NapiUtils::GetUndefined(env);
        }
#else
        context->isCleartextPermitted_ = true;
#endif
        NETSTACK_LOGD("isCleartextPermitted is %{public}d\n", context->isCleartextPermitted_);
    } else {
        napi_throw_error(env, std::to_string(context->GetErrorCode()).c_str(), context->GetErrorMessage().c_str());
        return NapiUtils::GetUndefined(env);
    }

    return NapiUtils::GetBoolean(context->GetEnv(), context->isCleartextPermitted_);
}
} // namespace OHOS::NetStack::Ssl
