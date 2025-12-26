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

#include "tlssocket_module.h"

#include <initializer_list>
#include <napi/native_common.h>

#include "common_context.h"
#include "event_manager.h"
#include "module_template.h"
#include "monitor.h"
#include "napi_utils.h"
#include "netstack_log.h"
#include "tls.h"
#include "tls_bind_context.h"
#include "tls_connect_context.h"
#include "tls_extra_context.h"
#include "tls_napi_context.h"
#include "tls_send_context.h"
#include "tls_init_context.h"
#include "tlssocket_async_work.h"
#ifndef CROSS_PLATFORM
#include "hi_app_event_report.h"
#endif

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
namespace {
static constexpr const char *PROTOCOL_TLSV13 = "TLSv13";
static constexpr const char *PROTOCOL_TLSV12 = "TLSv12";

void Finalize(napi_env, void *data, void *)
{
    NETSTACK_LOGI("tls socket is finalized");
    auto sharedManager = reinterpret_cast<std::shared_ptr<EventManager> *>(data);
    delete sharedManager;
}
} // namespace

napi_value TLSSocketModuleExports::TLSSocket::GetCertificate(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<GetCertificateContext>(env, info, FUNCTION_GET_CERTIFICATE,
        nullptr, TLSSocketAsyncWork::ExecGetCertificate, TLSSocketAsyncWork::GetCertificateCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::GetProtocol(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<GetCipherSuitesContext>(env, info, FUNCTION_GET_PROTOCOL,
        nullptr, TLSSocketAsyncWork::ExecGetProtocol, TLSSocketAsyncWork::GetProtocolCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::Connect(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TLSConnectContext>(
        env, info, FUNCTION_CONNECT, nullptr, TLSSocketAsyncWork::ExecConnect, TLSSocketAsyncWork::ConnectCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::GetCipherSuites(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<GetCipherSuitesContext>(env, info, FUNCTION_GET_CIPHER_SUITE,
        nullptr, TLSSocketAsyncWork::ExecGetCipherSuites, TLSSocketAsyncWork::GetCipherSuitesCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::GetRemoteCertificate(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<GetRemoteCertificateContext>(env, info,
        FUNCTION_GET_REMOTE_CERTIFICATE, nullptr, TLSSocketAsyncWork::ExecGetRemoteCertificate,
        TLSSocketAsyncWork::GetRemoteCertificateCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::GetSignatureAlgorithms(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<GetSignatureAlgorithmsContext>(
        env, info, FUNCTION_GET_SIGNATURE_ALGORITHMS, nullptr, TLSSocketAsyncWork::ExecGetSignatureAlgorithms,
        TLSSocketAsyncWork::GetSignatureAlgorithmsCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::Send(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TLSSendContext>(env, info, FUNCTION_SEND, nullptr,
        TLSSocketAsyncWork::ExecSend, TLSSocketAsyncWork::SendCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::Close(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TLSNapiContext>(env, info,
        FUNCTION_CLOSE, nullptr, TLSSocketAsyncWork::ExecClose,
        TLSSocketAsyncWork::CloseCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::Bind(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TLSBindContext>(env, info, FUNCTION_BIND, nullptr,
        TLSSocketAsyncWork::ExecBind, TLSSocketAsyncWork::BindCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::GetState(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TLSGetStateContext>(
        env, info, FUNCTION_GET_STATE, nullptr, TLSSocketAsyncWork::ExecGetState, TLSSocketAsyncWork::GetStateCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::GetRemoteAddress(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TLSGetRemoteAddressContext>(env, info,
        FUNCTION_GET_REMOTE_ADDRESS, nullptr, TLSSocketAsyncWork::ExecGetRemoteAddress,
        TLSSocketAsyncWork::GetRemoteAddressCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::GetLocalAddress(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TLSGetLocalAddressContext>(env, info, FUNCTION_GET_LOCAL_ADDRESS,
        nullptr, TLSSocketAsyncWork::ExecGetLocalAddress, TLSSocketAsyncWork::GetLocalAddressCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::SetExtraOptions(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TLSSetExtraOptionsContext>(env, info, FUNCTION_BIND, nullptr,
                                                                TLSSocketAsyncWork::ExecSetExtraOptions,
                                                                TLSSocketAsyncWork::SetExtraOptionsCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::On(napi_env env, napi_callback_info info)
{
    return DelayedSingleton<Monitor>::GetInstance()->On(env, info);
}

napi_value TLSSocketModuleExports::TLSSocket::Off(napi_env env, napi_callback_info info)
{
    return DelayedSingleton<Monitor>::GetInstance()->Off(env, info);
}

napi_value TLSSocketModuleExports::TLSSocket::GetSocketFd(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TLSGetSocketFdContext>(env, info, FUNCTION_GET_SOCKET_FD, nullptr,
                                                            TLSSocketAsyncWork::ExecGetSocketFd,
                                                            TLSSocketAsyncWork::GetSocketFdCallback);
}

void TLSSocketModuleExports::DefineTLSSocketClass(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> functions = {
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_GET_CERTIFICATE, TLSSocket::GetCertificate),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_GET_REMOTE_CERTIFICATE, TLSSocket::GetRemoteCertificate),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_GET_SIGNATURE_ALGORITHMS, TLSSocket::GetSignatureAlgorithms),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_GET_PROTOCOL, TLSSocket::GetProtocol),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_CONNECT, TLSSocket::Connect),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_GET_CIPHER_SUITE, TLSSocket::GetCipherSuites),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_SEND, TLSSocket::Send),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_CLOSE, TLSSocket::Close),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_BIND, TLSSocket::Bind),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_GET_STATE, TLSSocket::GetState),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_GET_REMOTE_ADDRESS, TLSSocket::GetRemoteAddress),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_GET_LOCAL_ADDRESS, TLSSocket::GetLocalAddress),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_SET_EXTRA_OPTIONS, TLSSocket::SetExtraOptions),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_ON, TLSSocket::On),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_OFF, TLSSocket::Off),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_GET_SOCKET_FD, TLSSocket::GetSocketFd),
    };
    ModuleTemplate::DefineClass(env, exports, functions, INTERFACE_TLS_SOCKET);
}

void TLSSocketModuleExports::InitProtocol(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_STATIC_PROPERTY(PROTOCOL_TLSV12, NapiUtils::CreateStringUtf8(env, PROTOCOL_TLS_V12)),
        DECLARE_NAPI_STATIC_PROPERTY(PROTOCOL_TLSV13, NapiUtils::CreateStringUtf8(env, PROTOCOL_TLS_V13)),
    };

    napi_value protocol = NapiUtils::CreateObject(env);
    NapiUtils::DefineProperties(env, protocol, properties);
    NapiUtils::SetNamedProperty(env, exports, INTERFACE_PROTOCOL, protocol);
}

napi_value TLSSocketModuleExports::ConstructTLSSocketInstance(napi_env env, napi_callback_info info)
{
    #ifndef CROSS_PLATFORM
    HiAppEventReport hiAppEventReport("NetworkKit", "TLSSocketConstructTLSSocketInstance");
    #endif
    napi_value result = ModuleTemplate::NewInstanceWithSharedManager(env, info, INTERFACE_TLS_SOCKET, Finalize);
    if (result == nullptr) {
        return nullptr;
    }

    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, nullptr, nullptr));
    if (paramsCount == 0) {
        return result;
    }

    std::shared_ptr<EventManager> *sharedManager = nullptr;
    auto napiRet = napi_unwrap(env, result, reinterpret_cast<void **>(&sharedManager));
    if (napiRet != napi_ok) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napiRet is %{public}d", napiRet);
        return nullptr;
    }
    std::shared_ptr<EventManager> manager = nullptr;
    if (sharedManager != nullptr && *sharedManager != nullptr) {
        manager = *sharedManager;
    }

    auto context = new TLSInitContext(env, manager);
    if (context == nullptr) {
        NETSTACK_LOGE("new TLSInitContext failed, no enough memory");
        return nullptr;
    }

    context->ParseParams(params, paramsCount);
    if (context->IsParseOK()) {
        TLSSocketAsyncWork::ExecInit(env, (void *)context);
    }

    if (context->IsNeedThrowException()) { // only api9 or later need throw exception.
        napi_throw_error(env, std::to_string(context->GetErrorCode()).c_str(), context->GetErrorMessage().c_str());
        delete context;
        return nullptr;
    }

    delete context;
    #ifndef CROSS_PLATFORM
    hiAppEventReport.ReportSdkEvent(RESULT_SUCCESS, ERR_NONE);
    #endif
    return result;
}

void TLSSocketModuleExports::InitTLSSocketProperties(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(FUNCTION_CONSTRUCTOR_TLS_SOCKET_INSTANCE, ConstructTLSSocketInstance),
    };
    NapiUtils::DefineProperties(env, exports, properties);
}

napi_value TLSSocketModuleExports::InitTLSSocketModule(napi_env env, napi_value exports)
{
    DefineTLSSocketClass(env, exports);
    InitTLSSocketProperties(env, exports);
    InitProtocol(env, exports);
    return exports;
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
