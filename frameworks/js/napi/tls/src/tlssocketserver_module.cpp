/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "tlssocketserver_module.h"

#include <initializer_list>
#include <napi/native_common.h>

#include "common_context.h"
#include "event_manager.h"
#include "module_template.h"
#include "monitor_server.h"
#include "napi_utils.h"
#include "netstack_log.h"
#include "tls.h"
#include "tls_bind_context.h"
#include "tls_connect_context.h"
#include "tls_extra_context.h"
#include "tls_napi_context.h"
#include "tls_server_close_context.h"
#include "tls_server_napi_context.h"
#include "tls_server_send_context.h"
#include "tlssocketserver_async_work.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocketServer {
namespace {
static constexpr const char *PROTOCOL_TLSV13 = "TLSv13";
static constexpr const char *PROTOCOL_TLSV12 = "TLSv12";
static constexpr const char *NAME_STOP_SERVER = "closeTLSServer";

void Finalize(napi_env, void *data, void *)
{
    NETSTACK_LOGI("tls socket server is finalized");
    auto sharedManager = reinterpret_cast<std::shared_ptr<EventManager> *>(data);
    delete sharedManager;
}
} // namespace

napi_value TLSSocketServerModuleExports::TLSSocketServer::GetCertificate(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TlsSocket::GetCertificateContext>(
        env, info, FUNCTION_GET_CERTIFICATE, nullptr, TLSSocketServerAsyncWork::ExecGetCertificate,
        TLSSocketServerAsyncWork::GetCertificateCallback);
}

napi_value TLSSocketServerModuleExports::TLSSocketServer::GetProtocol(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TlsSocket::GetProtocolContext>(env, info, FUNCTION_GET_PROTOCOL,
        nullptr, TLSSocketServerAsyncWork::ExecGetProtocol, TLSSocketServerAsyncWork::GetProtocolCallback);
}

napi_value TLSSocketServerModuleExports::TLSSocketServer::Listen(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TlsSocket::TLSListenContext>(env, info, FUNCTION_LISTEN, nullptr,
                                                                  TLSSocketServerAsyncWork::ExecListen,
                                                                  TLSSocketServerAsyncWork::ListenCallback);
}

napi_value TLSSocketServerModuleExports::TLSSocketServer::Stop(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TlsSocket::TLSNapiContext>(env, info, NAME_STOP_SERVER, nullptr,
                                                                  TLSSocketServerAsyncWork::ExecStop,
                                                                  TLSSocketServerAsyncWork::StopCallback);
}

napi_value TLSSocketServerModuleExports::TLSSocketConnection::Send(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TLSServerSendContext>(
        env, info, FUNCTION_SEND,
        [](napi_env theEnv, napi_value thisVal, TLSServerSendContext *context) -> bool {
            context->clientId_ = NapiUtils::GetInt32Property(theEnv, thisVal, PROPERTY_CLIENT_ID);
            return true;
        },
        TLSSocketServerAsyncWork::ExecSend, TLSSocketServerAsyncWork::SendCallback);
}

napi_value TLSSocketServerModuleExports::TLSSocketConnection::Close(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TLSServerCloseContext>(
        env, info, FUNCTION_CLOSE,
        [](napi_env theEnv, napi_value thisVal, TLSServerCloseContext *context) -> bool {
            context->clientId_ = NapiUtils::GetInt32Property(theEnv, thisVal, PROPERTY_CLIENT_ID);
            return true;
        },
        TLSSocketServerAsyncWork::ExecClose, TLSSocketServerAsyncWork::CloseCallback);
}

napi_value TLSSocketServerModuleExports::TLSSocketConnection::GetRemoteAddress(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<ServerTLSGetRemoteAddressContext>(
        env, info, FUNCTION_GET_REMOTE_ADDRESS,
        [](napi_env theEnv, napi_value thisVal, ServerTLSGetRemoteAddressContext *context) -> bool {
            context->clientId_ = NapiUtils::GetInt32Property(theEnv, thisVal, PROPERTY_CLIENT_ID);
            return true;
        },
        TLSSocketServerAsyncWork::ExecGetRemoteAddress, TLSSocketServerAsyncWork::GetRemoteAddressCallback);
}

napi_value TLSSocketServerModuleExports::TLSSocketConnection::GetLocalAddress(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TLSServerGetLocalAddressContext>(
        env, info, FUNCTION_GET_LOCAL_ADDRESS,
        [](napi_env theEnv, napi_value thisVal, TLSServerGetLocalAddressContext *context) -> bool {
            context->clientId_ = NapiUtils::GetInt32Property(theEnv, thisVal, PROPERTY_CLIENT_ID);
            return true;
        },
        TLSSocketServerAsyncWork::ExecConnectionGetLocalAddress,
            TLSSocketServerAsyncWork::GetConnectionLocalAddressCallback);
}

napi_value TLSSocketServerModuleExports::TLSSocketConnection::GetRemoteCertificate(napi_env env,
                                                                                   napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<ServerGetRemoteCertificateContext>(
        env, info, FUNCTION_GET_REMOTE_CERTIFICATE,
        [](napi_env theEnv, napi_value thisVal, ServerGetRemoteCertificateContext *context) -> bool {
            context->clientId_ = NapiUtils::GetInt32Property(theEnv, thisVal, PROPERTY_CLIENT_ID);
            return true;
        },
        TLSSocketServerAsyncWork::ExecGetRemoteCertificate, TLSSocketServerAsyncWork::GetRemoteCertificateCallback);
}

napi_value TLSSocketServerModuleExports::TLSSocketConnection::GetCipherSuites(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<ServerGetCipherSuitesContext>(
        env, info, FUNCTION_GET_CIPHER_SUITE,
        [](napi_env theEnv, napi_value thisVal, ServerGetCipherSuitesContext *context) -> bool {
            context->clientId_ = NapiUtils::GetInt32Property(theEnv, thisVal, PROPERTY_CLIENT_ID);
            return true;
        },
        TLSSocketServerAsyncWork::ExecGetCipherSuites, TLSSocketServerAsyncWork::GetCipherSuitesCallback);
}

napi_value TLSSocketServerModuleExports::TLSSocketConnection::GetSignatureAlgorithms(napi_env env,
                                                                                     napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<ServerGetSignatureAlgorithmsContext>(
        env, info, FUNCTION_GET_SIGNATURE_ALGORITHMS,
        [](napi_env theEnv, napi_value thisVal, ServerGetSignatureAlgorithmsContext *context) -> bool {
            context->clientId_ = NapiUtils::GetInt32Property(theEnv, thisVal, PROPERTY_CLIENT_ID);
            return true;
        },
        TLSSocketServerAsyncWork::ExecGetSignatureAlgorithms, TLSSocketServerAsyncWork::GetSignatureAlgorithmsCallback);
}

napi_value TLSSocketServerModuleExports::TLSSocketConnection::On(napi_env env, napi_callback_info info)
{
    return DelayedSingleton<MonitorServer>::GetInstance()->ConnectionOn(env, info);
}

napi_value TLSSocketServerModuleExports::TLSSocketConnection::Off(napi_env env, napi_callback_info info)
{
    return DelayedSingleton<MonitorServer>::GetInstance()->ConnectionOff(env, info);
}

napi_value TLSSocketServerModuleExports::TLSSocketConnection::GetCertificate(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TlsSocket::GetCertificateContext>(
        env, info, FUNCTION_GET_CERTIFICATE, nullptr, TLSSocketServerAsyncWork::ExecGetCertificate,
        TLSSocketServerAsyncWork::GetCertificateCallback);
}

napi_value TLSSocketServerModuleExports::TLSSocketConnection::GetSocketFd(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TLSServerGetSocketFdContext>(
        env, info, FUNCTION_GET_SOCKET_FD,
        [](napi_env theEnv, napi_value thisVal, TLSServerGetSocketFdContext *context) -> bool {
            context->clientId_ = NapiUtils::GetInt32Property(theEnv, thisVal, PROPERTY_CLIENT_ID);
            return true;
        },
        TLSSocketServerAsyncWork::ExecTLSConnectionGetSocketFd,
            TLSSocketServerAsyncWork::TLSConnectionGetSocketFdCallback);
}

napi_value TLSSocketServerModuleExports::TLSSocketServer::GetState(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TlsSocket::TLSGetStateContext>(env, info, FUNCTION_GET_STATE,
        nullptr, TLSSocketServerAsyncWork::ExecGetState, TLSSocketServerAsyncWork::GetStateCallback);
}

napi_value TLSSocketServerModuleExports::TLSSocketServer::GetLocalAddress(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TLSServerGetLocalAddressContext>(
        env, info, FUNCTION_GET_LOCAL_ADDRESS, nullptr, TLSSocketServerAsyncWork::ExecGetLocalAddress,
        TLSSocketServerAsyncWork::GetLocalAddressCallback);
}

napi_value TLSSocketServerModuleExports::TLSSocketServer::SetExtraOptions(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TlsSocket::TLSSetExtraOptionsContext>(
        env, info, FUNCTION_SET_EXTRA_OPTIONS, nullptr, TLSSocketServerAsyncWork::ExecSetExtraOptions,
        TLSSocketServerAsyncWork::SetExtraOptionsCallback);
}

napi_value TLSSocketServerModuleExports::TLSSocketServer::On(napi_env env, napi_callback_info info)
{
    return DelayedSingleton<MonitorServer>::GetInstance()->On(env, info);
}

napi_value TLSSocketServerModuleExports::TLSSocketServer::Off(napi_env env, napi_callback_info info)
{
    return DelayedSingleton<MonitorServer>::GetInstance()->Off(env, info);
}

napi_value TLSSocketServerModuleExports::TLSSocketServer::GetSocketFd(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<TlsSocket::TLSGetSocketFdContext>(
        env, info, FUNCTION_GET_SOCKET_FD, nullptr, TLSSocketServerAsyncWork::ExecTLSSocketServerGetSocketFd,
        TLSSocketServerAsyncWork::TLSSocketServerGetSocketFdCallback);
}

void TLSSocketServerModuleExports::DefineTLSSocketServerClass(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> functions = {
        DECLARE_NAPI_FUNCTION(TLSSocketServer::FUNCTION_LISTEN, TLSSocketServer::Listen),
        DECLARE_NAPI_FUNCTION(TLSSocketServer::FUNCTION_STOP, TLSSocketServer::Stop),
        DECLARE_NAPI_FUNCTION(TLSSocketServer::FUNCTION_GET_STATE, TLSSocketServer::GetState),
        DECLARE_NAPI_FUNCTION(TLSSocketServer::FUNCTION_GET_LOCAL_ADDRESS, TLSSocketServer::GetLocalAddress),
        DECLARE_NAPI_FUNCTION(TLSSocketServer::FUNCTION_SET_EXTRA_OPTIONS, TLSSocketServer::SetExtraOptions),
        DECLARE_NAPI_FUNCTION(TLSSocketServer::FUNCTION_ON, TLSSocketServer::On),
        DECLARE_NAPI_FUNCTION(TLSSocketServer::FUNCTION_OFF, TLSSocketServer::Off),
        DECLARE_NAPI_FUNCTION(TLSSocketServer::FUNCTION_GET_SOCKET_FD, TLSSocketServer::GetSocketFd),
        DECLARE_NAPI_FUNCTION(TLSSocketServer::FUNCTION_GET_CERTIFICATE, TLSSocketServer::GetCertificate),
        DECLARE_NAPI_FUNCTION(TLSSocketServer::FUNCTION_GET_PROTOCOL, TLSSocketServer::GetProtocol),
    };
    ModuleTemplate::DefineClass(env, exports, functions, INTERFACE_TLS_SOCKET_SERVER);
}

void TLSSocketServerModuleExports::InitProtocol(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_STATIC_PROPERTY(PROTOCOL_TLSV12, NapiUtils::CreateStringUtf8(env, TlsSocket::PROTOCOL_TLS_V12)),
        DECLARE_NAPI_STATIC_PROPERTY(PROTOCOL_TLSV13, NapiUtils::CreateStringUtf8(env, TlsSocket::PROTOCOL_TLS_V13)),
    };

    napi_value protocol = NapiUtils::CreateObject(env);
    NapiUtils::DefineProperties(env, protocol, properties);
    NapiUtils::SetNamedProperty(env, exports, INTERFACE_PROTOCOL, protocol);
}

void TlsSocketServer::TLSSocketServerModuleExports::DefineTLSSocketConnectionClass(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> functions = {
        DECLARE_NAPI_FUNCTION(TLSSocketConnection::FUNCTION_GET_CERTIFICATE, TLSSocketConnection::GetCertificate),
        DECLARE_NAPI_FUNCTION(TLSSocketConnection::FUNCTION_GET_SOCKET_FD, TLSSocketConnection::GetSocketFd),
        DECLARE_NAPI_FUNCTION(TLSSocketConnection::FUNCTION_GET_REMOTE_CERTIFICATE,
                              TLSSocketConnection::GetRemoteCertificate),
        DECLARE_NAPI_FUNCTION(TLSSocketConnection::FUNCTION_GET_SIGNATURE_ALGORITHMS,
                              TLSSocketConnection::GetSignatureAlgorithms),
        DECLARE_NAPI_FUNCTION(TLSSocketConnection::FUNCTION_GET_CIPHER_SUITE, TLSSocketConnection::GetCipherSuites),
        DECLARE_NAPI_FUNCTION(TLSSocketConnection::FUNCTION_SEND, TLSSocketConnection::Send),
        DECLARE_NAPI_FUNCTION(TLSSocketConnection::FUNCTION_CLOSE, TLSSocketConnection::Close),
        DECLARE_NAPI_FUNCTION(TLSSocketConnection::FUNCTION_GET_REMOTE_ADDRESS, TLSSocketConnection::GetRemoteAddress),
        DECLARE_NAPI_FUNCTION(TLSSocketConnection::FUNCTION_GET_LOCAL_ADDRESS, TLSSocketConnection::GetLocalAddress),
        DECLARE_NAPI_FUNCTION(TLSSocketConnection::FUNCTION_ON, TLSSocketConnection::On),
        DECLARE_NAPI_FUNCTION(TLSSocketConnection::FUNCTION_OFF, TLSSocketConnection::Off),
    };
    ModuleTemplate::DefineClass(env, exports, functions, INTERFACE_TLS_SOCKET_SERVER_CONNECTION);
}

napi_value TLSSocketServerModuleExports::ConstructTLSSocketServerInstance(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::NewInstanceWithSharedManager(env, info, INTERFACE_TLS_SOCKET_SERVER, Finalize);
}

void TLSSocketServerModuleExports::InitTLSSocketServerProperties(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(FUNCTION_CONSTRUCTOR_TLS_SOCKET_SERVER_INSTANCE, ConstructTLSSocketServerInstance),
    };
    NapiUtils::DefineProperties(env, exports, properties);
}

napi_value TLSSocketServerModuleExports::InitTLSSocketServerModule(napi_env env, napi_value exports)
{
    DefineTLSSocketServerClass(env, exports);
    DefineTLSSocketConnectionClass(env, exports);
    InitTLSSocketServerProperties(env, exports);
    InitProtocol(env, exports);
    return exports;
}

} // namespace TlsSocketServer
} // namespace NetStack
} // namespace OHOS
