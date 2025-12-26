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

#include "tlssocketserver_async_work.h"

#include "base_async_work.h"
#include "common_context.h"
#include "netstack_log.h"
#include "tls_bind_context.h"
#include "tls_connect_context.h"
#include "tls_extra_context.h"
#include "tls_napi_context.h"
#include "tls_server_close_context.h"
#include "tls_server_napi_context.h"
#include "tls_server_send_context.h"
#include "tlssocketserver_exec.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocketServer {
void TLSSocketServerAsyncWork::ExecGetCertificate(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TlsSocket::GetCertificateContext, TLSSocketServerExec::ExecGetCertificate>(env, data);
}

void TLSSocketServerAsyncWork::ExecTLSConnectionGetSocketFd(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TLSServerGetSocketFdContext,
        TLSSocketServerExec::ExecTLSConnectionGetSocketFd>(env, data);
}

void TLSSocketServerAsyncWork::ExecListen(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TlsSocket::TLSListenContext, TLSSocketServerExec::ExecListen>(env, data);
}

void TLSSocketServerAsyncWork::ExecGetCipherSuites(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<ServerGetCipherSuitesContext, TLSSocketServerExec::ExecGetCipherSuites>(env, data);
}

void TLSSocketServerAsyncWork::ExecGetRemoteCertificate(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<ServerGetRemoteCertificateContext, TLSSocketServerExec::ExecGetRemoteCertificate>(
        env, data);
}

void TLSSocketServerAsyncWork::ExecGetProtocol(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TlsSocket::GetProtocolContext, TLSSocketServerExec::ExecGetProtocol>(env, data);
}

void TLSSocketServerAsyncWork::ExecGetSignatureAlgorithms(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<ServerGetSignatureAlgorithmsContext, TLSSocketServerExec::ExecGetSignatureAlgorithms>(
        env, data);
}

void TLSSocketServerAsyncWork::ExecSend(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TLSServerSendContext, TLSSocketServerExec::ExecSend>(env, data);
}

void TLSSocketServerAsyncWork::ExecClose(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TLSServerCloseContext, TLSSocketServerExec::ExecClose>(env, data);
}

void TLSSocketServerAsyncWork::ExecStop(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TlsSocket::TLSNapiContext, TLSSocketServerExec::ExecStop>(env, data);
}

void TLSSocketServerAsyncWork::ExecGetState(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TlsSocket::TLSGetStateContext, TLSSocketServerExec::ExecGetState>(env, data);
}

void TLSSocketServerAsyncWork::ExecGetRemoteAddress(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<ServerTLSGetRemoteAddressContext, TLSSocketServerExec::ExecGetRemoteAddress>(env,
                                                                                                              data);
}

void TLSSocketServerAsyncWork::ExecConnectionGetLocalAddress(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TLSConnectionGetLocalAddressContext,
        TLSSocketServerExec::ExecConnectionGetLocalAddress>(env, data);
}

void TLSSocketServerAsyncWork::ExecGetLocalAddress(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TLSServerGetLocalAddressContext,
                                 TLSSocketServerExec::ExecGetLocalAddress>(env, data);
}

void TLSSocketServerAsyncWork::ExecSetExtraOptions(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TlsSocket::TLSSetExtraOptionsContext, TLSSocketServerExec::ExecSetExtraOptions>(env,
                                                                                                                 data);
}

void TLSSocketServerAsyncWork::ExecTLSSocketServerGetSocketFd(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TlsSocket::TLSGetSocketFdContext, TLSSocketServerExec::ExecGetSocketFd>(env, data);
}

void TLSSocketServerAsyncWork::GetCertificateCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TlsSocket::GetCertificateContext, TLSSocketServerExec::GetCertificateCallback>(
        env, status, data);
}

void TLSSocketServerAsyncWork::TLSConnectionGetSocketFdCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TLSServerGetSocketFdContext,
        TLSSocketServerExec::TLSConnectionGetSocketFdCallback>(env, status, data);
}

void TLSSocketServerAsyncWork::ListenCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TlsSocket::TLSListenContext, TLSSocketServerExec::ListenCallback>(env, status,
                                                                                                       data);
}

void TLSSocketServerAsyncWork::GetCipherSuitesCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<ServerGetCipherSuitesContext, TLSSocketServerExec::GetCipherSuitesCallback>(
        env, status, data);
}

void TLSSocketServerAsyncWork::GetRemoteCertificateCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<ServerGetRemoteCertificateContext,
                                     TLSSocketServerExec::GetRemoteCertificateCallback>(env, status, data);
}

void TLSSocketServerAsyncWork::GetProtocolCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TlsSocket::GetProtocolContext, TLSSocketServerExec::GetProtocolCallback>(
        env, status, data);
}

void TLSSocketServerAsyncWork::GetSignatureAlgorithmsCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<ServerGetSignatureAlgorithmsContext,
                                     TLSSocketServerExec::GetSignatureAlgorithmsCallback>(env, status, data);
}

void TLSSocketServerAsyncWork::SendCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TLSServerSendContext, TLSSocketServerExec::SendCallback>(env, status, data);
}

void TLSSocketServerAsyncWork::CloseCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TLSServerCloseContext, TLSSocketServerExec::CloseCallback>(env, status, data);
}

void TLSSocketServerAsyncWork::StopCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TlsSocket::TLSNapiContext, TLSSocketServerExec::StopCallback>(env, status, data);
}

void TLSSocketServerAsyncWork::GetStateCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TlsSocket::TLSGetStateContext, TLSSocketServerExec::GetStateCallback>(env, status,
                                                                                                           data);
}

void TLSSocketServerAsyncWork::GetRemoteAddressCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<ServerTLSGetRemoteAddressContext, TLSSocketServerExec::GetRemoteAddressCallback>(
        env, status, data);
}

void TLSSocketServerAsyncWork::GetConnectionLocalAddressCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TLSConnectionGetLocalAddressContext,
        TLSSocketServerExec::GetConnectionLocalAddressCallback>(env, status, data);
}

void TLSSocketServerAsyncWork::GetLocalAddressCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TLSServerGetLocalAddressContext, TLSSocketServerExec::GetLocalAddressCallback>(
        env, status, data);
}

void TLSSocketServerAsyncWork::SetExtraOptionsCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TlsSocket::TLSSetExtraOptionsContext,
                                     TLSSocketServerExec::SetExtraOptionsCallback>(env, status, data);
}

void TLSSocketServerAsyncWork::TLSSocketServerGetSocketFdCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TlsSocket::TLSGetSocketFdContext,
                                     TLSSocketServerExec::TLSSocketServerGetSocketFdCallback>(env, status, data);
}

} // namespace TlsSocketServer
} // namespace NetStack
} // namespace OHOS
