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

#ifndef TLS_TLSSOCKETSERVER_EXEC_H
#define TLS_TLSSOCKETSERVER_EXEC_H

#include <napi/native_api.h>

#include "common_context.h"
#include "tls_bind_context.h"
#include "tls_connect_context.h"
#include "tls_extra_context.h"
#include "tls_napi_context.h"
#include "tls_server_close_context.h"
#include "tls_server_napi_context.h"
#include "tls_server_send_context.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocketServer {
class TLSSocketServerExec final {
public:
    TLSSocketServerExec() = delete;
    ~TLSSocketServerExec() = delete;

    static bool ExecGetCertificate(TlsSocket::GetCertificateContext *context);
    static bool ExecTLSConnectionGetSocketFd(TLSServerGetSocketFdContext *context);
    static bool ExecListen(TlsSocket::TLSListenContext *context);
    static bool ExecGetCipherSuites(ServerGetCipherSuitesContext *context);
    static bool ExecGetRemoteCertificate(ServerGetRemoteCertificateContext *context);
    static bool ExecGetProtocol(TlsSocket::GetProtocolContext *context);
    static bool ExecGetSignatureAlgorithms(ServerGetSignatureAlgorithmsContext *context);
    static bool ExecSend(TLSServerSendContext *context);
    static bool ExecClose(TLSServerCloseContext *context);
    static bool ExecStop(TlsSocket::TLSNapiContext *context);
    static bool ExecGetState(TlsSocket::TLSGetStateContext *context);
    static bool ExecGetRemoteAddress(ServerTLSGetRemoteAddressContext *context);
    static bool ExecGetLocalAddress(TLSServerGetLocalAddressContext *context);
    static bool ExecConnectionGetLocalAddress(TLSConnectionGetLocalAddressContext *context);
    static bool ExecSetExtraOptions(TlsSocket::TLSSetExtraOptionsContext *context);
    static bool ExecGetSocketFd(TlsSocket::TLSGetSocketFdContext *context);

    static napi_value GetCertificateCallback(TlsSocket::GetCertificateContext *context);
    static napi_value TLSConnectionGetSocketFdCallback(TLSServerGetSocketFdContext *context);
    static napi_value ListenCallback(TlsSocket::TLSListenContext *context);
    static napi_value GetCipherSuitesCallback(ServerGetCipherSuitesContext *context);
    static napi_value GetRemoteCertificateCallback(ServerGetRemoteCertificateContext *context);
    static napi_value GetProtocolCallback(TlsSocket::GetProtocolContext *context);
    static napi_value GetSignatureAlgorithmsCallback(ServerGetSignatureAlgorithmsContext *context);
    static napi_value SendCallback(TLSServerSendContext *context);
    static napi_value CloseCallback(TLSServerCloseContext *context);
    static napi_value StopCallback(TlsSocket::TLSNapiContext *context);
    static napi_value GetStateCallback(TlsSocket::TLSGetStateContext *context);
    static napi_value GetRemoteAddressCallback(ServerTLSGetRemoteAddressContext *context);
    static napi_value GetLocalAddressCallback(TLSServerGetLocalAddressContext *context);
    static napi_value GetConnectionLocalAddressCallback(TLSConnectionGetLocalAddressContext *context);
    static napi_value SetExtraOptionsCallback(TlsSocket::TLSSetExtraOptionsContext *context);
    static napi_value TLSSocketServerGetSocketFdCallback(TlsSocket::TLSGetSocketFdContext *context);

    static bool ExecConnectionSend(TLSServerSendContext *context);
    static napi_value ConnectionSendCallback(TLSServerSendContext *context);
};
} // namespace TlsSocketServer
} // namespace NetStack
} // namespace OHOS
#endif // TLS_TLSSOCKETSERVER_EXEC_H
