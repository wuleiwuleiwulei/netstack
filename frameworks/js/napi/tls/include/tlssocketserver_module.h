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

#ifndef TLS_TLSSOCKETSERVER_MODULE_H
#define TLS_TLSSOCKETSERVER_MODULE_H

#include <napi/native_api.h>

namespace OHOS {
namespace NetStack {
namespace TlsSocketServer {
class TLSSocketServerModuleExports {
public:
    class TLSSocketServer {
    public:
        static constexpr const char *FUNCTION_LISTEN = "listen";
        static constexpr const char *FUNCTION_STOP = "close";
        static constexpr const char *FUNCTION_GET_STATE = "getState";
        static constexpr const char *FUNCTION_GET_LOCAL_ADDRESS = "getLocalAddress";
        static constexpr const char *FUNCTION_SET_EXTRA_OPTIONS = "setExtraOptions";
        static constexpr const char *FUNCTION_ON = "on";
        static constexpr const char *FUNCTION_OFF = "off";
        static constexpr const char *FUNCTION_GET_CERTIFICATE = "getCertificate";
        static constexpr const char *FUNCTION_GET_PROTOCOL = "getProtocol";
        static constexpr const char *FUNCTION_GET_SOCKET_FD = "getSocketFd";

        static napi_value GetCertificate(napi_env env, napi_callback_info info);
        static napi_value GetProtocol(napi_env env, napi_callback_info info);
        static napi_value Listen(napi_env env, napi_callback_info info);
        static napi_value Stop(napi_env env, napi_callback_info info);
        static napi_value GetState(napi_env env, napi_callback_info info);
        static napi_value GetLocalAddress(napi_env env, napi_callback_info info);
        static napi_value SetExtraOptions(napi_env env, napi_callback_info info);
        static napi_value On(napi_env env, napi_callback_info info);
        static napi_value Off(napi_env env, napi_callback_info info);
        static napi_value GetSocketFd(napi_env env, napi_callback_info info);
    };

    class TLSSocketConnection {
    public:
        static constexpr const char *PROPERTY_CLIENT_ID = "clientId";
        static constexpr const char *FUNCTION_SEND = "send";
        static constexpr const char *FUNCTION_CLOSE = "close";
        static constexpr const char *FUNCTION_GET_REMOTE_ADDRESS = "getRemoteAddress";
        static constexpr const char *FUNCTION_GET_LOCAL_ADDRESS = "getLocalAddress";
        static constexpr const char *FUNCTION_GET_REMOTE_CERTIFICATE = "getRemoteCertificate";
        static constexpr const char *FUNCTION_GET_CERTIFICATE = "getCertificate";
        static constexpr const char *FUNCTION_GET_CIPHER_SUITE = "getCipherSuite";
        static constexpr const char *FUNCTION_GET_SIGNATURE_ALGORITHMS = "getSignatureAlgorithms";
        static constexpr const char *FUNCTION_ON = "on";
        static constexpr const char *FUNCTION_OFF = "off";
        static constexpr const char *FUNCTION_GET_SOCKET_FD = "getSocketFd";

        static napi_value Send(napi_env env, napi_callback_info info);
        static napi_value Close(napi_env env, napi_callback_info info);
        static napi_value GetRemoteAddress(napi_env env, napi_callback_info info);
        static napi_value GetLocalAddress(napi_env env, napi_callback_info info);
        static napi_value GetRemoteCertificate(napi_env env, napi_callback_info info);
        static napi_value GetCipherSuites(napi_env env, napi_callback_info info);
        static napi_value GetSignatureAlgorithms(napi_env env, napi_callback_info info);
        static napi_value On(napi_env env, napi_callback_info info);
        static napi_value Off(napi_env env, napi_callback_info info);
        static napi_value GetCertificate(napi_env env, napi_callback_info info);
        static napi_value GetSocketFd(napi_env env, napi_callback_info info);
    };

public:
    static constexpr const char *INTERFACE_TLS_SOCKET_SERVER = "TLSSocketServer";
    static constexpr const char *FUNCTION_CONSTRUCTOR_TLS_SOCKET_SERVER_INSTANCE = "constructTLSSocketServerInstance";
    static constexpr const char *INTERFACE_PROTOCOL = "Protocol";
    static constexpr const char *INTERFACE_TLS_SOCKET_SERVER_CONNECTION = "TLSSocketServerConnection";

    static napi_value InitTLSSocketServerModule(napi_env env, napi_value exports);

private:
    static napi_value ConstructTLSSocketServerInstance(napi_env env, napi_callback_info info);
    static void DefineTLSSocketServerClass(napi_env env, napi_value exports);
    static void InitTLSSocketServerProperties(napi_env env, napi_value exports);
    static void InitProtocol(napi_env env, napi_value exports);
    static void DefineTLSSocketConnectionClass(napi_env env, napi_value exports);
};
} // namespace TlsSocketServer
} // namespace NetStack
} // namespace OHOS
#endif // TLS_TLSSOCKETSERVER_MODULE_H
