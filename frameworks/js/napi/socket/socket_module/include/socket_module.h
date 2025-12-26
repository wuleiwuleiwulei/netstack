/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_SOCKET_MODULE_H
#define COMMUNICATIONNETSTACK_SOCKET_MODULE_H

#include "napi/native_api.h"

namespace OHOS::NetStack::Socket {
class SocketModuleExports {
public:
    class UDPSocket {
    public:
        static constexpr const char *FUNCTION_BIND = "bind";
        static constexpr const char *FUNCTION_SEND = "send";
        static constexpr const char *FUNCTION_CLOSE = "close";
        static constexpr const char *FUNCTION_GET_STATE = "getState";
        static constexpr const char *FUNCTION_GET_LOCAL_ADDRESS = "getLocalAddress";
        static constexpr const char *FUNCTION_SET_EXTRA_OPTIONS = "setExtraOptions";
        static constexpr const char *FUNCTION_GET_SOCKET_FD = "getSocketFd";
        static constexpr const char *FUNCTION_ON = "on";
        static constexpr const char *FUNCTION_OFF = "off";

        static napi_value Bind(napi_env env, napi_callback_info info);
        static napi_value Send(napi_env env, napi_callback_info info);
        static napi_value Close(napi_env env, napi_callback_info info);
        static napi_value GetState(napi_env env, napi_callback_info info);
        static napi_value GetLocalAddress(napi_env env, napi_callback_info info);
        static napi_value SetExtraOptions(napi_env env, napi_callback_info info);
        static napi_value GetSocketFd(napi_env env, napi_callback_info info);
        static napi_value On(napi_env env, napi_callback_info info);
        static napi_value Off(napi_env env, napi_callback_info info);
    };

    class MulticastSocket : public UDPSocket {
    public:
        static constexpr char FUNCTION_ADD_MEMBER_SHIP[] = "addMembership";
        static constexpr char FUNCTION_DROP_MEMBER_SHIP[] = "dropMembership";
        static constexpr char FUNCTION_SET_MULTICAST_TTL[] = "setMulticastTTL";
        static constexpr char FUNCTION_GET_MULTICAST_TTL[] = "getMulticastTTL";
        static constexpr char FUNCTION_SET_LOOPBACK_MODE[] = "setLoopbackMode";
        static constexpr char FUNCTION_GET_LOOPBACK_MODE[] = "getLoopbackMode";

        static napi_value AddMembership(napi_env env, napi_callback_info info);
        static napi_value DropMembership(napi_env env, napi_callback_info info);
        static napi_value GetLocalAddress(napi_env env, napi_callback_info info);
        static napi_value SetMulticastTTL(napi_env env, napi_callback_info info);
        static napi_value GetMulticastTTL(napi_env env, napi_callback_info info);
        static napi_value SetLoopbackMode(napi_env env, napi_callback_info info);
        static napi_value GetLoopbackMode(napi_env env, napi_callback_info info);
    };

    class LocalSocket {
    public:
        static constexpr char FUNCTION_BIND[] = "bind";
        static constexpr char FUNCTION_CONNECT[] = "connect";
        static constexpr char FUNCTION_SEND[] = "send";
        static constexpr char FUNCTION_CLOSE[] = "close";
        static constexpr char FUNCTION_GET_STATE[] = "getState";
        static constexpr char FUNCTION_GET_LOCAL_ADDRESS[] = "getLocalAddress";
        static constexpr char FUNCTION_GET_SOCKET_FD[] = "getSocketFd";
        static constexpr char FUNCTION_SET_EXTRA_OPTIONS[] = "setExtraOptions";
        static constexpr char FUNCTION_GET_EXTRA_OPTIONS[] = "getExtraOptions";
        static constexpr char FUNCTION_ON[] = "on";
        static constexpr char FUNCTION_OFF[] = "off";

        static napi_value Bind(napi_env env, napi_callback_info info);
        static napi_value Connect(napi_env env, napi_callback_info info);
        static napi_value Send(napi_env env, napi_callback_info info);
        static napi_value Close(napi_env env, napi_callback_info info);
        static napi_value GetState(napi_env env, napi_callback_info info);
        static napi_value GetLocalAddress(napi_env env, napi_callback_info info);
        static napi_value GetSocketFd(napi_env env, napi_callback_info info);
        static napi_value SetExtraOptions(napi_env env, napi_callback_info info);
        static napi_value GetExtraOptions(napi_env env, napi_callback_info info);
        static napi_value On(napi_env env, napi_callback_info info);
        static napi_value Off(napi_env env, napi_callback_info info);
    };

    class LocalSocketServer {
    public:
        static constexpr char FUNCTION_LISTEN[] = "listen";
        static constexpr char FUNCTION_CLOSE[] = "close";
        static constexpr char FUNCTION_GET_STATE[] = "getState";
        static constexpr char FUNCTION_GET_LOCAL_ADDRESS[] = "getLocalAddress";
        static constexpr char FUNCTION_SET_EXTRA_OPTIONS[] = "setExtraOptions";
        static constexpr char FUNCTION_GET_EXTRA_OPTIONS[] = "getExtraOptions";
        static constexpr char FUNCTION_GET_SOCKET_FD[] = "getSocketFd";
        static constexpr char FUNCTION_ON[] = "on";
        static constexpr char FUNCTION_OFF[] = "off";

        static napi_value Listen(napi_env env, napi_callback_info info);
        static napi_value Close(napi_env env, napi_callback_info info);
        static napi_value GetState(napi_env env, napi_callback_info info);
        static napi_value GetLocalAddress(napi_env env, napi_callback_info info);
        static napi_value SetExtraOptions(napi_env env, napi_callback_info info);
        static napi_value GetExtraOptions(napi_env env, napi_callback_info info);
        static napi_value GetSocketFd(napi_env env, napi_callback_info info);
        static napi_value On(napi_env env, napi_callback_info info);
        static napi_value Off(napi_env env, napi_callback_info info);
    };

    class LocalSocketConnection {
    public:
        static constexpr char PROPERTY_CLIENT_ID[] = "clientId";
        static constexpr char FUNCTION_SEND[] = "send";
        static constexpr char FUNCTION_CLOSE[] = "close";
        static constexpr char FUNCTION_GET_SOCKET_FD[] = "getSocketFd";
        static constexpr char FUNCTION_ON[] = "on";
        static constexpr char FUNCTION_OFF[] = "off";

        static napi_value Send(napi_env env, napi_callback_info info);
        static napi_value Close(napi_env env, napi_callback_info info);
        static napi_value GetLocalAddress(napi_env env, napi_callback_info info);
        static napi_value GetSocketFd(napi_env env, napi_callback_info info);
        static napi_value On(napi_env env, napi_callback_info info);
        static napi_value Off(napi_env env, napi_callback_info info);
    };

    class TCPSocket {
    public:
        static constexpr const char *FUNCTION_BIND = "bind";
        static constexpr const char *FUNCTION_CONNECT = "connect";
        static constexpr const char *FUNCTION_SEND = "send";
        static constexpr const char *FUNCTION_CLOSE = "close";
        static constexpr const char *FUNCTION_GET_REMOTE_ADDRESS = "getRemoteAddress";
        static constexpr const char *FUNCTION_GET_LOCAL_ADDRESS = "getLocalAddress";
        static constexpr const char *FUNCTION_GET_STATE = "getState";
        static constexpr const char *FUNCTION_SET_EXTRA_OPTIONS = "setExtraOptions";
        static constexpr const char *FUNCTION_GET_SOCKET_FD = "getSocketFd";
        static constexpr const char *FUNCTION_ON = "on";
        static constexpr const char *FUNCTION_OFF = "off";

        static napi_value Bind(napi_env env, napi_callback_info info);
        static napi_value Connect(napi_env env, napi_callback_info info);
        static napi_value Send(napi_env env, napi_callback_info info);
        static napi_value Close(napi_env env, napi_callback_info info);
        static napi_value GetRemoteAddress(napi_env env, napi_callback_info info);
        static napi_value GetLocalAddress(napi_env env, napi_callback_info info);
        static napi_value GetState(napi_env env, napi_callback_info info);
        static napi_value SetExtraOptions(napi_env env, napi_callback_info info);
        static napi_value GetSocketFd(napi_env env, napi_callback_info info);
        static napi_value On(napi_env env, napi_callback_info info);
        static napi_value Off(napi_env env, napi_callback_info info);
    };

    class TCPConnection {
    public:
        static constexpr const char *PROPERTY_CLIENT_ID = "clientId";
        static constexpr const char *FUNCTION_SEND = "send";
        static constexpr const char *FUNCTION_CLOSE = "close";
        static constexpr const char *FUNCTION_GET_REMOTE_ADDRESS = "getRemoteAddress";
        static constexpr const char *FUNCTION_GET_LOCAL_ADDRESS = "getLocalAddress";
        static constexpr const char *FUNCTION_GET_SOCKET_FD = "getSocketFd";
        static constexpr const char *FUNCTION_ON = "on";
        static constexpr const char *FUNCTION_OFF = "off";

        static napi_value Send(napi_env env, napi_callback_info info);
        static napi_value Close(napi_env env, napi_callback_info info);
        static napi_value GetRemoteAddress(napi_env env, napi_callback_info info);
        static napi_value GetLocalAddress(napi_env env, napi_callback_info info);
        static napi_value GetSocketFd(napi_env env, napi_callback_info info);
        static napi_value On(napi_env env, napi_callback_info info);
        static napi_value Off(napi_env env, napi_callback_info info);
    };

    class TCPServerSocket {
    public:
        static constexpr const char *FUNCTION_LISTEN = "listen";
        static constexpr const char *FUNCTION_CLOSE = "close";
        static constexpr const char *FUNCTION_GET_STATE = "getState";
        static constexpr const char *FUNCTION_GET_LOCAL_ADDRESS = "getLocalAddress";
        static constexpr const char *FUNCTION_SET_EXTRA_OPTIONS = "setExtraOptions";
        static constexpr const char *FUNCTION_GET_SOCKET_FD = "getSocketFd";
        static constexpr const char *FUNCTION_ON = "on";
        static constexpr const char *FUNCTION_OFF = "off";

        static napi_value Listen(napi_env env, napi_callback_info info);
        static napi_value Close(napi_env env, napi_callback_info info);
        static napi_value GetState(napi_env env, napi_callback_info info);
        static napi_value GetLocalAddress(napi_env env, napi_callback_info info);
        static napi_value SetExtraOptions(napi_env env, napi_callback_info info);
        static napi_value GetSocketFd(napi_env env, napi_callback_info info);
        static napi_value On(napi_env env, napi_callback_info info);
        static napi_value Off(napi_env env, napi_callback_info info);
    };

    static constexpr const char *FUNCTION_CONSTRUCTOR_UDP_SOCKET_INSTANCE = "constructUDPSocketInstance";
    static constexpr const char *FUNCTION_CONSTRUCTOR_MULTICAST_SOCKET_INSTANCE = "constructMulticastSocketInstance";
    static constexpr const char *FUNCTION_CONSTRUCTOR_TCP_SOCKET_INSTANCE = "constructTCPSocketInstance";
    static constexpr const char *FUNCTION_CONSTRUCTOR_TCP_SOCKET_SERVER_INSTANCE = "constructTCPSocketServerInstance";
    static constexpr const char *FUNCTION_CONSTRUCTOR_LOCAL_SOCKET_INSTANCE = "constructLocalSocketInstance";
    static constexpr const char *FUNCTION_CONSTRUCTOR_LOCAL_SOCKET_SERVER_INSTANCE =
        "constructLocalSocketServerInstance";
    static constexpr const char *INTERFACE_UDP_SOCKET = "UDPSocket";
    static constexpr const char *INTERFACE_MULTICAST_SOCKET = "MulticastSocket";
    static constexpr const char *INTERFACE_TCP_SOCKET = "TCPSocket";
    static constexpr const char *INTERFACE_TCP_SOCKET_SERVER = "TCPSocketServer";
    static constexpr const char *INTERFACE_LOCAL_SOCKET = "LocalSocket";
    static constexpr const char *INTERFACE_LOCAL_SOCKET_SERVER = "LocalSocketServer";

    static napi_value InitSocketModule(napi_env env, napi_value exports);

private:
    static napi_value ConstructUDPSocketInstance(napi_env env, napi_callback_info info);

    static napi_value ConstructMulticastSocketInstance(napi_env env, napi_callback_info info);

    static napi_value ConstructTCPSocketInstance(napi_env env, napi_callback_info info);

    static napi_value ConstructTCPSocketServerInstance(napi_env env, napi_callback_info info);

    static napi_value ConstructLocalSocketInstance(napi_env env, napi_callback_info info);

    static napi_value ConstructLocalSocketServerInstance(napi_env env, napi_callback_info info);

    static void DefineUDPSocketClass(napi_env env, napi_value exports);

    static void DefineMulticastSocketClass(napi_env env, napi_value exports);

    static void DefineTCPSocketClass(napi_env env, napi_value exports);

    static void DefineTCPServerSocketClass(napi_env env, napi_value exports);

    static void DefineLocalSocketClass(napi_env env, napi_value exports);

    static void DefineLocalSocketServerClass(napi_env env, napi_value exports);

    static void InitSocketProperties(napi_env env, napi_value exports);

    static void InitSocketProxyProperties(napi_env env, napi_value exports);
};
} // namespace OHOS::NetStack::Socket
#endif // COMMUNICATIONNETSTACK_SOCKET_MODULE_H
