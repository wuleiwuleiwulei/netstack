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

#ifndef COMMUNICATIONNETSTACK_SOCKET_ASYNC_WORK_H
#define COMMUNICATIONNETSTACK_SOCKET_ASYNC_WORK_H

#include "napi/native_api.h"
#include "nocopyable.h"

namespace OHOS::NetStack::Socket {
class SocketAsyncWork final {
public:
    DISALLOW_COPY_AND_MOVE(SocketAsyncWork);

    /* executor */
    static void ExecUdpBind(napi_env env, void *data);

    static void ExecUdpSend(napi_env env, void *data);

    static void ExecUdpAddMembership(napi_env env, void *data);

    static void ExecUdpDropMembership(napi_env env, void *data);

    static void ExecSetMulticastTTL(napi_env env, void *data);

    static void ExecGetMulticastTTL(napi_env env, void *data);

    static void ExecSetLoopbackMode(napi_env env, void *data);

    static void ExecGetLoopbackMode(napi_env env, void *data);

    static void ExecTcpBind(napi_env env, void *data);

    static void ExecConnect(napi_env env, void *data);

    static void ExecTcpSend(napi_env env, void *data);

    static void ExecClose(napi_env env, void *data);

    static void ExecGetState(napi_env env, void *data);

    static void ExecGetRemoteAddress(napi_env env, void *data);

    static void ExecGetLocalAddress(napi_env env, void *data);

    static void ExecTcpSetExtraOptions(napi_env env, void *data);

    static void ExecUdpSetExtraOptions(napi_env env, void *data);

    static void ExecTcpGetSocketFd(napi_env env, void *data);

    static void ExecUdpGetSocketFd(napi_env env, void *data);

    static void ExecTcpConnectionSend(napi_env env, void *data);

    static void ExecTcpConnectionGetRemoteAddress(napi_env env, void *data);

    static void ExecTcpConnectionGetLocalAddress(napi_env env, void *data);

    static void ExecTcpConnectionGetSocketFd(napi_env env, void *data);

    static void ExecTcpConnectionClose(napi_env env, void *data);

    static void ExecTcpServerListen(napi_env env, void *data);

    static void ExecTcpServerClose(napi_env env, void *data);

    static void ExecTcpServerSetExtraOptions(napi_env env, void *data);

    static void ExecTcpServerGetSocketFd(napi_env env, void *data);

    static void ExecTcpServerGetState(napi_env env, void *data);

    static void ExecTcpServerGetLocalAddress(napi_env env, void *data);

    static void ExecLocalSocketBind(napi_env env, void *data);

    static void ExecLocalSocketConnect(napi_env env, void *data);

    static void ExecLocalSocketSend(napi_env env, void *data);

    static void ExecLocalSocketClose(napi_env env, void *data);

    static void ExecLocalSocketGetState(napi_env env, void *data);

    static void ExecLocalSocketGetLocalAddress(napi_env env, void *data);

    static void ExecLocalSocketGetSocketFd(napi_env env, void *data);

    static void ExecLocalSocketSetExtraOptions(napi_env env, void *data);

    static void ExecLocalSocketGetExtraOptions(napi_env env, void *data);

    static void ExecLocalSocketServerListen(napi_env env, void *data);

    static void ExecLocalSocketServerEnd(napi_env env, void *data);

    static void ExecLocalSocketServerGetState(napi_env env, void *data);

    static void ExecLocalSocketServerGetLocalAddress(napi_env env, void *data);

    static void ExecLocalSocketServerSetExtraOptions(napi_env env, void *data);

    static void ExecLocalSocketServerGetExtraOptions(napi_env env, void *data);

    static void ExecLocalSocketServerGetSocketFd(napi_env env, void *data);

    static void ExecLocalSocketConnectionSend(napi_env env, void *data);

    static void ExecLocalSocketConnectionClose(napi_env env, void *data);

    static void ExecLocalSocketConnectionGetLocalAddress(napi_env env, void *data);

    static void ExecLocalSocketConnectionGetSocketFd(napi_env env, void *data);

    /* callback */
    static void BindCallback(napi_env env, napi_status status, void *data);

    static void UdpSendCallback(napi_env env, napi_status status, void *data);

    static void UdpAddMembershipCallback(napi_env env, napi_status status, void *data);

    static void UdpDropMembershipCallback(napi_env env, napi_status status, void *data);

    static void UdpSetMulticastTTLCallback(napi_env env, napi_status status, void *data);

    static void UdpGetMulticastTTLCallback(napi_env env, napi_status status, void *data);

    static void UdpSetLoopbackModeCallback(napi_env env, napi_status status, void *data);

    static void UdpGetLoopbackModeCallback(napi_env env, napi_status status, void *data);

    static void ConnectCallback(napi_env env, napi_status status, void *data);

    static void TcpSendCallback(napi_env env, napi_status status, void *data);

    static void CloseCallback(napi_env env, napi_status status, void *data);

    static void GetStateCallback(napi_env env, napi_status status, void *data);

    static void GetRemoteAddressCallback(napi_env env, napi_status status, void *data);

    static void GetLocalAddressCallback(napi_env env, napi_status status, void *data);

    static void TcpSetExtraOptionsCallback(napi_env env, napi_status status, void *data);

    static void UdpSetExtraOptionsCallback(napi_env env, napi_status status, void *data);

    static void TcpGetSocketFdCallback(napi_env env, napi_status status, void *data);

    static void UdpGetSocketFdCallback(napi_env env, napi_status status, void *data);

    static void TcpConnectionSendCallback(napi_env env, napi_status status, void *data);

    static void TcpConnectionCloseCallback(napi_env env, napi_status status, void *data);

    static void TcpConnectionGetRemoteAddressCallback(napi_env env, napi_status status, void *data);

    static void TcpConnectionGetLocalAddressCallback(napi_env env, napi_status status, void *data);

    static void TcpConnectionGetSocketFdCallback(napi_env env, napi_status status, void *data);

    static void ListenCallback(napi_env env, napi_status status, void *data);

    static void TcpServerCloseCallback(napi_env env, napi_status status, void *data);

    static void TcpServerSetExtraOptionsCallback(napi_env env, napi_status status, void *data);

    static void TcpServerGetSocketFdCallback(napi_env env, napi_status status, void *data);

    static void TcpServerGetStateCallback(napi_env env, napi_status status, void *data);

    static void TcpServerGetLocalAddressCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketBindCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketConnectCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketSendCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketCloseCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketGetStateCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketGetLocalAddressCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketGetSocketFdCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketSetExtraOptionsCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketGetExtraOptionsCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketServerListenCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketServerEndCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketServerGetStateCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketServerGetLocalAddressCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketServerSetExtraOptionsCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketServerGetExtraOptionsCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketServerGetSocketFdCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketConnectionSendCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketConnectionCloseCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketConnectionGetLocalAddressCallback(napi_env env, napi_status status, void *data);

    static void LocalSocketConnectionGetSocketFdCallback(napi_env env, napi_status status, void *data);
};
} // namespace OHOS::NetStack::Socket

#endif /* COMMUNICATIONNETSTACK_SOCKET_ASYNC_WORK_H */
