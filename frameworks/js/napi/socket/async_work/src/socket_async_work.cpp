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

#include "socket_async_work.h"

#include "base_async_work.h"
#include "bind_context.h"
#include "common_context.h"
#include "connect_context.h"
#include "local_socket_context.h"
#include "local_socket_exec.h"
#include "local_socket_server_context.h"
#include "multicast_get_loopback_context.h"
#include "multicast_get_ttl_context.h"
#include "multicast_membership_context.h"
#include "multicast_set_loopback_context.h"
#include "multicast_set_ttl_context.h"
#include "socket_exec.h"
#include "tcp_extra_context.h"
#include "tcp_send_context.h"
#include "tcp_server_common_context.h"
#include "tcp_server_extra_context.h"
#include "tcp_server_listen_context.h"
#include "tcp_server_send_context.h"
#include "udp_extra_context.h"
#include "udp_send_context.h"

namespace OHOS::NetStack::Socket {
void SocketAsyncWork::ExecUdpBind(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<BindContext, SocketExec::ExecUdpBind>(env, data);
}

void SocketAsyncWork::ExecUdpSend(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<UdpSendContext, SocketExec::ExecUdpSend>(env, data);
}

void SocketAsyncWork::ExecUdpAddMembership(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<MulticastMembershipContext, SocketExec::ExecUdpAddMembership>(env, data);
}

void SocketAsyncWork::ExecUdpDropMembership(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<MulticastMembershipContext, SocketExec::ExecUdpDropMembership>(env, data);
}

void SocketAsyncWork::ExecSetMulticastTTL(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<MulticastSetTTLContext, SocketExec::ExecSetMulticastTTL>(env, data);
}

void SocketAsyncWork::ExecGetMulticastTTL(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<MulticastGetTTLContext, SocketExec::ExecGetMulticastTTL>(env, data);
}

void SocketAsyncWork::ExecSetLoopbackMode(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<MulticastSetLoopbackContext, SocketExec::ExecSetLoopbackMode>(env, data);
}

void SocketAsyncWork::ExecGetLoopbackMode(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<MulticastGetLoopbackContext, SocketExec::ExecGetLoopbackMode>(env, data);
}

void SocketAsyncWork::ExecTcpBind(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<BindContext, SocketExec::ExecTcpBind>(env, data);
}

void SocketAsyncWork::ExecConnect(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<ConnectContext, SocketExec::ExecConnect>(env, data);
}

void SocketAsyncWork::ExecClose(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<CloseContext, SocketExec::ExecClose>(env, data);
}

void SocketAsyncWork::ExecTcpSend(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TcpSendContext, SocketExec::ExecTcpSend>(env, data);
}

void SocketAsyncWork::ExecGetState(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<GetStateContext, SocketExec::ExecGetState>(env, data);
}

void SocketAsyncWork::ExecGetRemoteAddress(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<GetRemoteAddressContext, SocketExec::ExecGetRemoteAddress>(env, data);
}

void SocketAsyncWork::ExecGetLocalAddress(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<GetLocalAddressContext, SocketExec::ExecGetLocalAddress>(env, data);
}

void SocketAsyncWork::ExecTcpSetExtraOptions(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TcpSetExtraOptionsContext, SocketExec::ExecTcpSetExtraOptions>(env, data);
}

void SocketAsyncWork::ExecUdpSetExtraOptions(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<UdpSetExtraOptionsContext, SocketExec::ExecUdpSetExtraOptions>(env, data);
}

void SocketAsyncWork::ExecTcpGetSocketFd(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<GetSocketFdContext, SocketExec::ExecTcpGetSocketFd>(env, data);
}

void SocketAsyncWork::ExecUdpGetSocketFd(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<GetSocketFdContext, SocketExec::ExecUdpGetSocketFd>(env, data);
}

void SocketAsyncWork::ExecTcpConnectionSend(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TcpServerSendContext, SocketExec::ExecTcpConnectionSend>(env, data);
}

void SocketAsyncWork::ExecTcpConnectionGetRemoteAddress(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TcpServerGetRemoteAddressContext, SocketExec::ExecTcpConnectionGetRemoteAddress>(env,
                                                                                                                  data);
}

void SocketAsyncWork::ExecTcpConnectionGetLocalAddress(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TcpConnectionGetLocalAddressContext, SocketExec::ExecTcpConnectionGetLocalAddress>(
        env, data);
}

void SocketAsyncWork::ExecTcpConnectionGetSocketFd(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TcpServerGetSocketFdContext, SocketExec::ExecTcpConnectionGetSocketFd>(env, data);
}

void SocketAsyncWork::ExecTcpConnectionClose(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TcpServerCloseContext, SocketExec::ExecTcpConnectionClose>(env, data);
}

void SocketAsyncWork::ExecTcpServerListen(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TcpServerListenContext, SocketExec::ExecTcpServerListen>(env, data);
}

void SocketAsyncWork::ExecTcpServerClose(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TcpServerCloseContext, SocketExec::ExecTcpServerClose>(env, data);
}

void SocketAsyncWork::ExecTcpServerSetExtraOptions(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TcpServerSetExtraOptionsContext, SocketExec::ExecTcpServerSetExtraOptions>(env, data);
}

void SocketAsyncWork::ExecTcpServerGetSocketFd(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TcpServerGetSocketFdContext, SocketExec::ExecTcpServerGetSocketFd>(env, data);
}

void SocketAsyncWork::ExecTcpServerGetState(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TcpServerGetStateContext, SocketExec::ExecTcpServerGetState>(env, data);
}

void SocketAsyncWork::ExecTcpServerGetLocalAddress(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<TcpServerGetLocalAddressContext, SocketExec::ExecTcpServerGetLocalAddress>(env, data);
}

void SocketAsyncWork::ExecLocalSocketBind(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketBindContext, LocalSocketExec::ExecLocalSocketBind>(env, data);
}

void SocketAsyncWork::ExecLocalSocketConnect(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketConnectContext, LocalSocketExec::ExecLocalSocketConnect>(env, data);
}

void SocketAsyncWork::ExecLocalSocketSend(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketSendContext, LocalSocketExec::ExecLocalSocketSend>(env, data);
}

void SocketAsyncWork::ExecLocalSocketClose(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketCloseContext, LocalSocketExec::ExecLocalSocketClose>(env, data);
}

void SocketAsyncWork::ExecLocalSocketGetState(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketGetStateContext, LocalSocketExec::ExecLocalSocketGetState>(env, data);
}

void SocketAsyncWork::ExecLocalSocketGetLocalAddress(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketGetLocalAddressContext,
        LocalSocketExec::ExecLocalSocketGetLocalAddress>(env, data);
}

void SocketAsyncWork::ExecLocalSocketGetSocketFd(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketGetSocketFdContext, LocalSocketExec::ExecLocalSocketGetSocketFd>(env, data);
}

void SocketAsyncWork::ExecLocalSocketSetExtraOptions(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketSetExtraOptionsContext, LocalSocketExec::ExecLocalSocketSetExtraOptions>(
        env, data);
}

void SocketAsyncWork::ExecLocalSocketGetExtraOptions(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketGetExtraOptionsContext, LocalSocketExec::ExecLocalSocketGetExtraOptions>(
        env, data);
}

void SocketAsyncWork::ExecLocalSocketServerListen(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketServerListenContext, LocalSocketExec::ExecLocalSocketServerListen>(env,
                                                                                                               data);
}

void SocketAsyncWork::ExecLocalSocketServerEnd(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketServerEndContext, LocalSocketExec::ExecLocalSocketServerEnd>(env, data);
}

void SocketAsyncWork::ExecLocalSocketServerGetState(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketServerGetStateContext, LocalSocketExec::ExecLocalSocketServerGetState>(
        env, data);
}

void SocketAsyncWork::ExecLocalSocketServerGetLocalAddress(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketServerGetLocalAddressContext,
                                 LocalSocketExec::ExecLocalSocketServerGetLocalAddress>(env, data);
}

void SocketAsyncWork::ExecLocalSocketServerSetExtraOptions(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketServerSetExtraOptionsContext,
                                 LocalSocketExec::ExecLocalSocketServerSetExtraOptions>(env, data);
}

void SocketAsyncWork::ExecLocalSocketServerGetExtraOptions(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketServerGetExtraOptionsContext,
                                 LocalSocketExec::ExecLocalSocketServerGetExtraOptions>(env, data);
}

void SocketAsyncWork::ExecLocalSocketServerGetSocketFd(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketServerGetSocketFdContext,
                                 LocalSocketExec::ExecLocalSocketServerGetSocketFd>(env, data);
}

void SocketAsyncWork::ExecLocalSocketConnectionSend(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketServerSendContext, LocalSocketExec::ExecLocalSocketConnectionSend>(env,
                                                                                                               data);
}

void SocketAsyncWork::ExecLocalSocketConnectionClose(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketServerCloseContext, LocalSocketExec::ExecLocalSocketConnectionClose>(env,
                                                                                                                 data);
}

void SocketAsyncWork::ExecLocalSocketConnectionGetLocalAddress(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketServerGetLocalAddressContext,
                                 LocalSocketExec::ExecLocalSocketConnectionGetLocalAddress>(env, data);
}

void SocketAsyncWork::ExecLocalSocketConnectionGetSocketFd(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<LocalSocketServerGetSocketFdContext,
                                 LocalSocketExec::ExecLocalSocketConnectionGetSocketFd>(env, data);
}

void SocketAsyncWork::BindCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<BindContext, SocketExec::BindCallback>(env, status, data);
}

void SocketAsyncWork::UdpSendCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<UdpSendContext, SocketExec::UdpSendCallback>(env, status, data);
}

void SocketAsyncWork::UdpAddMembershipCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<MulticastMembershipContext, SocketExec::UdpAddMembershipCallback>(env, status,
                                                                                                       data);
}

void SocketAsyncWork::UdpDropMembershipCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<MulticastMembershipContext, SocketExec::UdpDropMembershipCallback>(env, status,
                                                                                                        data);
}

void SocketAsyncWork::UdpSetMulticastTTLCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<MulticastSetTTLContext, SocketExec::UdpSetMulticastTTLCallback>(env, status, data);
}

void SocketAsyncWork::UdpGetMulticastTTLCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<MulticastGetTTLContext, SocketExec::UdpGetMulticastTTLCallback>(env, status, data);
}

void SocketAsyncWork::UdpSetLoopbackModeCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<MulticastSetLoopbackContext, SocketExec::UdpSetLoopbackModeCallback>(env, status,
                                                                                                          data);
}

void SocketAsyncWork::UdpGetLoopbackModeCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<MulticastGetLoopbackContext, SocketExec::UdpGetLoopbackModeCallback>(env, status,
                                                                                                          data);
}

void SocketAsyncWork::ConnectCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<ConnectContext, SocketExec::ConnectCallback>(env, status, data);
}

void SocketAsyncWork::TcpSendCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TcpSendContext, SocketExec::TcpSendCallback>(env, status, data);
}

void SocketAsyncWork::CloseCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<CloseContext, SocketExec::CloseCallback>(env, status, data);
}

void SocketAsyncWork::GetStateCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<GetStateContext, SocketExec::GetStateCallback>(env, status, data);
}

void SocketAsyncWork::GetRemoteAddressCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<GetRemoteAddressContext, SocketExec::GetRemoteAddressCallback>(env, status, data);
}

void SocketAsyncWork::GetLocalAddressCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<GetLocalAddressContext, SocketExec::GetLocalAddressCallback>(env, status, data);
}

void SocketAsyncWork::TcpSetExtraOptionsCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TcpSetExtraOptionsContext, SocketExec::TcpSetExtraOptionsCallback>(env, status,
                                                                                                        data);
}

void SocketAsyncWork::UdpSetExtraOptionsCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<UdpSetExtraOptionsContext, SocketExec::UdpSetExtraOptionsCallback>(env, status,
                                                                                                        data);
}

void SocketAsyncWork::TcpGetSocketFdCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<GetSocketFdContext, SocketExec::TcpGetSocketFdCallback>(env, status, data);
}

void SocketAsyncWork::UdpGetSocketFdCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<GetSocketFdContext, SocketExec::UdpGetSocketFdCallback>(env, status, data);
}

void SocketAsyncWork::TcpConnectionSendCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TcpServerSendContext, SocketExec::TcpConnectionSendCallback>(env, status, data);
}

void SocketAsyncWork::TcpConnectionCloseCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TcpServerCloseContext, SocketExec::TcpConnectionCloseCallback>(env, status, data);
}

void SocketAsyncWork::TcpConnectionGetRemoteAddressCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TcpServerGetRemoteAddressContext,
                                     SocketExec::TcpConnectionGetRemoteAddressCallback>(env, status, data);
}

void SocketAsyncWork::TcpConnectionGetLocalAddressCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TcpConnectionGetLocalAddressContext,
                                     SocketExec::TcpConnectionGetLocalAddressCallback>(env, status, data);
}

void SocketAsyncWork::TcpConnectionGetSocketFdCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TcpServerGetSocketFdContext,
                                     SocketExec::TcpConnectionGetSocketFdCallback>(env, status, data);
}

void SocketAsyncWork::ListenCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TcpServerListenContext, SocketExec::ListenCallback>(env, status, data);
}

void SocketAsyncWork::TcpServerCloseCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TcpServerCloseContext, SocketExec::TcpServerCloseCallback>(env, status, data);
}

void SocketAsyncWork::TcpServerSetExtraOptionsCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TcpServerSetExtraOptionsContext, SocketExec::TcpServerSetExtraOptionsCallback>(
        env, status, data);
}

void SocketAsyncWork::TcpServerGetSocketFdCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TcpServerGetSocketFdContext, SocketExec::TcpServerGetSocketFdCallback>(
        env, status, data);
}

void SocketAsyncWork::TcpServerGetStateCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TcpServerGetStateContext, SocketExec::TcpServerGetStateCallback>(env, status,
                                                                                                      data);
}

void SocketAsyncWork::TcpServerGetLocalAddressCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<TcpServerGetLocalAddressContext, SocketExec::TcpServerGetLocalAddressCallback>(
        env, status, data);
}

void SocketAsyncWork::LocalSocketBindCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketBindContext, LocalSocketExec::LocalSocketBindCallback>(env, status,
                                                                                                       data);
}

void SocketAsyncWork::LocalSocketConnectCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketConnectContext, LocalSocketExec::LocalSocketConnectCallback>(
        env, status, data);
}

void SocketAsyncWork::LocalSocketSendCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketSendContext, LocalSocketExec::LocalSocketSendCallback>(env, status,
                                                                                                       data);
}

void SocketAsyncWork::LocalSocketCloseCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketCloseContext, LocalSocketExec::LocalSocketCloseCallback>(env, status,
                                                                                                         data);
}

void SocketAsyncWork::LocalSocketGetStateCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketGetStateContext, LocalSocketExec::LocalSocketGetStateCallback>(
        env, status, data);
}

void SocketAsyncWork::LocalSocketGetLocalAddressCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketGetLocalAddressContext,
        LocalSocketExec::LocalSocketGetLocalAddressCallback>(env, status, data);
}

void SocketAsyncWork::LocalSocketGetSocketFdCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketGetSocketFdContext, LocalSocketExec::LocalSocketGetSocketFdCallback>(
        env, status, data);
}

void SocketAsyncWork::LocalSocketSetExtraOptionsCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketSetExtraOptionsContext,
                                     LocalSocketExec::LocalSocketSetExtraOptionsCallback>(env, status, data);
}

void SocketAsyncWork::LocalSocketGetExtraOptionsCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketGetExtraOptionsContext,
                                     LocalSocketExec::LocalSocketGetExtraOptionsCallback>(env, status, data);
}

void SocketAsyncWork::LocalSocketServerListenCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketServerListenContext, LocalSocketExec::LocalSocketServerListenCallback>(
        env, status, data);
}

void SocketAsyncWork::LocalSocketServerEndCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketServerEndContext, LocalSocketExec::LocalSocketServerEndCallback>(
        env, status, data);
}

void SocketAsyncWork::LocalSocketServerGetStateCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketServerGetStateContext,
                                     LocalSocketExec::LocalSocketServerGetStateCallback>(env, status, data);
}

void SocketAsyncWork::LocalSocketServerGetLocalAddressCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketServerGetLocalAddressContext,
                                     LocalSocketExec::LocalSocketServerGetLocalAddressCallback>(env, status, data);
}

void SocketAsyncWork::LocalSocketServerSetExtraOptionsCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketServerSetExtraOptionsContext,
                                     LocalSocketExec::LocalSocketServerSetExtraOptionsCallback>(env, status, data);
}

void SocketAsyncWork::LocalSocketServerGetExtraOptionsCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketServerGetExtraOptionsContext,
                                     LocalSocketExec::LocalSocketServerGetExtraOptionsCallback>(env, status, data);
}

void SocketAsyncWork::LocalSocketServerGetSocketFdCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketServerGetSocketFdContext,
                                     LocalSocketExec::LocalSocketServerGetSocketFdCallback>(env, status, data);
}

void SocketAsyncWork::LocalSocketConnectionSendCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketServerSendContext, LocalSocketExec::LocalSocketConnectionSendCallback>(
        env, status, data);
}

void SocketAsyncWork::LocalSocketConnectionCloseCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketServerCloseContext,
                                     LocalSocketExec::LocalSocketConnectionCloseCallback>(env, status, data);
}

void SocketAsyncWork::LocalSocketConnectionGetLocalAddressCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketServerGetLocalAddressContext,
                                     LocalSocketExec::LocalSocketConnectionGetLocalAddressCallback>(env, status, data);
}

void SocketAsyncWork::LocalSocketConnectionGetSocketFdCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<LocalSocketServerGetSocketFdContext,
                                     LocalSocketExec::LocalSocketConnectionGetSocketFdCallback>(env, status, data);
}
} // namespace OHOS::NetStack::Socket
