/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_SOCKET_EXEC_H
#define COMMUNICATIONNETSTACK_SOCKET_EXEC_H

#include "bind_context.h"
#include "common_context.h"
#include "connect_context.h"
#include "multicast_get_loopback_context.h"
#include "multicast_get_ttl_context.h"
#include "multicast_membership_context.h"
#include "multicast_set_loopback_context.h"
#include "multicast_set_ttl_context.h"
#include "safe_map.h"
#include "tcp_extra_context.h"
#include "tcp_send_context.h"
#include "tcp_server_common_context.h"
#include "tcp_server_extra_context.h"
#include "tcp_server_listen_context.h"
#include "tcp_server_send_context.h"
#include "udp_extra_context.h"
#include "udp_send_context.h"
#include "napi_utils.h"

#include <set>

namespace OHOS::NetStack::Socket::SocketExec {

class SocketConfig {
public:
    SocketConfig() {}
    ~SocketConfig() {}
    void SetTcpExtraOptions(int listenFd, const TCPExtraOptions& option)
    {
        tcpExtraOptions_.EnsureInsert(listenFd, option);
    }

    bool GetTcpExtraOptions(int listenFd, TCPExtraOptions& option)
    {
        return tcpExtraOptions_.Find(listenFd, option);
    }

    void AddNewListenSocket(int listenFd)
    {
        tcpClients_.Insert(listenFd, {});
    }

    void AddNewAcceptSocket(int listenFd, int acceptFd)
    {
        std::set<int> fdSet;
        auto fn = [&](std::set<int> &value) -> void {
            value.emplace(acceptFd);
        };
        if (tcpClients_.Find(listenFd, fdSet)) {
            tcpClients_.ChangeValueByLambda(listenFd, fn);
        }
    }

    void RemoveAcceptSocket(int acceptFd)
    {
        tcpClients_.Iterate([acceptFd](int listenFd, std::set<int> fdSet) {
            if (auto ite = fdSet.find(acceptFd); ite != fdSet.end()) {
                fdSet.erase(ite);
            }
        });
    }

    std::set<int> GetClients(int listenFd)
    {
        std::set<int> fdSet;
        tcpClients_.Find(listenFd, fdSet);
        return fdSet;
    }

    void RemoveServerSocket(int listenFd)
    {
        tcpExtraOptions_.Erase(listenFd);
        tcpClients_.Erase(listenFd);
    }

    void ShutdownAllSockets()
    {
        tcpClients_.Iterate([](const int key, std::set<int>&) { shutdown(key, SHUT_RDWR); });
        tcpExtraOptions_.Clear();
        tcpClients_.Clear();
    }
private:
    SocketConfig(const SocketConfig& singleton) = delete;
    SocketConfig& operator=(const SocketConfig& singleton) = delete;

    SafeMap<int, TCPExtraOptions> tcpExtraOptions_;
    SafeMap<int, std::set<int>> tcpClients_;
};

void NotifyRegisterEvent();

std::shared_ptr<SocketConfig> GetSharedConfig(const std::shared_ptr<EventManager> &manager);

/* async work execute */
bool ExecUdpBind(BindContext *context);

bool ExecUdpSend(UdpSendContext *context);

bool ExecUdpAddMembership(MulticastMembershipContext *context);

bool ExecUdpDropMembership(MulticastMembershipContext *context);

bool ExecSetMulticastTTL(MulticastSetTTLContext *context);

bool ExecGetMulticastTTL(MulticastGetTTLContext *context);

bool ExecSetLoopbackMode(MulticastSetLoopbackContext *context);

bool ExecGetLoopbackMode(MulticastGetLoopbackContext *context);

bool ExecTcpBind(BindContext *context);

bool ExecConnect(ConnectContext *context);

bool ExecTcpSend(TcpSendContext *context);

bool ExecClose(CloseContext *context);

bool ExecGetState(GetStateContext *context);

bool ExecGetRemoteAddress(GetRemoteAddressContext *context);

bool ExecGetLocalAddress(GetLocalAddressContext *context);

bool ExecTcpSetExtraOptions(TcpSetExtraOptionsContext *context);

bool ExecUdpSetExtraOptions(UdpSetExtraOptionsContext *context);

bool ExecTcpGetSocketFd(GetSocketFdContext *context);

bool ExecUdpGetSocketFd(GetSocketFdContext *context);

bool ExecTcpConnectionSend(TcpServerSendContext *context);

bool ExecTcpConnectionGetRemoteAddress(TcpServerGetRemoteAddressContext *context);

bool ExecTcpConnectionGetLocalAddress(TcpServerGetLocalAddressContext *context);

bool ExecTcpConnectionGetSocketFd(TcpServerGetSocketFdContext *context);

bool ExecTcpConnectionClose(TcpServerCloseContext *context);

bool ExecTcpServerListen(TcpServerListenContext *context);

bool ExecTcpServerClose(TcpServerCloseContext *context);

bool ExecTcpServerSetExtraOptions(TcpServerSetExtraOptionsContext *context);

bool ExecTcpServerGetSocketFd(TcpServerGetSocketFdContext *context);

bool ExecTcpServerGetState(TcpServerGetStateContext *context);

bool ExecTcpServerGetLocalAddress(TcpServerGetLocalAddressContext *context);

/* async work callback */
napi_value BindCallback(BindContext *context);

napi_value UdpSendCallback(UdpSendContext *context);

napi_value UdpAddMembershipCallback(MulticastMembershipContext *context);

napi_value UdpDropMembershipCallback(MulticastMembershipContext *context);

napi_value UdpSetMulticastTTLCallback(MulticastSetTTLContext *context);

napi_value UdpGetMulticastTTLCallback(MulticastGetTTLContext *context);

napi_value UdpSetLoopbackModeCallback(MulticastSetLoopbackContext *context);

napi_value UdpGetLoopbackModeCallback(MulticastGetLoopbackContext *context);

napi_value ConnectCallback(ConnectContext *context);

napi_value TcpSendCallback(TcpSendContext *context);

napi_value CloseCallback(CloseContext *context);

napi_value GetStateCallback(GetStateContext *context);

napi_value GetRemoteAddressCallback(GetRemoteAddressContext *context);

napi_value GetLocalAddressCallback(GetLocalAddressContext *context);

napi_value TcpSetExtraOptionsCallback(TcpSetExtraOptionsContext *context);

napi_value UdpSetExtraOptionsCallback(UdpSetExtraOptionsContext *context);

napi_value TcpGetSocketFdCallback(GetSocketFdContext *context);

napi_value TcpConnectionSendCallback(TcpServerSendContext *context);

napi_value TcpConnectionCloseCallback(TcpServerCloseContext *context);

napi_value TcpConnectionGetRemoteAddressCallback(TcpServerGetRemoteAddressContext *context);

napi_value TcpConnectionGetLocalAddressCallback(TcpServerGetLocalAddressContext *context);

napi_value TcpConnectionGetSocketFdCallback(TcpServerGetSocketFdContext *context);

napi_value ListenCallback(TcpServerListenContext *context);

napi_value TcpServerCloseCallback(TcpServerCloseContext *context);

napi_value TcpServerSetExtraOptionsCallback(TcpServerSetExtraOptionsContext *context);

napi_value TcpServerGetSocketFdCallback(TcpServerGetSocketFdContext *context);

napi_value TcpServerGetStateCallback(TcpServerGetStateContext *context);

napi_value TcpServerGetLocalAddressCallback(TcpServerGetLocalAddressContext *context);

napi_value UdpGetSocketFdCallback(GetSocketFdContext *context);

struct MessageData {
    MessageData() = delete;
    MessageData(void *d, size_t l, const SocketRemoteInfo &info) : data(d), len(l), remoteInfo(info) {}
    ~MessageData()
    {
        if (data) {
            free(data);
        }
    }

    void *data;
    size_t len;
    SocketRemoteInfo remoteInfo;
};

struct TcpConnection {
    TcpConnection() = delete;
    explicit TcpConnection(int32_t clientid) : clientId(clientid) {}
    ~TcpConnection() = default;

    int32_t clientId;
};

class MessageCallback {
public:
    MessageCallback() = delete;

    virtual ~MessageCallback() = default;

    explicit MessageCallback(const std::shared_ptr<EventManager> &manager) : manager_(manager) {}

    virtual void OnError(int err) const = 0;

    virtual void OnCloseMessage(const std::shared_ptr<EventManager> &manager) const = 0;

    virtual bool OnMessage(void *data, size_t dataLen, sockaddr *addr) const = 0;

    virtual bool OnMessage(int sock, void *data, size_t dataLen, sockaddr *addr,
        const std::shared_ptr<EventManager> &manager) const = 0;

    virtual void OnTcpConnectionMessage(int32_t id) const = 0;

    [[nodiscard]] std::shared_ptr<EventManager> GetEventManager() const;

protected:
    std::shared_ptr<EventManager> manager_ = nullptr;
};

using SocketRecvCallback = std::function<bool(int socketId, std::pair<std::unique_ptr<char[]> &, int> &bufInfo,
    std::pair<sockaddr *, socklen_t> &addrInfo, const MessageCallback &callback)>;

} // namespace OHOS::NetStack::Socket::SocketExec
#endif /* COMMUNICATIONNETSTACK_SOCKET_EXEC_H */
