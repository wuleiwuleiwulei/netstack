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

#include "socket_exec.h"

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <fcntl.h>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>

#include "context_key.h"
#include "event_list.h"
#include "napi_utils.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "proxy_options.h"
#include "securec.h"
#include "socket_async_work.h"
#include "socket_module.h"
#include "socket_exec_common.h"
#include "socks5_utils.h"
#include "module_template.h"

#ifdef IOS_PLATFORM
#define SO_PROTOCOL 38
#endif

static constexpr const int DEFAULT_BUFFER_SIZE = 8192;

static constexpr const int MAX_SOCKET_BUFFER_SIZE = 262144;

static constexpr const int DEFAULT_TIMEOUT_MS = 20000;

static constexpr const int DEFAULT_POLL_TIMEOUT = 500; // 0.5 Seconds

static constexpr const int ADDRESS_INVALID = 99;

static constexpr const int OTHER_ERROR = 100;

static constexpr const int UNKNOW_ERROR = -1;

static constexpr const int NO_MEMORY = -2;

static constexpr const int USER_LIMIT = 511;

static constexpr const int MAX_CLIENTS = 1024;

static constexpr const int ERRNO_BAD_FD = 9;

static constexpr const int UNIT_CONVERSION_1000 = 1000;

static constexpr const char *TCP_SOCKET_CONNECTION = "TCPSocketConnection";

static constexpr const char *TCP_SERVER_ACCEPT_RECV_DATA = "OS_NET_SockRD";

static constexpr const char *TCP_SERVER_HANDLE_CLIENT = "OS_NET_SockAcc";

static constexpr const char *SOCKET_EXEC_UDP_BIND = "OS_NET_SockUPRD";

static constexpr const char *SOCKET_EXEC_CONNECT = "OS_NET_SockTPRD";

static constexpr const char *SOCKET_RECV_FROM_MULTI_CAST = "OS_NET_SockMPRD";

static constexpr const char *WILD_ADDRESS = "0.0.0.0";

namespace OHOS::NetStack::Socket::SocketExec {
#define ERROR_RETURN(context, ...) \
    do { \
        NETSTACK_LOGE(__VA_ARGS__); \
        context->SetErrorCode(errno); \
        context->SetExecOK(false); \
        return false; \
    } while (0)

std::map<int32_t, int32_t> g_clientFDs;
std::map<int32_t, std::shared_ptr<EventManager>> g_clientEventManagers;
std::condition_variable g_cv;
std::mutex g_mutex;
std::shared_mutex g_fdMutex;
std::atomic_int g_userCounter = 0;

static void SetIsBound(sa_family_t family, GetStateContext *context, const sockaddr_in *addr4,
                       const sockaddr_in6 *addr6)
{
    if (family == AF_INET) {
        context->state_.SetIsBound(ntohs(addr4->sin_port) != 0);
    } else if (family == AF_INET6) {
        context->state_.SetIsBound(ntohs(addr6->sin6_port) != 0);
    }
}

static void SetIsConnected(sa_family_t family, GetStateContext *context, const sockaddr_in *addr4,
                           const sockaddr_in6 *addr6)
{
    if (family == AF_INET) {
        context->state_.SetIsConnected(ntohs(addr4->sin_port) != 0);
    } else if (family == AF_INET6) {
        context->state_.SetIsConnected(ntohs(addr6->sin6_port) != 0);
    }
}

static napi_value MakeError(napi_env env, void *errCode)
{
    auto code = reinterpret_cast<int32_t *>(errCode);
    NETSTACK_LOGI("go to MakeError, err: %{public}d", *code);
    auto deleter = [](const int32_t *p) { delete p; };
    std::unique_ptr<int32_t, decltype(deleter)> handler(code, deleter);

    napi_value err = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, err) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetInt32Property(env, err, KEY_ERROR_CODE, *code);
    return err;
}

static napi_value MakeClose(napi_env env, void *data)
{
    (void)data;
    NETSTACK_LOGI("go to MakeClose");
    napi_value obj = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, obj) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }

    return obj;
}

void TcpServerConnectionFinalize(napi_env, void *data, void *)
{
    NETSTACK_LOGI("socket server connection handle is finalized");
    auto sharedManager = reinterpret_cast<std::shared_ptr<EventManager> *>(data);
    if (sharedManager != nullptr) {
        auto manager = *sharedManager;
        NETSTACK_LOGI("manager is not nullptr");
        int clientIndex = -1;
        std::lock_guard<std::mutex> lock(g_mutex);
        for (auto it = g_clientEventManagers.begin(); it != g_clientEventManagers.end(); ++it) {
            if (it->second == manager) {
                clientIndex = it->first;
                g_clientEventManagers.erase(it);
                break;
            }
        }
        auto clientIter = g_clientFDs.find(clientIndex);
        if (clientIter != g_clientFDs.end()) {
            if (clientIter->second != -1) {
                NETSTACK_LOGI("close connection socketFd %{public}d", clientIter->second);
                shutdown(clientIter->second, SHUT_RDWR);
                clientIter->second = -1;
            }
        }
    }
    delete sharedManager;
}

void NotifyRegisterEvent()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_cv.notify_all();
}

napi_value NewInstanceWithConstructor(napi_env env, napi_callback_info info, napi_value jsConstructor, int32_t counter)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_new_instance(env, jsConstructor, 0, nullptr, &result));

    auto sharedManager = new (std::nothrow) std::shared_ptr<EventManager>();
    if (sharedManager == nullptr) {
        return result;
    }
    auto manager = std::make_shared<EventManager>();
    *sharedManager = manager;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_clientEventManagers.insert(std::pair<int32_t, std::shared_ptr<EventManager>>(counter, manager));
        g_cv.notify_one();
    }

    manager->SetData(reinterpret_cast<void *>(counter));
    napi_wrap(env, result, reinterpret_cast<void *>(sharedManager), TcpServerConnectionFinalize, nullptr, nullptr);
    return result;
} // namespace OHOS::NetStack::Socket::SocketExec

napi_value ConstructTCPSocketConnection(napi_env env, napi_callback_info info, int32_t counter)
{
    napi_value jsConstructor = nullptr;
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(SocketModuleExports::TCPConnection::FUNCTION_SEND,
                              SocketModuleExports::TCPConnection::Send),
        DECLARE_NAPI_FUNCTION(SocketModuleExports::TCPConnection::FUNCTION_CLOSE,
                              SocketModuleExports::TCPConnection::Close),
        DECLARE_NAPI_FUNCTION(SocketModuleExports::TCPConnection::FUNCTION_GET_REMOTE_ADDRESS,
                              SocketModuleExports::TCPConnection::GetRemoteAddress),
        DECLARE_NAPI_FUNCTION(SocketModuleExports::TCPConnection::FUNCTION_GET_LOCAL_ADDRESS,
                              SocketModuleExports::TCPConnection::GetLocalAddress),
        DECLARE_NAPI_FUNCTION(SocketModuleExports::TCPConnection::FUNCTION_GET_SOCKET_FD,
                              SocketModuleExports::TCPConnection::GetSocketFd),
        DECLARE_NAPI_FUNCTION(SocketModuleExports::TCPConnection::FUNCTION_ON, SocketModuleExports::TCPConnection::On),
        DECLARE_NAPI_FUNCTION(SocketModuleExports::TCPConnection::FUNCTION_OFF,
                              SocketModuleExports::TCPConnection::Off),
    };

    auto constructor = [](napi_env env, napi_callback_info info) -> napi_value {
        napi_value thisVal = nullptr;
        NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVal, nullptr));

        return thisVal;
    };

    napi_property_descriptor descriptors[properties.size()];
    std::copy(properties.begin(), properties.end(), descriptors);

    NAPI_CALL_BASE(env,
                   napi_define_class(env, TCP_SOCKET_CONNECTION, NAPI_AUTO_LENGTH, constructor, nullptr,
                                     properties.size(), descriptors, &jsConstructor),
                   NapiUtils::GetUndefined(env));

    if (jsConstructor != nullptr) {
        napi_value result = NewInstanceWithConstructor(env, info, jsConstructor, counter);
        NapiUtils::SetInt32Property(env, result, SocketModuleExports::TCPConnection::PROPERTY_CLIENT_ID, counter);
        return result;
    }
    return NapiUtils::GetUndefined(env);
}

static napi_value MakeTcpConnectionMessage(napi_env env, void *para)
{
    auto netConnection = reinterpret_cast<TcpConnection *>(para);
    auto deleter = [](const TcpConnection *p) { delete p; };
    std::unique_ptr<TcpConnection, decltype(deleter)> handler(netConnection, deleter);

    napi_callback_info info = nullptr;
    return ConstructTCPSocketConnection(env, info, netConnection->clientId);
}

static std::string MakeAddressString(sockaddr *addr)
{
    if (addr->sa_family == AF_INET) {
        auto *addr4 = reinterpret_cast<sockaddr_in *>(addr);
        const char *str = inet_ntoa(addr4->sin_addr);
        if (str == nullptr || strlen(str) == 0) {
            return {};
        }
        return str;
    } else if (addr->sa_family == AF_INET6) {
        auto *addr6 = reinterpret_cast<sockaddr_in6 *>(addr);
        char str[INET6_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET6, &addr6->sin6_addr, str, INET6_ADDRSTRLEN) == nullptr || strlen(str) == 0) {
            return {};
        }
        return str;
    }
    return {};
}

static napi_value MakeJsMessageParam(napi_env env, napi_value msgBuffer, SocketRemoteInfo *remoteInfo)
{
    napi_value obj = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, obj) != napi_object) {
        return nullptr;
    }
    if (NapiUtils::ValueIsArrayBuffer(env, msgBuffer)) {
        NapiUtils::SetNamedProperty(env, obj, KEY_MESSAGE, msgBuffer);
    }
    napi_value jsRemoteInfo = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, jsRemoteInfo) != napi_object) {
        return nullptr;
    }
    NapiUtils::SetStringPropertyUtf8(env, jsRemoteInfo, KEY_ADDRESS, remoteInfo->GetAddress());
    NapiUtils::SetStringPropertyUtf8(env, jsRemoteInfo, KEY_FAMILY, remoteInfo->GetFamily());
    NapiUtils::SetUint32Property(env, jsRemoteInfo, KEY_PORT, remoteInfo->GetPort());
    NapiUtils::SetUint32Property(env, jsRemoteInfo, KEY_SIZE, remoteInfo->GetSize());

    NapiUtils::SetNamedProperty(env, obj, KEY_REMOTE_INFO, jsRemoteInfo);
    return obj;
}

static napi_value MakeMessage(napi_env env, const std::shared_ptr<EventManager> &manager)
{
    auto messageData = reinterpret_cast<MessageData *>(manager->GetQueueData());
    auto deleter = [](const MessageData *p) { delete p; };
    std::unique_ptr<MessageData, decltype(deleter)> handler(messageData, deleter);

    if (messageData == nullptr) {
        SocketRemoteInfo remoteInfo;
        return MakeJsMessageParam(env, NapiUtils::GetUndefined(env), &remoteInfo);
    }

    if (messageData->data == nullptr || messageData->len == 0) {
        return MakeJsMessageParam(env, NapiUtils::GetUndefined(env), &messageData->remoteInfo);
    }

    void *dataHandle = nullptr;
    napi_value msgBuffer = NapiUtils::CreateArrayBuffer(env, messageData->len, &dataHandle);
    if (dataHandle == nullptr || !NapiUtils::ValueIsArrayBuffer(env, msgBuffer)) {
        return MakeJsMessageParam(env, NapiUtils::GetUndefined(env), &messageData->remoteInfo);
    }

    int result = memcpy_s(dataHandle, messageData->len, messageData->data, messageData->len);
    if (result != EOK) {
        NETSTACK_LOGI("copy ret %{public}d", result);
        return NapiUtils::GetUndefined(env);
    }

    return MakeJsMessageParam(env, msgBuffer, &messageData->remoteInfo);
}

static bool OnRecvMessage(const std::shared_ptr<EventManager> &manager, void *data, size_t len, sockaddr *addr)
{
    if (data == nullptr || len == 0) {
        return false;
    }

    SocketRemoteInfo remoteInfo;
    std::string address = MakeAddressString(addr);
    if (address.empty() && manager->HasEventListener(EVENT_ERROR)) {
        manager->EmitByUvWithoutCheckShared(EVENT_ERROR, new int32_t(ADDRESS_INVALID),
            ModuleTemplate::CallbackTemplate<MakeError>);
        return false;
    }
    remoteInfo.SetAddress(address);
    remoteInfo.SetFamily(addr->sa_family);
    if (addr->sa_family == AF_INET) {
        auto *addr4 = reinterpret_cast<sockaddr_in *>(addr);
        remoteInfo.SetPort(ntohs(addr4->sin_port));
    } else if (addr->sa_family == AF_INET6) {
        auto *addr6 = reinterpret_cast<sockaddr_in6 *>(addr);
        remoteInfo.SetPort(ntohs(addr6->sin6_port));
    }

    if (manager->GetProxyData() != nullptr &&
        !manager->GetProxyData()->RemoveHeader(data, len, addr->sa_family)) {
            NETSTACK_LOGE("remove socks5 udp header failed");
    }
    remoteInfo.SetSize(len);

    if (manager->HasEventListener(EVENT_MESSAGE)) {
        auto *messageStruct = new MessageData(data, len, remoteInfo);
        manager->SetQueueData(reinterpret_cast<void *>(messageStruct));
        manager->EmitWithoutUV(EVENT_MESSAGE, nullptr, MakeMessage);
        return true;
    }
    return false;
}

std::shared_ptr<EventManager> MessageCallback::GetEventManager() const
{
    return manager_;
}

class TcpMessageCallback final : public MessageCallback {
public:
    TcpMessageCallback() = delete;

    ~TcpMessageCallback() override = default;

    explicit TcpMessageCallback(const std::shared_ptr<EventManager> &manager) : MessageCallback(manager) {}

    void OnError(int err) const override
    {
        if (manager_ != nullptr && manager_->HasEventListener(EVENT_ERROR)) {
            manager_->EmitByUvWithoutCheckShared(EVENT_ERROR, new int(err),
                ModuleTemplate::CallbackTemplate<MakeError>);
            return;
        }
        NETSTACK_LOGI("tcp socket handle has been finalized, manager is invalid or ERROR listener is not registered");
    }

    void OnCloseMessage(const std::shared_ptr<EventManager> &manager) const override
    {
        if (manager != nullptr) {
            manager->EmitByUvWithoutCheckShared(EVENT_CLOSE, nullptr, ModuleTemplate::CallbackTemplate<MakeClose>);
        }
    }

    bool OnMessage(void *data, size_t dataLen, sockaddr *addr) const override
    {
        (void)addr;
        if (manager_ == nullptr) {
            NETSTACK_LOGE("invalid manager");
            return false;
        }
        int sock = static_cast<int>(reinterpret_cast<uint64_t>(manager_->GetData()));
        if (sock == 0) {
            return false;
        }
        sockaddr sockAddr = {0};
        socklen_t len = sizeof(sockaddr);
        int ret = getsockname(sock, &sockAddr, &len);
        if (ret < 0) {
            return false;
        }

        if (sockAddr.sa_family == AF_INET) {
            sockaddr_in addr4 = {0};
            socklen_t len4 = sizeof(sockaddr_in);

            ret = getpeername(sock, reinterpret_cast<sockaddr *>(&addr4), &len4);
            if (ret < 0) {
                return false;
            }
            return OnRecvMessage(manager_, data, dataLen, reinterpret_cast<sockaddr *>(&addr4));
        } else if (sockAddr.sa_family == AF_INET6) {
            sockaddr_in6 addr6 = {0};
            socklen_t len6 = sizeof(sockaddr_in6);

            ret = getpeername(sock, reinterpret_cast<sockaddr *>(&addr6), &len6);
            if (ret < 0) {
                return false;
            }
            return OnRecvMessage(manager_, data, dataLen, reinterpret_cast<sockaddr *>(&addr6));
        }
        return false;
    }

    bool OnMessage(int sock, void *data, size_t dataLen, sockaddr *addr,
        const std::shared_ptr<EventManager> &manager) const override
    {
        (void)addr;
        if (static_cast<int>(reinterpret_cast<uint64_t>(manager_->GetData())) == 0) {
            return false;
        }
        sockaddr sockAddr = {0};
        socklen_t len = sizeof(sockaddr);
        int ret = getsockname(sock, &sockAddr, &len);
        if (ret < 0) {
            return false;
        }

        if (sockAddr.sa_family == AF_INET) {
            sockaddr_in addr4 = {0};
            socklen_t len4 = sizeof(sockaddr_in);

            ret = getpeername(sock, reinterpret_cast<sockaddr *>(&addr4), &len4);
            if (ret < 0) {
                return false;
            }
            return OnRecvMessage(manager, data, dataLen, reinterpret_cast<sockaddr *>(&addr4));
        } else if (sockAddr.sa_family == AF_INET6) {
            sockaddr_in6 addr6 = {0};
            socklen_t len6 = sizeof(sockaddr_in6);

            ret = getpeername(sock, reinterpret_cast<sockaddr *>(&addr6), &len6);
            if (ret < 0) {
                return false;
            }
            return OnRecvMessage(manager, data, dataLen, reinterpret_cast<sockaddr *>(&addr6));
        }
        return false;
    }

    void OnTcpConnectionMessage(int32_t id) const override
    {
        if (manager_ != nullptr && manager_->HasEventListener(EVENT_CONNECT)) {
            manager_->EmitByUvWithoutCheckShared(EVENT_CONNECT, new TcpConnection(id),
                ModuleTemplate::CallbackTemplate<MakeTcpConnectionMessage>);
        }
    }
};

class UdpMessageCallback final : public MessageCallback {
public:
    UdpMessageCallback() = delete;

    ~UdpMessageCallback() override = default;

    explicit UdpMessageCallback(const std::shared_ptr<EventManager> &manager) : MessageCallback(manager) {}

    void OnError(int err) const override
    {
        if (manager_ != nullptr && manager_->HasEventListener(EVENT_ERROR)) {
            manager_->EmitByUvWithoutCheckShared(EVENT_ERROR, new int(err),
                ModuleTemplate::CallbackTemplate<MakeError>);
            return;
        }
        NETSTACK_LOGI("udp socket handle has been finalized, manager is invalid or ERROR listener is not registered");
    }

    void OnCloseMessage(const std::shared_ptr<EventManager> &manager) const override {}

    bool OnMessage(void *data, size_t dataLen, sockaddr *addr) const override
    {
        int sock = static_cast<int>(reinterpret_cast<uint64_t>(manager_->GetData()));
        if (sock == 0) {
            return false;
        }
        return OnRecvMessage(manager_, data, dataLen, addr);
    }

    bool OnMessage(int sock, void *data, size_t dataLen, sockaddr *addr,
        const std::shared_ptr<EventManager> &manager) const override
    {
        if (static_cast<int>(reinterpret_cast<uint64_t>(manager_->GetData())) == 0) {
            return false;
        }
        return true;
    }

    void OnTcpConnectionMessage(int32_t id) const override {}
};

static void GetAddr(NetAddress *address, sockaddr_in *addr4, sockaddr_in6 *addr6, sockaddr **addr, socklen_t *len)
{
    sa_family_t family = address->GetSaFamily();
    if (family == AF_INET) {
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(address->GetPort());
        addr4->sin_addr.s_addr = inet_addr(address->GetAddress().c_str());
        *addr = reinterpret_cast<sockaddr *>(addr4);
        *len = sizeof(sockaddr_in);
    } else if (family == AF_INET6) {
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(address->GetPort());
        inet_pton(AF_INET6, address->GetAddress().c_str(), &addr6->sin6_addr);
        *addr = reinterpret_cast<sockaddr *>(addr6);
        *len = sizeof(sockaddr_in6);
    }
}

static bool PollFd(pollfd *fds, nfds_t num, int timeout)
{
    int ret = poll(fds, num, timeout);
    if (ret == -1) {
        NETSTACK_LOGE("poll to send failed, socket is %{public}d, errno is %{public}d", fds->fd, errno);
        return false;
    }
    if (ret == 0) {
        NETSTACK_LOGE("poll to send timeout, socket is %{public}d, timeout is %{public}d", fds->fd, timeout);
        return false;
    }
    return true;
}

static bool TcpSendEvent(TcpSendContext *context)
{
    std::string encoding = context->options.GetEncoding();
    (void)encoding;
    /* no use for now */

    sockaddr sockAddr = {0};
    socklen_t len = sizeof(sockaddr);
    if (getsockname(context->GetSocketFd(), &sockAddr, &len) < 0) {
        ERROR_RETURN(context, "getsockname failed, sock:%{public}d, errno:%{public}d", context->GetSocketFd(), errno);
    }
    bool connected = false;
    if (sockAddr.sa_family == AF_INET) {
        sockaddr_in addr4 = {0};
        socklen_t len4 = sizeof(addr4);
        int ret = getpeername(context->GetSocketFd(), reinterpret_cast<sockaddr *>(&addr4), &len4);
        if (ret >= 0 && addr4.sin_port != 0) {
            connected = true;
        }
    } else if (sockAddr.sa_family == AF_INET6) {
        sockaddr_in6 addr6 = {0};
        socklen_t len6 = sizeof(addr6);
        int ret = getpeername(context->GetSocketFd(), reinterpret_cast<sockaddr *>(&addr6), &len6);
        if (ret >= 0 && addr6.sin6_port != 0) {
            connected = true;
        }
    }

    if (!connected) {
        NETSTACK_LOGE("sock is not connect to remote, socket is %{public}d, errno is %{public}d",
                      context->GetSocketFd(), errno);
        context->SetErrorCode(errno);
        return false;
    }

    if (!PollSendData(context->GetSocketFd(), context->options.GetData().c_str(), context->options.GetData().size(),
                      nullptr, 0)) {
        ERROR_RETURN(context, "send failed, socket is %{public}d, errno is %{public}d", context->GetSocketFd(), errno);
    }
    return true;
}

static bool UdpSendEvent(UdpSendContext *context)
{
    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len;
    context->options.address.SetRawAddress(
        ConvertAddressToIp(context->options.address.GetAddress(), context->options.address.GetSaFamily()));
    GetAddr(&context->options.address, &addr4, &addr6, &addr, &len);
    if (addr == nullptr) {
        NETSTACK_LOGE("get sock name failed, socket is %{public}d, errno is %{public}d", context->GetSocketFd(), errno);
        context->SetErrorCode(ADDRESS_INVALID);
        context->SetExecOK(false);
        return false;
    }

    if (!PollSendData(context->GetSocketFd(), context->options.GetData().c_str(), context->options.GetData().size(),
                      addr, len)) {
        ERROR_RETURN(context, "send failed, socket is %{public}d, errno is %{public}d", context->GetSocketFd(), errno);
    }
    return true;
}

static bool IsTCPSocket(int sockfd)
{
    int optval;
    socklen_t optlen = sizeof(optval);

    if (getsockopt(sockfd, SOL_SOCKET, SO_PROTOCOL, &optval, &optlen) != 0) {
        return false;
    }
    return optval == IPPROTO_TCP;
}

static int UpdateRecvBuffer(int sock, int &bufferSize, std::unique_ptr<char[]> &buf, const MessageCallback &callback)
{
    if (int currentRecvBufferSize = ConfirmBufferSize(sock); currentRecvBufferSize != bufferSize) {
        bufferSize = currentRecvBufferSize;
        if (bufferSize <= 0 || bufferSize > MAX_SOCKET_BUFFER_SIZE) {
            NETSTACK_LOGD("buffer size is out of range, size: %{public}d", bufferSize);
            bufferSize = DEFAULT_BUFFER_SIZE;
        }
        buf.reset(new (std::nothrow) char[bufferSize]);
        if (buf == nullptr) {
            callback.OnError(NO_MEMORY);
            return NO_MEMORY;
        }
    }
    (void)memset_s(buf.get(), bufferSize, 0, bufferSize);
    return 0;
}

static int ExitOrAbnormal(int sock, ssize_t recvLen, const MessageCallback &callback)
{
    if (!IsTCPSocket(sock) && errno != EBADF) {
        NETSTACK_LOGI("not tcpsocket, continue loop, recvLen: %{public}zd, err: %{public}d", recvLen, errno);
        if (errno == ENOTSOCK) {
            return -1;
        }
        return 0;
    }
    if (recvLen == 0) {
        NETSTACK_LOGI("closed by peer, socket:%{public}d, recvLen:%{public}zd", sock, recvLen);
        callback.OnCloseMessage(callback.GetEventManager());
        return -1;
    }
    if (errno == EAGAIN || errno == EINTR) {
        return 0;
    }
    
    if (callback.GetEventManager() != nullptr && static_cast<int>(
        reinterpret_cast<uint64_t>(callback.GetEventManager()->GetData())) > 0) {
        NETSTACK_LOGE("recv fail, socket:%{public}d, recvLen:%{public}zd, errno:%{public}d", sock, recvLen, errno);
        callback.OnError(errno);
    }
    return -1;
}

static inline void PollRecvFinish(const MessageCallback &callback)
{
    auto manager = callback.GetEventManager();
    if (manager != nullptr) {
        manager->NotifyRcvThdExit();
    } else {
        NETSTACK_LOGE("manager is error");
    }
}

static void ProcessPollResult(int currentFd, const MessageCallback &callback)
{
    if (callback.GetEventManager() != nullptr) {
        if (static_cast<int>(reinterpret_cast<uint64_t>(callback.GetEventManager()->GetData())) > 0) {
            NETSTACK_LOGE("poll to recv failed, socket is %{public}d, errno is %{public}d", currentFd, errno);
            callback.OnError(errno);
        }
        auto inst = callback.GetEventManager()->GetProxyData();
        if (inst != nullptr) {
            inst->OnProxySocketError();
        }
    }
}

static bool SocketRecvHandle(int socketId, std::pair<std::unique_ptr<char[]> &, int> &bufInfo,
    std::pair<sockaddr *, socklen_t> &addrInfo, const MessageCallback &callback)
{
    if (UpdateRecvBuffer(socketId, bufInfo.second, bufInfo.first, callback) < 0) {
        return false;
    }

    socklen_t tempAddrLen = addrInfo.second;
    auto recvLen = recvfrom(socketId, bufInfo.first.get(), bufInfo.second, 0, addrInfo.first, &tempAddrLen);
    if (recvLen <= 0) {
        if (ExitOrAbnormal(socketId, recvLen, callback) < 0) {
            return false;
        }
        return true;
    }
    if (callback.GetEventManager() && !callback.GetEventManager()->GetContextState()) {
        return false; // close fd 后 客户端socket read区被丢弃， 不走OnMessage处理
    }
    void *data = malloc(recvLen);
    if (data == nullptr) {
        callback.OnError(NO_MEMORY);
        return false;
    }
    if (memcpy_s(data, recvLen, bufInfo.first.get(), recvLen) != EOK ||
        !callback.OnMessage(data, recvLen, addrInfo.first)) {
        free(data);
    }
    return true;
}

static bool ProcessRecvFds(std::pair<std::unique_ptr<char[]> &, int> &bufInfo,
    std::pair<sockaddr *, socklen_t> &addrInfo, const MessageCallback &callback, std::vector<pollfd> &fds,
    std::unordered_map<int, SocketRecvCallback> &socketCallbackMap)
{
    for (auto &fd : fds) {
        if ((static_cast<uint16_t>(fd.revents) & POLLERR) || (static_cast<uint16_t>(fd.revents) & POLLNVAL)) {
            NETSTACK_LOGE("recv fail, socket:%{public}d, errno:%{public}d, revent:%{public}x",
                fd.fd, errno, fd.revents);
            if (callback.GetEventManager() != nullptr && static_cast<int>(
                reinterpret_cast<uint64_t>(callback.GetEventManager()->GetData())) > 0) {
                callback.OnError(errno);
            }
            return false;
        }
        if ((static_cast<uint16_t>(fd.revents) & POLLIN) == 0) {
            continue;
        }
        auto it = socketCallbackMap.find(fd.fd);
        if (it == socketCallbackMap.end()) {
            continue;
        }
        auto cb = it->second;
        if (cb != nullptr && !cb(fd.fd, bufInfo, addrInfo, callback)) {
            return false;
        }
    }
    return true;
}

static bool PreparePollFds(int &currentFd, std::vector<pollfd> &fds,
                           std::unordered_map<int, SocketRecvCallback> &socketCallbackMap,
                           const MessageCallback &callback)
{
    socketCallbackMap.clear();
    fds.clear();

    auto manager = callback.GetEventManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is error");
        return false;
    }

    currentFd = static_cast<int>(reinterpret_cast<uint64_t>(manager->GetData()));
    if (currentFd <= 0) {
        NETSTACK_LOGE("currentFd: %{public}d is error", currentFd);
        return false;
    }

    socketCallbackMap[currentFd] = SocketRecvHandle;
    fds.push_back({currentFd, POLLIN, 0});

    auto inst = manager->GetProxyData();
    if (inst != nullptr && inst->IsConnected()) {
        if (inst->GetSocketId() != -1 && inst->GetSocketId() != currentFd) {
            socketCallbackMap[inst->GetSocketId()] = inst->GetProxySocketRecvCallback();
            fds.push_back({inst->GetSocketId(), POLLIN, 0});
        }
    }
    return true;
}

static void PollRecvData(sockaddr *addr, socklen_t addrLen, const MessageCallback &callback)
{
    std::shared_ptr<EventManager> manager = callback.GetEventManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    int socketfd = manager->GetData()? static_cast<int>(reinterpret_cast<uint64_t>(manager->GetData())) : -1;
    if (socketfd < 0) {
        PollRecvFinish(callback);
        NETSTACK_LOGE("fd is nullptr or closed");
        return;
    }
    int bufferSize = ConfirmBufferSize(socketfd);
    auto buf = std::make_unique<char[]>(bufferSize);
    auto addrDeleter = [](sockaddr *a) { free(reinterpret_cast<void *>(a)); };
    std::unique_ptr<sockaddr, decltype(addrDeleter)> pAddr(addr, addrDeleter);

    lock.unlock();
    std::pair<std::unique_ptr<char[]> &, int> bufInfo{buf, bufferSize};
    std::pair<sockaddr *, socklen_t> addrInfo{addr, addrLen};
    std::unordered_map<int, SocketRecvCallback> socketCallbackMap{};
    std::vector<pollfd> fds{};

    while (true) {
        int currentFd = -1;
        std::shared_lock<std::shared_mutex> lock2(manager->GetDataMutex());
        if (!PreparePollFds(currentFd, fds, socketCallbackMap, callback)) {
            break;
        }

        int ret = poll(fds.data(), fds.size(), DEFAULT_POLL_TIMEOUT);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            ProcessPollResult(currentFd, callback);
            break;
        } else if (ret == 0) {
            continue;
        }

        if (!ProcessRecvFds(bufInfo, addrInfo, callback, fds, socketCallbackMap)) {
            break;
        }
    }

    PollRecvFinish(callback);
}

static bool SetBaseOptions(int sock, ExtraOptionsBase *option)
{
    if (option->AlreadySetRecvBufSize()) {
        int size = static_cast<int>(option->GetReceiveBufferSize());
        if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<void *>(&size), sizeof(size)) < 0) {
            NETSTACK_LOGE("set SO_RCVBUF failed, fd: %{public}d", sock);
            return false;
        }
    }

    if (option->AlreadySetSendBufSize()) {
        int size = static_cast<int>(option->GetSendBufferSize());
        if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<void *>(&size), sizeof(size)) < 0) {
            NETSTACK_LOGE("set SO_SNDBUF failed, fd: %{public}d", sock);
            return false;
        }
    }

    if (option->AlreadySetReuseAddr()) {
        int reuse = static_cast<int>(option->IsReuseAddress());
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<void *>(&reuse), sizeof(reuse)) < 0) {
            NETSTACK_LOGE("set SO_REUSEADDR failed, fd: %{public}d", sock);
            return false;
        }
    }

    if (option->AlreadySetTimeout()) {
        int value = static_cast<int>(option->GetSocketTimeout());
        timeval timeout = {value / UNIT_CONVERSION_1000, (value % UNIT_CONVERSION_1000) * UNIT_CONVERSION_1000};
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<void *>(&timeout), sizeof(timeout)) < 0) {
            NETSTACK_LOGE("set SO_RCVTIMEO failed, fd: %{public}d", sock);
            return false;
        }
        if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<void *>(&timeout), sizeof(timeout)) < 0) {
            NETSTACK_LOGE("set SO_SNDTIMEO failed, fd: %{public}d", sock);
            return false;
        }
    }

    return true;
}

bool ExecBind(BindContext *context)
{
    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len;
    GetAddr(&context->address_, &addr4, &addr6, &addr, &len);
    if (addr == nullptr) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }

    int reuse = 0;
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    std::unique_lock<std::shared_mutex> lock(manager->GetDataMutex());
    int socketfd = manager->GetData() ? static_cast<int>(reinterpret_cast<uint64_t>(manager->GetData())) : -1;
    if (socketfd < 0) {
        NETSTACK_LOGE("fd is nullptr or closed");
        return false;
    }

    reuse = manager->GetReuseAddr();
    if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<void *>(&reuse), sizeof(reuse)) < 0) {
        NETSTACK_LOGE("set SO_REUSEADDR failed, fd: %{public}d", socketfd);
        context->SetErrorCode(errno);
        return false;
    }

    if (bind(socketfd, addr, len) < 0) {
        if (errno != EADDRINUSE) {
            ERROR_RETURN(context, "bind failed, socket:%{public}d, errno:%{public}d", socketfd, errno);
        }
        if (addr->sa_family == AF_INET) {
            NETSTACK_LOGI("distribute a random port");
            addr4.sin_port = 0; /* distribute a random port */
        } else if (addr->sa_family == AF_INET6) {
            NETSTACK_LOGI("distribute a random port");
            addr6.sin6_port = 0; /* distribute a random port */
        }
        if (bind(socketfd, addr, len) < 0) {
            ERROR_RETURN(context, "rebind failed, socket:%{public}d, errno:%{public}d", socketfd, errno);
        }
        NETSTACK_LOGI("rebind success");
    }
    NETSTACK_LOGI("bind success, sock:%{public}d", socketfd);

    return true;
}

bool ExecUdpBind(BindContext *context)
{
    if (!ExecBind(context)) {
        return false;
    }

    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len;
    GetAddr(&context->address_, &addr4, &addr6, &addr, &len);
    if (addr == nullptr) {
        NETSTACK_LOGE("get addr failed, addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }

    if (addr->sa_family == AF_INET) {
        void *pTmpAddr = malloc(sizeof(addr4));
        auto pAddr4 = reinterpret_cast<sockaddr *>(pTmpAddr);
        if (pAddr4 == nullptr) {
            NETSTACK_LOGE("no memory!");
            return false;
        }
        NETSTACK_LOGI("copy ret = %{public}d", memcpy_s(pAddr4, sizeof(addr4), &addr4, sizeof(addr4)));
        std::thread serviceThread(PollRecvData, pAddr4, sizeof(addr4),
                                  UdpMessageCallback(context->GetSharedManager()));
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
        pthread_setname_np(SOCKET_EXEC_UDP_BIND);
#else
        pthread_setname_np(serviceThread.native_handle(), SOCKET_EXEC_UDP_BIND);
#endif
        serviceThread.detach();
    } else if (addr->sa_family == AF_INET6) {
        void *pTmpAddr = malloc(sizeof(addr6));
        auto pAddr6 = reinterpret_cast<sockaddr *>(pTmpAddr);
        if (pAddr6 == nullptr) {
            NETSTACK_LOGE("no memory!");
            return false;
        }
        NETSTACK_LOGI("copy ret = %{public}d", memcpy_s(pAddr6, sizeof(addr6), &addr6, sizeof(addr6)));
        std::thread serviceThread(PollRecvData, pAddr6, sizeof(addr6),
                                  UdpMessageCallback(context->GetSharedManager()));
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
        pthread_setname_np(SOCKET_EXEC_UDP_BIND);
#else
        pthread_setname_np(serviceThread.native_handle(), SOCKET_EXEC_UDP_BIND);
#endif
        serviceThread.detach();
    }

    return true;
}

static std::shared_ptr<Socks5::Socks5UdpInstance> InitSocks5UdpInstance(UdpSendContext *context)
{
    const std::shared_ptr<Socks5::Socks5Option> opt{std::make_shared<Socks5::Socks5Option>()};
    opt->username_ = context->proxyOptions->username_;
    opt->password_ = context->proxyOptions->password_;
    opt->proxyAddress_.netAddress_ = context->proxyOptions->address_;
    socklen_t len;
    GetAddr(&opt->proxyAddress_.netAddress_, &opt->proxyAddress_.addrV4_, &opt->proxyAddress_.addrV6_,
        &opt->proxyAddress_.addr_, &len);
    if (opt->proxyAddress_.addr_ == nullptr) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return nullptr;
    }

    auto socks5Udp = std::make_shared<Socks5::Socks5UdpInstance>();
    socks5Udp->SetDestAddress(context->options.address);
    socks5Udp->AddHeader();
    socks5Udp->SetSocks5Option(opt);
    return socks5Udp;
}

static int HandleUdpProxyOptions(UdpSendContext *context)
{
    auto eventMgr = context->GetSharedManager();
    if (eventMgr == nullptr) {
        NETSTACK_LOGE("event manager is null");
        return -1;
    }

    if (context->proxyOptions->type_ != ProxyType::SOCKS5) {
        NETSTACK_LOGE("unsupport proxy type");
        return 0;
    }

    auto socks5Udp = eventMgr->GetProxyData();
    if (socks5Udp == nullptr) {
        socks5Udp = InitSocks5UdpInstance(context);
        if (socks5Udp == nullptr) {
            return -1;
        }
        socks5Udp->SetSocks5Instance(socks5Udp);
        eventMgr->SetProxyData(socks5Udp);
    }

    if (!socks5Udp->IsConnected()) {
        if (!socks5Udp->Connect()) {
            Socks5::Socks5Utils::SetProxyAuthError(context, socks5Udp);
            NapiUtils::CreateUvQueueWorkEnhanced(context->GetEnv(), context, SocketAsyncWork::UdpSendCallback);
            return -1;
        }
    }

    Socket::NetAddress bindAddr = socks5Udp->GetProxyBindAddress();
    context->options.SetData(socks5Udp->GetHeader() + context->options.GetData());

    // process wild address from some socks5 server
    if (bindAddr.GetAddress() == WILD_ADDRESS) {
        bindAddr.SetAddress(context->proxyOptions->address_.GetAddress());
    }
    context->options.address = bindAddr;

    return 0;
}

bool ExecUdpSend(UdpSendContext *context)
{
#ifdef FUZZ_TEST
    return true;
#endif
    if (!context->IsParseOK()) {
        return false;
    }

    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    if (context->GetSocketFd() <= 0) {
        context->SetError(ERRNO_BAD_FD, strerror(ERRNO_BAD_FD));
        NapiUtils::CreateUvQueueWorkEnhanced(context->GetEnv(), context, SocketAsyncWork::UdpSendCallback);
        return false;
    }

    if (context->proxyOptions != nullptr && HandleUdpProxyOptions(context) != 0) {
        return false;
    }

    bool result = UdpSendEvent(context);
    NapiUtils::CreateUvQueueWorkEnhanced(context->GetEnv(), context, SocketAsyncWork::UdpSendCallback);
    return result;
}

bool ExecTcpBind(BindContext *context)
{
    return ExecBind(context);
}

static std::shared_ptr<Socks5::Socks5TcpInstance> InitSocks5TcpInstance(ConnectContext *context)
{
    const std::shared_ptr<Socks5::Socks5Option> opt{std::make_shared<Socks5::Socks5Option>()};
    opt->username_ = context->proxyOptions->username_;
    opt->password_ = context->proxyOptions->password_;
    opt->proxyAddress_.netAddress_ = context->proxyOptions->address_;
    socklen_t len;
    GetAddr(&opt->proxyAddress_.netAddress_, &opt->proxyAddress_.addrV4_, &opt->proxyAddress_.addrV6_,
        &opt->proxyAddress_.addr_, &len);
    if (opt->proxyAddress_.addr_ == nullptr) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return nullptr;
    }

    auto socks5Tcp = std::make_shared<Socks5::Socks5TcpInstance>(context->GetSocketFd());
    socks5Tcp->SetDestAddress(context->options.address);
    socks5Tcp->SetSocks5Option(opt);
    return socks5Tcp;
}

static int HandleTcpProxyOptions(ConnectContext *context)
{
    auto eventMgr = context->GetSharedManager();
    if (eventMgr == nullptr) {
        NETSTACK_LOGE("event manager is null");
        return -1;
    }

    if (context->proxyOptions->type_ != ProxyType::SOCKS5) {
        NETSTACK_LOGE("unsupport proxy type");
        return 0;
    }

    auto socks5Tcp = eventMgr->GetProxyData();
    if (socks5Tcp == nullptr) {
        socks5Tcp = InitSocks5TcpInstance(context);
        if (socks5Tcp == nullptr) {
            return -1;
        }
        socks5Tcp->SetSocks5Instance(socks5Tcp);
        eventMgr->SetProxyData(socks5Tcp);
    }

    if (!socks5Tcp->IsConnected()) {
        if (!socks5Tcp->Connect()) {
            Socks5::Socks5Utils::SetProxyAuthError(context, socks5Tcp);
            return -1;
        }
    }

    return 0;
}

bool HandleNonProxyConnection(ConnectContext *context, sockaddr *addr, socklen_t len)
{
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    int socketfd = manager->GetData() ? static_cast<int>(reinterpret_cast<uint64_t>(manager->GetData())) : -1;
    if (socketfd < 0) {
        NETSTACK_LOGE("fd is nullptr or closed");
        return false;
    }
    if (!NonBlockConnect(context->GetSocketFd(), addr, len, context->options.GetTimeout())) {
        ERROR_RETURN(context, "connect errno %{public}d", errno);
    }
    return true;
}

bool ExecConnect(ConnectContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len;
    context->options.address.SetRawAddress(
        ConvertAddressToIp(context->options.address.GetAddress(), context->options.address.GetSaFamily()));
    if ((context->proxyOptions != nullptr)) {
        GetAddr(&context->proxyOptions->address_, &addr4, &addr6, &addr, &len);
    } else {
        GetAddr(&context->options.address, &addr4, &addr6, &addr, &len);
    }

    if (addr == nullptr) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }

    if (context->proxyOptions == nullptr) {
        if (!HandleNonProxyConnection(context, addr, len)) {
            return false;
        }
    } else {
        if (HandleTcpProxyOptions(context) != 0) {
            context->SetExecOK(false);
            return false;
        }
    }

    NETSTACK_LOGI("connect success, sock:%{public}d", context->GetSocketFd());

    std::thread serviceThread(PollRecvData, nullptr, 0,
                              TcpMessageCallback(context->GetSharedManager()));
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(SOCKET_EXEC_CONNECT);
#else
    pthread_setname_np(serviceThread.native_handle(), SOCKET_EXEC_CONNECT);
#endif
    serviceThread.detach();
    return true;
}

bool ExecTcpSend(TcpSendContext *context)
{
#ifdef FUZZ_TEST
    return true;
#endif
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!context->IsParseOK()) {
        return false;
    }

    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    std::shared_ptr<EventManager> manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    if (context->GetSocketFd() <= 0) {
        context->SetError(ERRNO_BAD_FD, strerror(ERRNO_BAD_FD));
        NapiUtils::CreateUvQueueWorkEnhanced(context->GetEnv(), context, SocketAsyncWork::TcpSendCallback);
        return false;
    }

    bool result = TcpSendEvent(context);
    NapiUtils::CreateUvQueueWorkEnhanced(context->GetEnv(), context, SocketAsyncWork::TcpSendCallback);
    return result;
}

bool ExecClose(CloseContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }

    auto inst = manager->GetProxyData();
    if (inst != nullptr) {
        inst->Close();
    }
    
    manager->SetContextState(false); // 加锁前先置close标志位，防止socket流发生close后仍在接收数据
    std::unique_lock<std::shared_mutex> lock(manager->GetDataMutex());
    if (context->GetSocketFd() < 0) {
        NETSTACK_LOGE("sock %{public}d is previous closed", context->GetSocketFd());
        context->SetErrorCode(UNKNOW_ERROR);
        return false;
    }
    int ret = close(context->GetSocketFd());
    if (ret < 0) {
        NETSTACK_LOGE("sock closed failed , socket is %{public}d, errno is %{public}d", context->GetSocketFd(), errno);
        context->SetErrorCode(UNKNOW_ERROR);
        return false;
    }
    NETSTACK_LOGI("sock %{public}d closed success", context->GetSocketFd());

    context->state_.SetIsClose(true);
    context->SetSocketFd(-1);

    return true;
}

static bool CheckClosed(GetStateContext *context, int &opt)
{
    socklen_t optLen = sizeof(int);
    int r = getsockopt(context->GetSocketFd(), SOL_SOCKET, SO_TYPE, &opt, &optLen);
    if (r < 0) {
        context->state_.SetIsClose(true);
        return true;
    }
    return false;
}

static bool CheckSocketFd(GetStateContext *context, sockaddr &sockAddr)
{
    socklen_t len = sizeof(sockaddr);
    int ret = getsockname(context->GetSocketFd(), &sockAddr, &len);
    if (ret < 0) {
        context->SetErrorCode(errno);
        return false;
    }
    return true;
}

static void SelectSockAddr(
    const sockaddr &sockAddr, sockaddr_in &addr4, sockaddr_in6 &addr6, sockaddr* &addr, socklen_t &addrlen)
{
    if (sockAddr.sa_family == AF_INET) {
        addr = reinterpret_cast<sockaddr *>(&addr4);
        addrlen = sizeof(addr4);
    } else if (sockAddr.sa_family == AF_INET6) {
        addr = reinterpret_cast<sockaddr *>(&addr6);
        addrlen = sizeof(addr6);
    }
}

static bool GetSocketState(GetStateContext *context)
{
    std::shared_ptr<EventManager> manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    int socketfd = manager->GetData()? static_cast<int>(reinterpret_cast<uint64_t>(manager->GetData())) : -1;
    if (socketfd < 0) {
        NETSTACK_LOGE("fd is nullptr or closed");
        context->state_.SetIsClose(true);
        return true;
    }
    int opt;
    if (CheckClosed(context, opt)) {
        return true;
    }

    sockaddr sockAddr = {0};
    if (!CheckSocketFd(context, sockAddr)) {
        return false;
    }

    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t addrLen;
    SelectSockAddr(sockAddr, addr4, addr6, addr, addrLen);

    if (addr == nullptr) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }

    (void)memset_s(addr, addrLen, 0, addrLen);
    socklen_t len = addrLen;
    int ret = getsockname(context->GetSocketFd(), addr, &len);
    if (ret < 0) {
        context->SetErrorCode(errno);
        return false;
    }

    SetIsBound(sockAddr.sa_family, context, &addr4, &addr6);

    if (opt != SOCK_STREAM) {
        return true;
    }

    (void)memset_s(addr, addrLen, 0, addrLen);
    len = addrLen;
    (void)getpeername(context->GetSocketFd(), addr, &len);
    SetIsConnected(sockAddr.sa_family, context, &addr4, &addr6);
    return true;
}

bool ExecGetState(GetStateContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGI("manager is nullptr");
        return false;
    }
    if (!manager->GetData()) {
        return true;
    }

    return GetSocketState(context);
}

bool IsAddressAndRetValid(const int &ret, const std::string &address, GetRemoteAddressContext *context)
{
    if (ret < 0) {
        context->SetErrorCode(errno);
        return false;
    }
    if (address.empty()) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }
    return true;
}

bool ExecGetRemoteAddress(GetRemoteAddressContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    sockaddr sockAddr = {0};
    socklen_t len = sizeof(sockaddr);
    int ret = getsockname(context->GetSocketFd(), &sockAddr, &len);
    if (ret < 0) {
        context->SetErrorCode(errno);
        return false;
    }

    if (sockAddr.sa_family == AF_INET) {
        sockaddr_in addr4 = {0};
        socklen_t len4 = sizeof(sockaddr_in);

        ret = getpeername(context->GetSocketFd(), reinterpret_cast<sockaddr *>(&addr4), &len4);
        std::string address = MakeAddressString(reinterpret_cast<sockaddr *>(&addr4));
        if (!IsAddressAndRetValid(ret, address, context)) {
            return false;
        }
        context->address_.SetRawAddress(address);
        context->address_.SetFamilyBySaFamily(sockAddr.sa_family);
        context->address_.SetPort(ntohs(addr4.sin_port));
        return true;
    } else if (sockAddr.sa_family == AF_INET6) {
        sockaddr_in6 addr6 = {0};
        socklen_t len6 = sizeof(sockaddr_in6);

        ret = getpeername(context->GetSocketFd(), reinterpret_cast<sockaddr *>(&addr6), &len6);
        std::string address = MakeAddressString(reinterpret_cast<sockaddr *>(&addr6));
        if (!IsAddressAndRetValid(ret, address, context)) {
            return false;
        }
        context->address_.SetRawAddress(address);
        context->address_.SetFamilyBySaFamily(sockAddr.sa_family);
        context->address_.SetPort(ntohs(addr6.sin6_port));
        return true;
    }

    return false;
}

static bool SocketSetTcpExtraOptions(int sockfd, TCPExtraOptions& option)
{
    if (!SetBaseOptions(sockfd, &option)) {
        return false;
    }
    if (option.AlreadySetKeepAlive()) {
        int alive = static_cast<int>(option.IsKeepAlive());
        if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<void*>(&alive), sizeof(alive)) < 0) {
            NETSTACK_LOGE("set SO_KEEPALIVE failed, fd: %{public}d", sockfd);
            return false;
        }
    }

    if (option.AlreadySetOobInline()) {
        int oob = static_cast<int>(option.IsOOBInline());
        if (setsockopt(sockfd, SOL_SOCKET, SO_OOBINLINE, reinterpret_cast<void*>(&oob), sizeof(oob)) < 0) {
            NETSTACK_LOGE("set SO_OOBINLINE failed, fd: %{public}d", sockfd);
            return false;
        }
    }

    if (option.AlreadySetTcpNoDelay()) {
        int noDelay = static_cast<int>(option.IsTCPNoDelay());
        if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<void*>(&noDelay), sizeof(noDelay)) < 0) {
            NETSTACK_LOGE("set TCP_NODELAY failed, fd: %{public}d", sockfd);
            return false;
        }
    }

    if (option.AlreadySetLinger()) {
        linger soLinger = {.l_onoff = option.socketLinger.IsOn(),
                           .l_linger = static_cast<int>(option.socketLinger.GetLinger())};
        if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &soLinger, sizeof(soLinger)) < 0) {
            NETSTACK_LOGE("set SO_LINGER failed, fd: %{public}d", sockfd);
            return false;
        }
    }
    return true;
}

bool ExecTcpSetExtraOptions(TcpSetExtraOptionsContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    if (context->GetSocketFd() <= 0) {
        context->SetError(ERRNO_BAD_FD, strerror(ERRNO_BAD_FD));
        return false;
    }

    if (!SocketSetTcpExtraOptions(context->GetSocketFd(), context->options_)) {
        context->SetErrorCode(errno);
        return false;
    }
    return true;
}

bool ExecUdpSetExtraOptions(UdpSetExtraOptionsContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    int sockfd = context->GetSocketFd();
    if (sockfd <= 0) {
        context->SetError(ERRNO_BAD_FD, strerror(ERRNO_BAD_FD));
        return false;
    }

    if (!SetBaseOptions(sockfd, &context->options)) {
        context->SetErrorCode(errno);
        return false;
    }

    if (context->options.AlreadySetBroadcast()) {
        int broadcast = static_cast<int>(context->options.IsBroadcast());
        if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
            context->SetErrorCode(errno);
            return false;
        }
    }

    return true;
}

void RecvfromMulticastSetThreadName(pthread_t threadhandle)
{
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(SOCKET_RECV_FROM_MULTI_CAST);
#else
    pthread_setname_np(threadhandle, SOCKET_RECV_FROM_MULTI_CAST);
#endif
}

bool RecvfromMulticast(MulticastMembershipContext *context)
{
    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len = 0;
    GetAddr(&context->address_, &addr4, &addr6, &addr, &len);
    if (addr == nullptr) {
        NETSTACK_LOGE("get addr failed, addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }

    if (addr->sa_family == AF_INET) {
        void *pTmpAddr = malloc(sizeof(addr4));
        auto pAddr4 = reinterpret_cast<sockaddr *>(pTmpAddr);
        if (pAddr4 == nullptr) {
            return false;
        }
        addr4.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(context->GetSocketFd(), reinterpret_cast<struct sockaddr *>(&addr4), sizeof(addr4)) < 0) {
            free(pTmpAddr);
            ERROR_RETURN(context, "v4bind err, port:%{public}d, errno:%{public}d", context->address_.GetPort(), errno);
        }
        NETSTACK_LOGI("copy ret = %{public}d", memcpy_s(pAddr4, sizeof(addr4), &addr4, sizeof(addr4)));
        std::thread serviceThread(PollRecvData, pAddr4, sizeof(addr4),
                                  UdpMessageCallback(context->GetSharedManager()));
        RecvfromMulticastSetThreadName(serviceThread.native_handle());
        serviceThread.detach();
    } else if (addr->sa_family == AF_INET6) {
        void *pTmpAddr = malloc(sizeof(addr6));
        auto pAddr6 = reinterpret_cast<sockaddr *>(pTmpAddr);
        if (pAddr6 == nullptr) {
            return false;
        }
        addr6.sin6_addr = in6addr_any;
        if (bind(context->GetSocketFd(), reinterpret_cast<struct sockaddr *>(&addr6), sizeof(addr6)) < 0) {
            free(pTmpAddr);
            ERROR_RETURN(context, "v6bind err, port:%{public}d, errno:%{public}d", context->address_.GetPort(), errno);
        }
        NETSTACK_LOGI("copy ret = %{public}d", memcpy_s(pAddr6, sizeof(addr6), &addr6, sizeof(addr6)));
        std::thread serviceThread(PollRecvData, pAddr6, sizeof(addr6),
                                  UdpMessageCallback(context->GetSharedManager()));
        RecvfromMulticastSetThreadName(serviceThread.native_handle());
        serviceThread.detach();
    }
    return true;
}

static inline int GetSockFamily(int fd)
{
    sockaddr sockAddr = {0};
    socklen_t len = sizeof(sockaddr);
    return (getsockname(fd, &sockAddr, &len) < 0) ? -1 : sockAddr.sa_family;
}

bool ExecUdpAddMembership(MulticastMembershipContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    if (context->address_.GetFamily() == NetAddress::Family::IPv4) {
        ip_mreq mreq = {};
        mreq.imr_multiaddr.s_addr = inet_addr(context->address_.GetAddress().c_str());
        mreq.imr_interface.s_addr = INADDR_ANY;
        if (setsockopt(context->GetSocketFd(), IPPROTO_IP, IP_ADD_MEMBERSHIP, reinterpret_cast<void *>(&mreq),
                       sizeof(mreq)) == -1) {
            NETSTACK_LOGE("ipv4 addmembership err: %{public}d", errno);
            context->SetErrorCode(errno);
            return false;
        }
    } else {
        ipv6_mreq mreq = {};
        inet_pton(AF_INET6, context->address_.GetAddress().c_str(), &mreq.ipv6mr_multiaddr);
        mreq.ipv6mr_interface = 0;
        if (setsockopt(context->GetSocketFd(), IPPROTO_IPV6, IPV6_JOIN_GROUP, reinterpret_cast<void *>(&mreq),
                       sizeof(mreq)) == -1) {
            NETSTACK_LOGE("ipv6 addmembership err: %{public}d", errno);
            context->SetErrorCode(errno);
            return false;
        }
    }
    NETSTACK_LOGI("addmembership ok, sock:%{public}d", context->GetSocketFd());
    return RecvfromMulticast(context);
}

bool ExecUdpDropMembership(MulticastMembershipContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    if (context->address_.GetFamily() == NetAddress::Family::IPv4) {
        ip_mreq mreq = {};
        mreq.imr_multiaddr.s_addr = inet_addr(context->address_.GetAddress().c_str());
        mreq.imr_interface.s_addr = INADDR_ANY;
        if (setsockopt(context->GetSocketFd(), IPPROTO_IP, IP_DROP_MEMBERSHIP, reinterpret_cast<void *>(&mreq),
                       sizeof(mreq)) == -1) {
            NETSTACK_LOGE("ipv4 dropmembership err: %{public}d", errno);
            context->SetErrorCode(errno);
            return false;
        }
    } else {
        ipv6_mreq mreq = {};
        inet_pton(AF_INET6, context->address_.GetAddress().c_str(), &mreq.ipv6mr_multiaddr);
        mreq.ipv6mr_interface = 0;
        if (setsockopt(context->GetSocketFd(), IPPROTO_IPV6, IPV6_LEAVE_GROUP, reinterpret_cast<void *>(&mreq),
                       sizeof(mreq)) == -1) {
            NETSTACK_LOGE("ipv6 dropmembership err: %{public}d", errno);
            context->SetErrorCode(errno);
            return false;
        }
    }

    if (close(context->GetSocketFd()) < 0) {
        NETSTACK_LOGE("sock closed failed , socket is %{public}d, errno is %{public}d", context->GetSocketFd(), errno);
        context->SetErrorCode(errno);
        return false;
    }
    NETSTACK_LOGI("ExecUdpDropMembership sock: %{public}d closed success", context->GetSocketFd());
    context->SetSocketFd(0);
    return true;
}

bool ExecSetMulticastTTL(MulticastSetTTLContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    int ttl = context->GetMulticastTTL();
    int family = GetSockFamily(context->GetSocketFd());
    if (setsockopt(context->GetSocketFd(), (family == AF_INET) ? IPPROTO_IP : IPPROTO_IPV6, (family == AF_INET) ?
        IP_MULTICAST_TTL : IPV6_MULTICAST_HOPS, reinterpret_cast<void *>(&ttl), sizeof(ttl)) == -1) {
        ERROR_RETURN(context, "set ttl err, ttl:%{public}d, family:%{public}d, errno:%{public}d", ttl, family, errno);
    }
    return true;
}

bool ExecGetMulticastTTL(MulticastGetTTLContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    int ttl = 0;
    socklen_t ttlLen = sizeof(ttl);
    int family = GetSockFamily(context->GetSocketFd());
    if (getsockopt(context->GetSocketFd(), (family == AF_INET) ? IPPROTO_IP : IPPROTO_IPV6, (family == AF_INET) ?
        IP_MULTICAST_TTL : IPV6_MULTICAST_HOPS, reinterpret_cast<void *>(&ttl), &ttlLen) == -1) {
        ERROR_RETURN(context, "get ttl err, family:%{public}d, errno:%{public}d", family, errno);
    }
    context->SetMulticastTTL(ttl);
    return true;
}

bool ExecSetLoopbackMode(MulticastSetLoopbackContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    int mode = static_cast<int>(context->GetLoopbackMode());
    int family = GetSockFamily(context->GetSocketFd());
    if (setsockopt(context->GetSocketFd(), (family == AF_INET) ? IPPROTO_IP : IPPROTO_IPV6, (family == AF_INET) ?
        IP_MULTICAST_LOOP : IPV6_MULTICAST_LOOP, reinterpret_cast<void *>(&mode), sizeof(mode)) == -1) {
        ERROR_RETURN(context, "setloopback err, mode:%{public}d, fa:%{public}d, err:%{public}d", mode, family, errno);
    }
    return true;
}

bool ExecGetLoopbackMode(MulticastGetLoopbackContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    int mode = 0;
    socklen_t len = sizeof(mode);
    int family = GetSockFamily(context->GetSocketFd());
    if (getsockopt(context->GetSocketFd(), (family == AF_INET) ? IPPROTO_IP : IPPROTO_IPV6, (family == AF_INET) ?
        IP_MULTICAST_LOOP : IPV6_MULTICAST_LOOP, reinterpret_cast<void *>(&mode), &len) == -1) {
        ERROR_RETURN(context, "getloopback err, family:%{public}d, errno:%{public}d", family, errno);
    }
    context->SetLoopbackMode(static_cast<bool>(mode));
    return true;
}

bool ExecTcpGetSocketFd(GetSocketFdContext *context)
{
    return true;
}

bool ExecUdpGetSocketFd(GetSocketFdContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    return true;
}

static bool GetIPv4Address(TcpServerGetRemoteAddressContext *context, int32_t fd, sockaddr sockAddr)
{
    sockaddr_in addr4 = {0};
    socklen_t len4 = sizeof(sockaddr_in);

    int ret = getpeername(fd, reinterpret_cast<sockaddr *>(&addr4), &len4);
    if (ret < 0) {
        context->SetErrorCode(errno);
        return false;
    }

    std::string address = MakeAddressString(reinterpret_cast<sockaddr *>(&addr4));
    if (address.empty()) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }
    context->address_.SetRawAddress(address);
    context->address_.SetFamilyBySaFamily(sockAddr.sa_family);
    context->address_.SetPort(ntohs(addr4.sin_port));
    return true;
}

static bool GetIPv6Address(TcpServerGetRemoteAddressContext *context, int32_t fd, sockaddr sockAddr)
{
    sockaddr_in6 addr6 = {0};
    socklen_t len6 = sizeof(sockaddr_in6);

    int ret = getpeername(fd, reinterpret_cast<sockaddr *>(&addr6), &len6);
    if (ret < 0) {
        context->SetErrorCode(errno);
        return false;
    }

    std::string address = MakeAddressString(reinterpret_cast<sockaddr *>(&addr6));
    if (address.empty()) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }
    context->address_.SetRawAddress(address);
    context->address_.SetFamilyBySaFamily(sockAddr.sa_family);
    context->address_.SetPort(ntohs(addr6.sin6_port));
    return true;
}

bool ExecTcpConnectionGetRemoteAddress(TcpServerGetRemoteAddressContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    int32_t clientFd = -1;
    bool fdValid = false;

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto iter = g_clientFDs.find(context->clientId_);
        if (iter != g_clientFDs.end()) {
            fdValid = true;
            clientFd = iter->second;
        } else {
            NETSTACK_LOGE("not find clientId");
        }
    }

    if (!fdValid) {
        NETSTACK_LOGE("client fd is invalid");
        context->SetError(OTHER_ERROR, "client fd is invalid");
        return false;
    }

    sockaddr sockAddr = {0};
    socklen_t len = sizeof(sockaddr);
    int ret = getsockname(clientFd, &sockAddr, &len);
    if (ret < 0) {
        context->SetError(errno, strerror(errno));
        return false;
    }

    if (sockAddr.sa_family == AF_INET) {
        return GetIPv4Address(context, clientFd, sockAddr);
    } else if (sockAddr.sa_family == AF_INET6) {
        return GetIPv6Address(context, clientFd, sockAddr);
    }

    return false;
}

bool ExecTcpConnectionGetLocalAddress(TcpConnectionGetLocalAddressContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    int32_t clientFd = -1;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto iter = g_clientFDs.find(context->clientId_);
        if (iter != g_clientFDs.end()) {
            clientFd = iter->second;
        } else {
            NETSTACK_LOGE("not find clientId");
        }
    }
    struct sockaddr_storage addr{};
    socklen_t addrLen = sizeof(addr);
    if (getsockname(clientFd, reinterpret_cast<struct sockaddr *>(&addr), &addrLen) < 0) {
        context->SetNeedThrowException(true);
        context->SetErrorCode(errno);
        return false;
    }

    char ipStr[INET6_ADDRSTRLEN] = {0};
    Socket::NetAddress localAddress;
    if (addr.ss_family == AF_INET) {
        auto *addrIn = reinterpret_cast<struct sockaddr_in *>(&addr);
        inet_ntop(AF_INET, &addrIn->sin_addr, ipStr, sizeof(ipStr));
        localAddress.SetFamilyBySaFamily(AF_INET);
        localAddress.SetRawAddress(ipStr);
        localAddress.SetPort(ntohs(addrIn->sin_port));
        context->localAddress_ = localAddress;
    } else if (addr.ss_family == AF_INET6) {
        auto *addrIn6 = reinterpret_cast<struct sockaddr_in6 *>(&addr);
        inet_ntop(AF_INET6, &addrIn6->sin6_addr, ipStr, sizeof(ipStr));
        localAddress.SetFamilyBySaFamily(AF_INET6);
        localAddress.SetRawAddress(ipStr);
        localAddress.SetPort(ntohs(addrIn6->sin6_port));
        context->localAddress_ = localAddress;
    }
    return true;
}

bool ExecTcpConnectionGetSocketFd(TcpServerGetSocketFdContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    int32_t clientFd = -1;
    bool fdValid = false;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto iter = g_clientFDs.find(context->clientId_);
        if (iter != g_clientFDs.end()) {
            fdValid = true;
            clientFd = iter->second;
        } else {
            NETSTACK_LOGE("not find clientId: %d in g_clientFDs", context->clientId_);
            clientFd = -1;
        }
    }
    context->socketFd_ = clientFd;
    if (!fdValid || clientFd < 0) {
        NETSTACK_LOGE("client fd is invalid (fd: %d)", clientFd);
    } else {
        NETSTACK_LOGI("get socketfd success: %d for clientId: %d", clientFd, context->clientId_);
    }
    return true;
}

static bool IsRemoteConnect(TcpServerSendContext *context, int32_t clientFd)
{
    sockaddr sockAddr = {0};
    socklen_t len = sizeof(sockaddr);
    if (getsockname(clientFd, &sockAddr, &len) < 0) {
        NETSTACK_LOGE("get sock name failed, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }
    bool connected = false;
    if (sockAddr.sa_family == AF_INET) {
        sockaddr_in addr4 = {0};
        socklen_t len4 = sizeof(addr4);
        int ret = getpeername(clientFd, reinterpret_cast<sockaddr *>(&addr4), &len4);
        if (ret >= 0 && addr4.sin_port != 0) {
            connected = true;
        }
    } else if (sockAddr.sa_family == AF_INET6) {
        sockaddr_in6 addr6 = {0};
        socklen_t len6 = sizeof(addr6);
        int ret = getpeername(clientFd, reinterpret_cast<sockaddr *>(&addr6), &len6);
        if (ret >= 0 && addr6.sin6_port != 0) {
            connected = true;
        }
    }

    if (!connected) {
        ERROR_RETURN(context, "sock is not connect to remote, socket:%{public}d, errno:%{public}d", clientFd, errno);
    }
    return true;
}

bool ExecTcpConnectionSend(TcpServerSendContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    int32_t clientFd = -1;
    bool fdValid = false;

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto iter = g_clientFDs.find(context->clientId_);
        if (iter != g_clientFDs.end()) {
            fdValid = true;
            clientFd = iter->second;
        } else {
            NETSTACK_LOGE("not find clientId");
        }
    }

    if (!fdValid) {
        NETSTACK_LOGE("client fd is invalid");
        context->SetError(OTHER_ERROR, "client fd is invalid");
        return false;
    }

    std::string encoding = context->options.GetEncoding();
    (void)encoding;
    /* no use for now */

    if (!IsRemoteConnect(context, clientFd)) {
        return false;
    }

    if (!PollSendData(clientFd, context->options.GetData().c_str(), context->options.GetData().size(), nullptr, 0)) {
        NETSTACK_LOGE("send failed, , socket is %{public}d, errno is %{public}d", clientFd, errno);
        context->SetError(errno, strerror(errno));
        return false;
    }
    return true;
}

bool ExecTcpConnectionClose(TcpServerCloseContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    bool fdValid = false;

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto iter = g_clientFDs.find(context->clientId_);
        if (iter != g_clientFDs.end()) {
            fdValid = true;
        } else {
            NETSTACK_LOGE("not find clientId: %{public}d", context->clientId_);
        }
    }

    if (!fdValid) {
        NETSTACK_LOGE("client fd: %{public}d is invalid", context->clientId_);
        context->SetError(OTHER_ERROR, "client fd is invalid");
        return false;
    }

    return true;
}

static bool ServerBind(TcpServerListenContext *context)
{
    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len;
    GetAddr(&context->address_, &addr4, &addr6, &addr, &len);
    if (addr == nullptr) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetError(ADDRESS_INVALID, "addr family error, address invalid");
        return false;
    }

    if (bind(context->GetSocketFd(), addr, len) < 0) {
        if (errno != EADDRINUSE) {
            NETSTACK_LOGE("bind failed, socket is %{public}d, errno is %{public}d", context->GetSocketFd(), errno);
            context->SetError(errno, strerror(errno));
            return false;
        }
        if (addr->sa_family == AF_INET) {
            NETSTACK_LOGI("distribute a random port");
            addr4.sin_port = 0; /* distribute a random port */
        } else if (addr->sa_family == AF_INET6) {
            NETSTACK_LOGI("distribute a random port");
            addr6.sin6_port = 0; /* distribute a random port */
        }
        if (bind(context->GetSocketFd(), addr, len) < 0) {
            NETSTACK_LOGE("rebind failed, socket is %{public}d, errno is %{public}d", context->GetSocketFd(), errno);
            context->SetError(errno, strerror(errno));
            return false;
        }
        NETSTACK_LOGI("rebind success");
    }
    NETSTACK_LOGI("bind success");

    return true;
}

static bool IsClientFdClosed(int32_t clientFd)
{
    return (fcntl(clientFd, F_GETFL) == -1 && errno == EBADF);
}

static void RemoveClientConnection(int32_t clientId, TcpServerCloseContext *context)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    std::shared_ptr<EventManager> manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return;
    }
    for (auto it = g_clientFDs.begin(); it != g_clientFDs.end(); ++it) {
        if (it->first == clientId) {
            NETSTACK_LOGI("remove clientfd and eventmanager clientid: %{public}d clientFd:%{public}d", it->first,
                          it->second);
            if (!IsClientFdClosed(it->second)) {
                std::unique_lock<std::shared_mutex> lock(manager->GetDataMutex());
                NETSTACK_LOGI("connectFD: %{public}d, not close should close", it->second);
                shutdown(it->second, SHUT_RDWR);
                close(it->second);
                context->SetSocketFd(-1);
            }

            g_clientFDs.erase(it->first);
            break;
        }
    }
}

static void RemoveClientConnection(int32_t clientId)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    for (auto it = g_clientFDs.begin(); it != g_clientFDs.end(); ++it) {
        if (it->first == clientId) {
            NETSTACK_LOGI("remove clientfd and eventmanager clientid: %{public}d clientFd:%{public}d", it->first,
                          it->second);
            if (!IsClientFdClosed(it->second)) {
                NETSTACK_LOGI("connectFD: %{public}d, not close should close", it->second);
                shutdown(it->second, SHUT_RDWR);
                close(it->second);
            }

            g_clientFDs.erase(it->first);
            break;
        }
    }
}

static std::shared_ptr<EventManager> WaitForManagerReady(int32_t clientId, int &connectFd)
{
    std::shared_ptr<EventManager> manager = nullptr;
    std::unique_lock<std::mutex> lock(g_mutex);
    g_cv.wait(lock, [&manager, &clientId]() {
        auto iter = g_clientEventManagers.find(clientId);
        if (iter != g_clientEventManagers.end()) {
            manager = iter->second;
            if (manager->HasEventListener(EVENT_MESSAGE)) {
                NETSTACK_LOGI("manager is ready with registering message event");
                return true;
            }
        } else {
            NETSTACK_LOGE("iter==g_clientEventManagers.end()");
        }
        return false;
    });
    connectFd = g_clientFDs[clientId];
    return manager;
}

static inline void RecvInErrorCondition(int reason, int clientId, int connectFD, const TcpMessageCallback &callback)
{
    NETSTACK_LOGE("Recv Error, reason: %{public}d, clientId: %{public}d,"
        "connectFD: %{public}d", reason, clientId, connectFD);
    RemoveClientConnection(clientId);
    auto config = GetSharedConfig(callback.GetEventManager());
    if (config == nullptr) {
        return;
    }
    config->RemoveAcceptSocket(connectFD);
    callback.OnError(reason);
}

static inline void CloseClientHandler(int clientId, int connectFD, const std::shared_ptr<EventManager> &manager,
    const TcpMessageCallback &callback)
{
    callback.OnCloseMessage(manager);
    RemoveClientConnection(clientId);
    auto config = GetSharedConfig(callback.GetEventManager());
    if (config == nullptr) {
        return;
    }
    config->RemoveAcceptSocket(connectFD);
}

static int PollSocket(int clientId, int connectFD, const std::shared_ptr<EventManager> &manager,
    const TcpMessageCallback &callback)
{
    pollfd fds[1] = {{connectFD, POLLIN, 0}};
    int ret = poll(fds, 1, DEFAULT_POLL_TIMEOUT);
    if (ret < 0) {
        if (errno == EINTR) {
            return 0;
        }
        NETSTACK_LOGE("Client poll to recv failed, socket is %{public}d, errno is %{public}d", connectFD, errno);
        callback.OnCloseMessage(manager);
        CloseClientHandler(clientId, connectFD, manager, callback);
        return -1;
    } else if (ret == 0) {
        return 0;
    }
    return 1;
}

static bool IsValidSock(int &currentFd, const std::shared_ptr<EventManager> &manager)
{
    if (manager != nullptr) {
        currentFd = static_cast<int>(reinterpret_cast<uint64_t>(manager->GetData()));
        if (currentFd <= 0) {
            NETSTACK_LOGD("currentFd: %{public}d is error", currentFd);
            return false;
        }
    } else {
        NETSTACK_LOGE("manager is error");
        return false;
    }
    return true;
}

static int RecvWithSockCheck(int connectFD, char *buffer, uint32_t recvBufferSize,
    const std::shared_ptr<EventManager> &manager, int &recvSize)
{
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    if (buffer == nullptr) {
        return -1;
    }
    int currentFd = -1;
    if (!IsValidSock(currentFd, manager)) {
        return -1;
    }
    recvSize = recv(connectFD, buffer, recvBufferSize, 0);
    return 0;
}

static void ClientPollRecv(int clientId, int connectFD, uint32_t recvBufferSize,
    const std::shared_ptr<EventManager> &manager, const TcpMessageCallback &callback)
{
    auto buffer = std::make_unique<char[]>(recvBufferSize);
    if (buffer == nullptr) {
        RecvInErrorCondition(NO_MEMORY, clientId, connectFD, callback);
        return;
    }
    while (true) {
        if (memset_s(buffer.get(), recvBufferSize, 0, recvBufferSize) != EOK) {
            RecvInErrorCondition(UNKNOW_ERROR, clientId, connectFD, callback);
            break;
        }
        int ret = PollSocket(clientId, connectFD, manager, callback);
        if (ret < 0) {
            break;
        } else if (ret == 0) {
            continue;
        }
        int recvSize = 0;
        if (RecvWithSockCheck(connectFD, buffer.get(), recvBufferSize, manager, recvSize) < 0) {
            CloseClientHandler(clientId, connectFD, manager, callback);
            break;
        }
        if (fcntl(connectFD, F_GETFL, 0) == -1) {
            NETSTACK_LOGE("Client socket %{public}d fcntl F_GETFL error, errno is %{public}d", connectFD, errno);
            CloseClientHandler(clientId, connectFD, manager, callback);
            break;
        }
        if (recvSize <= 0) {
            NETSTACK_LOGI("Recv: fd:%{public}d, size:%{public}d, err:%{public}d", connectFD, recvSize, errno);
            if ((recvSize == 0) || (recvSize < 0 && errno != EAGAIN && errno != EINTR)) {
                recvSize == 0 ? NETSTACK_LOGE("connection closed by peer, socket is %{public}d", connectFD) :
                    NETSTACK_LOGE("connection recv failed, socket: %{public}d, errno: %{public}d", connectFD, errno);
                CloseClientHandler(clientId, connectFD, manager, callback);
                break;
            }
        } else {
            void *data = malloc(recvSize);
            if (data == nullptr) {
                RecvInErrorCondition(NO_MEMORY, clientId, connectFD, callback);
                break;
            }
            if (memcpy_s(data, recvSize, buffer.get(), recvSize) != EOK ||
                !callback.OnMessage(connectFD, data, recvSize, nullptr, manager)) {
                free(data);
                RecvInErrorCondition(UNKNOW_ERROR, clientId, connectFD, callback);
            }
        }
    }
}

static void ClientHandler(int32_t sock, int32_t clientId, const TcpMessageCallback &callback)
{
    int32_t connectFD = 0;
    auto manager = WaitForManagerReady(clientId, connectFD);

    uint32_t recvBufferSize = DEFAULT_BUFFER_SIZE;
    TCPExtraOptions option;
    auto config = GetSharedConfig(callback.GetEventManager());
    if (config == nullptr) {
        return;
    }
    config->RemoveAcceptSocket(connectFD);
    if (config->GetTcpExtraOptions(sock, option)) {
        if (option.GetReceiveBufferSize() != 0) {
            recvBufferSize = option.GetReceiveBufferSize();
        }
    }
    ClientPollRecv(clientId, connectFD, recvBufferSize, manager, callback);
}

static void AcceptRecvData(int sock, sockaddr *addr, socklen_t addrLen, const TcpMessageCallback &callback)
{
    std::vector<std::shared_ptr<std::thread>> clientThreads;
    while (true) {
        sockaddr_in clientAddress;
        socklen_t clientAddrLength = sizeof(clientAddress);
        int32_t connectFD = accept(sock, reinterpret_cast<sockaddr *>(&clientAddress), &clientAddrLength);
        if (connectFD < 0) {
            if (errno != EINTR) {
                NETSTACK_LOGE("accept fail, close sock: %{public}d, connectFD: %{public}d, errno: %{public}d", sock,
                              connectFD, errno);
                close(sock);
                break;
            }
            NETSTACK_LOGI("accept fail, sock: %{public}d, connectFD: %{public}d, errno: %{public}d", sock, connectFD,
                          errno);
            continue;
        }
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_clientFDs.size() >= MAX_CLIENTS) {
                NETSTACK_LOGE("Maximum number of clients reached, connection rejected");
                close(connectFD);
                continue;
            }
            NETSTACK_LOGI("Server accept new client, fd= %{public}d clientfd= %{public}d", sock, connectFD);
            g_userCounter++;
            g_clientFDs[g_userCounter] = connectFD;
        }
        callback.OnTcpConnectionMessage(g_userCounter);
        int clientId = g_userCounter;
        auto config = GetSharedConfig(callback.GetEventManager());
        if (config == nullptr) {
            return;
        }
        config->AddNewAcceptSocket(sock, connectFD);
        if (TCPExtraOptions option; config->GetTcpExtraOptions(sock, option)) {
            SocketSetTcpExtraOptions(connectFD, option);
        }
        auto handlerThread = std::make_shared<std::thread>(ClientHandler, sock, clientId, callback);
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
        pthread_setname_np(TCP_SERVER_HANDLE_CLIENT);
#else
        pthread_setname_np(handlerThread->native_handle(), TCP_SERVER_HANDLE_CLIENT);
#endif
        clientThreads.push_back(handlerThread);
    }
    for (auto handlerThread : clientThreads) {
        handlerThread->join();
    }
}

bool ExecTcpServerListen(TcpServerListenContext *context)
{
    int ret = 0;
    if (!ServerBind(context)) {
        return false;
    }

    ret = listen(context->GetSocketFd(), USER_LIMIT);
    if (ret < 0) {
        NETSTACK_LOGE("tcp server listen error");
        return false;
    }
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is null");
        return false;
    }
    if (!manager->GetSocketConfig()) {
        auto config = std::make_shared<SocketConfig>();
        manager->SetSocketConfig(config);
    }
    manager->GetSocketConfig()->AddNewListenSocket(context->GetSocketFd());
    NETSTACK_LOGI("listen success");
    std::thread serviceThread(AcceptRecvData, context->GetSocketFd(), nullptr, 0,
                              TcpMessageCallback(context->GetSharedManager()));
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(TCP_SERVER_ACCEPT_RECV_DATA);
#else
    pthread_setname_np(serviceThread.native_handle(), TCP_SERVER_ACCEPT_RECV_DATA);
#endif
    serviceThread.detach();
    return true;
}

std::shared_ptr<SocketConfig> GetSharedConfig(const std::shared_ptr<EventManager> &manager)
{
    if (manager == nullptr) {
        NETSTACK_LOGE("GetSocketConfig manager is nullptr");
        return nullptr;
    }
    if (manager->GetSocketConfig() == nullptr) {
        NETSTACK_LOGE("GetSocketConfig socketConfig is nullptr");
        return nullptr;
    }
    return manager->GetSocketConfig();
}

bool ExecTcpServerClose(TcpServerCloseContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    int sock = context->GetSocketFd();
    if (sock == -1) {
        NETSTACK_LOGI("TCPServer socket was closed before");
        return true;
    }
    auto config = GetSharedConfig(context->GetSharedManager());
    if (config == nullptr) {
        return false;
    }
    config->ShutdownAllSockets();
    NETSTACK_LOGI("close all listenfd");
    context->SetSocketFd(-1);
    return true;
}

bool ExecTcpServerSetExtraOptions(TcpServerSetExtraOptionsContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    if (context->GetSocketFd() <= 0) {
        context->SetError(ERRNO_BAD_FD, strerror(ERRNO_BAD_FD));
        return false;
    }
    auto config = GetSharedConfig(context->GetSharedManager());
    if (config == nullptr) {
        return false;
    }
    auto clients = config->GetClients(context->GetSocketFd());
    if (std::any_of(clients.begin(), clients.end(), [&context](int32_t fd) {
            return !SocketSetTcpExtraOptions(fd, context->options_);
        })) {
        context->SetError(errno, strerror(errno));
        return false;
    }

    config->SetTcpExtraOptions(context->GetSocketFd(), context->options_);
    return true;
}

bool ExecTcpServerGetSocketFd(TcpServerGetSocketFdContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    return true;
}

static void SetIsConnected(TcpServerGetStateContext *context)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_clientFDs.empty()) {
        context->state_.SetIsConnected(false);
    } else {
        context->state_.SetIsConnected(true);
    }
}

static void SetIsBound(sa_family_t family, TcpServerGetStateContext *context, const sockaddr_in *addr4,
                       const sockaddr_in6 *addr6)
{
    if (family == AF_INET) {
        context->state_.SetIsBound(ntohs(addr4->sin_port) != 0);
    } else if (family == AF_INET6) {
        context->state_.SetIsBound(ntohs(addr6->sin6_port) != 0);
    }
}

static bool GetTcpServerState(TcpServerGetStateContext *context)
{
    int opt;
    socklen_t optLen = sizeof(int);
    if (getsockopt(context->GetSocketFd(), SOL_SOCKET, SO_TYPE, &opt, &optLen) < 0) {
        context->state_.SetIsClose(true);
        return true;
    }

    sockaddr sockAddr = {0};
    socklen_t len = sizeof(sockaddr);
    if (getsockname(context->GetSocketFd(), &sockAddr, &len) < 0) {
        context->SetError(errno, strerror(errno));
        return false;
    }

    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t addrLen;
    if (sockAddr.sa_family == AF_INET) {
        addr = reinterpret_cast<sockaddr *>(&addr4);
        addrLen = sizeof(addr4);
    } else if (sockAddr.sa_family == AF_INET6) {
        addr = reinterpret_cast<sockaddr *>(&addr6);
        addrLen = sizeof(addr6);
    }

    if (addr == nullptr) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }

    if (memset_s(addr, addrLen, 0, addrLen) != EOK) {
        NETSTACK_LOGE("memset_s failed!");
        return false;
    }
    len = addrLen;
    if (getsockname(context->GetSocketFd(), addr, &len) < 0) {
        context->SetError(errno, strerror(errno));
        return false;
    }

    SetIsBound(sockAddr.sa_family, context, &addr4, &addr6);

    if (opt != SOCK_STREAM) {
        return true;
    }
    SetIsConnected(context);
    return true;
}

bool ExecTcpServerGetState(TcpServerGetStateContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    if (!manager->GetData()) {
        return true;
    }

    return GetTcpServerState(context);
}

napi_value BindCallback(BindContext *context)
{
    context->EmitSharedManager(EVENT_LISTENING, std::make_pair(NapiUtils::GetUndefined(context->GetEnv()),
        NapiUtils::GetUndefined(context->GetEnv())));
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value UdpSendCallback(UdpSendContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value UdpAddMembershipCallback(MulticastMembershipContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value UdpDropMembershipCallback(MulticastMembershipContext *context)
{
    context->EmitSharedManager(EVENT_CLOSE, std::make_pair(NapiUtils::GetUndefined(context->GetEnv()),
        NapiUtils::GetUndefined(context->GetEnv())));
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value UdpSetMulticastTTLCallback(MulticastSetTTLContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value UdpGetMulticastTTLCallback(MulticastGetTTLContext *context)
{
    return NapiUtils::CreateInt32(context->GetEnv(), context->GetMulticastTTL());
}

napi_value UdpSetLoopbackModeCallback(MulticastSetLoopbackContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value UdpGetLoopbackModeCallback(MulticastGetLoopbackContext *context)
{
    return NapiUtils::GetBoolean(context->GetEnv(), context->GetLoopbackMode());
}

napi_value ConnectCallback(ConnectContext *context)
{
    context->EmitSharedManager(EVENT_CONNECT, std::make_pair(NapiUtils::GetUndefined(context->GetEnv()),
        NapiUtils::GetUndefined(context->GetEnv())));
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TcpSendCallback(TcpSendContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value CloseCallback(CloseContext *context)
{
    context->EmitSharedManager(EVENT_CLOSE, std::make_pair(NapiUtils::GetUndefined(context->GetEnv()),
        NapiUtils::GetUndefined(context->GetEnv())));
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value GetStateCallback(GetStateContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }

    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_BOUND, context->state_.IsBound());
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_CLOSE, context->state_.IsClose());
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_CONNECTED, context->state_.IsConnected());

    return obj;
}

napi_value GetRemoteAddressCallback(GetRemoteAddressContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }

    NapiUtils::SetStringPropertyUtf8(context->GetEnv(), obj, KEY_ADDRESS, context->address_.GetAddress());
    NapiUtils::SetUint32Property(context->GetEnv(), obj, KEY_FAMILY, context->address_.GetJsValueFamily());
    NapiUtils::SetUint32Property(context->GetEnv(), obj, KEY_PORT, context->address_.GetPort());

    return obj;
}

napi_value TcpSetExtraOptionsCallback(TcpSetExtraOptionsContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value UdpSetExtraOptionsCallback(UdpSetExtraOptionsContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TcpGetSocketFdCallback(GetSocketFdContext *context)
{
    int socketFd = context->GetSocketFd();
    if (socketFd == -1) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    return NapiUtils::CreateUint32(context->GetEnv(), socketFd);
}

napi_value UdpGetSocketFdCallback(GetSocketFdContext *context)
{
    int socketFd = context->GetSocketFd();
    return NapiUtils::CreateInt32(context->GetEnv(), socketFd);
}

napi_value TcpConnectionSendCallback(TcpServerSendContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TcpConnectionCloseCallback(TcpServerCloseContext *context)
{
    NETSTACK_LOGI("Close tcp socket, clientId:%{public}d", context->clientId_);
    RemoveClientConnection(context->clientId_, context);
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TcpConnectionGetRemoteAddressCallback(TcpServerGetRemoteAddressContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }

    NapiUtils::SetStringPropertyUtf8(context->GetEnv(), obj, KEY_ADDRESS, context->address_.GetAddress());
    NapiUtils::SetUint32Property(context->GetEnv(), obj, KEY_FAMILY, context->address_.GetJsValueFamily());
    NapiUtils::SetUint32Property(context->GetEnv(), obj, KEY_PORT, context->address_.GetPort());

    return obj;
}

napi_value ListenCallback(TcpServerListenContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TcpServerCloseCallback(TcpServerCloseContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TcpServerSetExtraOptionsCallback(TcpServerSetExtraOptionsContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TcpServerGetSocketFdCallback(TcpServerGetSocketFdContext *context)
{
    int socketFd = context->GetSocketFd();
    return NapiUtils::CreateInt32(context->GetEnv(), socketFd);
}

napi_value TcpServerGetStateCallback(TcpServerGetStateContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }

    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_BOUND, context->state_.IsBound());
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_CLOSE, context->state_.IsClose());
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_CONNECTED, context->state_.IsConnected());

    return obj;
}
} // namespace OHOS::NetStack::Socket::SocketExec

std::string ConvertAddressToIp(const std::string &address, sa_family_t family)
{
    if (address.empty()) {
        return {};
    }
    addrinfo hints{};
    hints.ai_family = family;
    char ipStr[INET6_ADDRSTRLEN] = {0};
    addrinfo *res = nullptr;
    auto status = getaddrinfo(address.c_str(), nullptr, &hints, &res);
    if (status != 0 || res == nullptr) {
        return {};
    }
    std::string ip;
    if (res->ai_family == AF_INET) {
        auto *ipv4 = reinterpret_cast<struct sockaddr_in *>(res->ai_addr);
        auto addr = &(ipv4->sin_addr);
        inet_ntop(res->ai_family, addr, ipStr, sizeof(ipStr));
        ip = ipStr;
    } else {
        auto *ipv6 = reinterpret_cast<struct sockaddr_in6 *>(res->ai_addr);
        auto addr = &(ipv6->sin6_addr);
        inet_ntop(res->ai_family, addr, ipStr, sizeof(ipStr));
        ip = ipStr;
    }
    freeaddrinfo(res);
    return ip;
}

bool IpMatchFamily(const std::string &address, sa_family_t family)
{
    if (family == AF_INET6) {
        in_addr ipv4{};
        if (inet_pton(AF_INET, address.c_str(), &(ipv4.s_addr)) > 0) {
            return false;
        }
    } else if (family == AF_INET) {
        in6_addr ipv6{};
        if (inet_pton(AF_INET6, address.c_str(), &ipv6) > 0) {
            return false;
        }
    }
    return true;
}

static bool HandlePollEvent(struct pollfd *fds)
{
    if (fds == nullptr) {
        return false;
    }
    if (static_cast<uint16_t>(fds[0].revents) & (POLLNVAL | POLLHUP | POLLERR)) {
        NETSTACK_LOGE("NonBlockConnect poll failed, socket is %{public}d, revents is %{public}x",
            fds[0].fd, fds[0].revents);
        return false;
    }
    
    int err = 0;
    socklen_t optLen = sizeof(err);
    int ret = getsockopt(fds[0].fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<void *>(&err), &optLen);
    if (ret < 0) {
        return false;
    }
    if (err != 0) {
        NETSTACK_LOGE("NonBlockConnect exec failed, socket is %{public}d, err is %{public}d", fds[0].fd, err);
        return false;
    }
    return true;
}

bool NonBlockConnect(int sock, sockaddr *addr, socklen_t addrLen, uint32_t timeoutMSec)
{
    int ret = connect(sock, addr, addrLen);
    if (ret >= 0) {
        return true;
    }
    if (errno != EINPROGRESS) {
        return false;
    }
    struct pollfd fds[1] = {{.fd = sock, .events = POLLOUT}};
    int timeoutMs = (timeoutMSec == 0) ? DEFAULT_CONNECT_TIMEOUT : timeoutMSec;
    while (true) {
        auto startTime = std::chrono::steady_clock::now();
        ret = poll(fds, 1, timeoutMs);
        if (ret > 0) {
            break;
        } else if (ret == 0) {
            NETSTACK_LOGE("connect poll timeout, socket is %{public}d", sock);
            return false;
        }

        if (errno == EINTR) {
            auto endTime = std::chrono::steady_clock::now();
            auto intervalMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
            timeoutMs -= static_cast<int>(intervalMs.count());
            if (timeoutMs <= 0) {
                NETSTACK_LOGE("invalid timeout");
                return false;
            }
            continue;
        }
        NETSTACK_LOGE("connect poll failed, socket is %{public}d, errno is %{public}d", sock, errno);
        return false;
    }
    
    return HandlePollEvent(fds);
}

static bool GetSendBufferSize(int sock, int &bufferSize, int &sockType)
{
    int opt = 0;
    socklen_t optLen = sizeof(opt);
    bufferSize = DEFAULT_BUFFER_SIZE;

    if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<void *>(&opt), &optLen) >= 0 && opt > 0) {
        bufferSize = opt;
    }

    sockType = 0;
    optLen = sizeof(sockType);
    if (getsockopt(sock, SOL_SOCKET, SO_TYPE, reinterpret_cast<void *>(&sockType), &optLen) < 0) {
        return false;
    }
    return true;
}

bool PollSendData(int sock, const char *data, size_t size, sockaddr *addr, socklen_t addrLen)
{
    NETSTACK_LOGD("js send RawSize: %{public}zu", size);
    int bufferSize = DEFAULT_BUFFER_SIZE;
    int sockType = 0;
    if (!GetSendBufferSize(sock, bufferSize, sockType)) {
        NETSTACK_LOGI("get sock opt sock type failed, socket is %{public}d, errno is %{public}d", sock, errno);
        return false;
    }

    auto curPos = data;
    auto leftSize = size;
    nfds_t num = 1;
    pollfd fds[1] = {{0}};
    fds[0].fd = sock;
    fds[0].events = 0;
    fds[0].events |= POLLOUT;
    int sendTimeoutMs = ConfirmSocketTimeoutMs(sock, SO_SNDTIMEO, DEFAULT_TIMEOUT_MS);
    if (sendTimeoutMs < 0) {
        return false;
    }
    while (leftSize > 0) {
        if (!OHOS::NetStack::Socket::SocketExec::PollFd(fds, num, sendTimeoutMs)) {
            if (errno != EINTR) {
                return false;
            }
        }
        size_t sendSize = (sockType == SOCK_STREAM ? leftSize : std::min<size_t>(leftSize, bufferSize));
        auto sendLen = sendto(sock, curPos, sendSize, 0, addr, addrLen);
        NETSTACK_LOGD("socketFD: %{public}d, send len: %{public}zu", sock, sendLen);
        if (sendLen < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }
            NETSTACK_LOGE("send failed, socket is %{public}d, errno is %{public}d", sock, errno);
            return false;
        }
        if (sendLen == 0) {
            break;
        }
        curPos += sendLen;
        leftSize -= sendLen;
    }

    if (leftSize != 0) {
        NETSTACK_LOGE("send not complete, socket is %{public}d, errno is %{public}d", sock, errno);
        return false;
    }
    return true;
}

int ConfirmSocketTimeoutMs(int sock, int type, int defaultValue)
{
    timeval timeout;
    socklen_t optlen = sizeof(timeout);
    if (getsockopt(sock, SOL_SOCKET, type, reinterpret_cast<void *>(&timeout), &optlen) < 0) {
        NETSTACK_LOGE("get timeout failed, type: %{public}d, sock: %{public}d, errno: %{public}d", type, sock, errno);
        if (errno == ENOTSOCK && type == SO_RCVTIMEO) {
            return -1;
        }
        return defaultValue;
    }
    auto socketTimeoutMs = timeout.tv_sec * UNIT_CONVERSION_1000 + timeout.tv_usec / UNIT_CONVERSION_1000;
    return socketTimeoutMs == 0 ? defaultValue : socketTimeoutMs;
}

int ConfirmBufferSize(int sock)
{
    int bufferSize = DEFAULT_BUFFER_SIZE;
    int opt = 0;
    socklen_t optLen = sizeof(opt);
    if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<void *>(&opt), &optLen) >= 0 && opt > 0) {
        bufferSize = opt;
    }
    return bufferSize;
}
