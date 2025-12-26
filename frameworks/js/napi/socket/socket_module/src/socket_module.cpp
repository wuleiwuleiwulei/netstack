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

#include "socket_module.h"

#include <cstdint>
#include <initializer_list>
#include <new>
#include <unistd.h>
#include <utility>

#include "bind_context.h"
#include "common_context.h"
#include "connect_context.h"
#include "context_key.h"
#include "event_list.h"
#include "event_manager.h"
#include "local_socket_context.h"
#include "local_socket_exec.h"
#include "local_socket_server_context.h"
#include "module_template.h"
#include "multicast_get_loopback_context.h"
#include "multicast_get_ttl_context.h"
#include "multicast_membership_context.h"
#include "multicast_set_loopback_context.h"
#include "multicast_set_ttl_context.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_utils.h"
#include "net_address.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "node_api.h"
#include "socket_async_work.h"
#include "socket_exec.h"
#include "socket_exec_common.h"
#include "tcp_extra_context.h"
#include "tcp_send_context.h"
#include "tcp_server_common_context.h"
#include "tcp_server_extra_context.h"
#include "tcp_server_listen_context.h"
#include "tcp_server_send_context.h"
#include "tlssocket_module.h"
#include "tlssocketserver_module.h"
#include "udp_extra_context.h"
#include "udp_send_context.h"

static constexpr const char *SOCKET_MODULE_NAME = "net.socket";

static const char *UDP_BIND_NAME = "UdpBind";
static const char *UDP_SEND_NAME = "UdpSend";
static const char *UDP_CLOSE_NAME = "UdpClose";
static const char *UDP_GET_STATE = "UdpGetState";
static const char *FINALIZE_CLOSE_NAME = "FinalizeClose";
static const char *UDP_GET_LOCAL_ADDRESS = "UdpGetLocalAddress";
static const char *UDP_SET_EXTRA_OPTIONS_NAME = "UdpSetExtraOptions";
static constexpr const char *UDP_GET_SOCKET_FD = "UdpGetSocketFd";

static constexpr const char *UDP_ADD_MEMBERSHIP = "UdpAddMembership";
static constexpr const char *UDP_DROP_MEMBERSHIP = "UdpDropMembership";
static constexpr const char *UDP_SET_MULTICAST_TTL = "UdpSetMulticastTTL";
static constexpr const char *UDP_GET_MULTICAST_TTL = "UdpGetMulticastTTL";
static constexpr const char *UDP_SET_LOOPBACK_MODE = "UdpSetLoopbackMode";
static constexpr const char *UDP_GET_LOOPBACK_MODE = "UdpGetLoopbackMode";

static constexpr const char *LOCAL_SOCKET_BIND = "LocalSocketBind";
static constexpr const char *LOCAL_SOCKET_CONNECT = "LocalSocketConnect";
static constexpr const char *LOCAL_SOCKET_SEND = "LocalSocketSend";
static constexpr const char *LOCAL_SOCKET_CLOSE = "LocalSocketClose";
static constexpr const char *LOCAL_SOCKET_GET_STATE = "LocalSocketGetState";
static constexpr const char *LOCAL_SOCKET_GET_LOCAL_ADDRESS = "LocalSocketGetState";
static constexpr const char *LOCAL_SOCKET_GET_SOCKET_FD = "LocalSocketGetSocketFd";
static constexpr const char *LOCAL_SOCKET_SET_EXTRA_OPTIONS = "LocalSocketSetExtraOptions";
static constexpr const char *LOCAL_SOCKET_GET_EXTRA_OPTIONS = "LocalSocketGetExtraOptions";

static constexpr const char *LOCAL_SOCKET_SERVER_LISTEN = "LocalSocketServerListen";
static constexpr const char *LOCAL_SOCKET_SERVER_END = "LocalSocketServerEnd";
static constexpr const char *LOCAL_SOCKET_SERVER_GET_STATE = "LocalSocketServerGetState";
static constexpr const char *LOCAL_SOCKET_SERVER_GET_LOCAL_ADDRESS = "LocalSocketServerGetState";
static constexpr const char *LOCAL_SOCKET_SERVER_SET_EXTRA_OPTIONS = "LocalSocketServerSetExtraOptions";
static constexpr const char *LOCAL_SOCKET_SERVER_GET_EXTRA_OPTIONS = "LocalSocketServerGetExtraOptions";
static constexpr const char *LOCAL_SOCKET_SERVER_GET_SOCKET_FD = "LocalSocketServerGetSocketFd";

static constexpr const char *LOCAL_SOCKET_CONNECTION_SEND = "LocalSocketConnectionSend";
static constexpr const char *LOCAL_SOCKET_CONNECTION_GET_LOCAL_ADDRESS = "LocalSocketConnectionGetLocalAddress";
static constexpr const char *LOCAL_SOCKET_CONNECTION_GET_SOCKET_FD = "LocalSocketConnectionGetSocketFd";
static constexpr const char *LOCAL_SOCKET_CONNECTION_CLOSE = "LocalSocketConnectionClose";

static const char *TCP_BIND_NAME = "TcpBind";
static const char *TCP_CONNECT_NAME = "TcpConnect";
static const char *TCP_SEND_NAME = "TcpSend";
static const char *TCP_CLOSE_NAME = "TcpClose";
static const char *TCP_GET_STATE = "TcpGetState";
static const char *TCP_GET_REMOTE_ADDRESS = "TcpGetRemoteAddress";
static const char *TCP_GET_LOCAL_ADDRESS = "TcpGetLocalAddress";
static const char *TCP_SET_EXTRA_OPTIONS_NAME = "TcpSetExtraOptions";
static constexpr const char *TCP_GET_SOCKET_FD = "TcpGetSocketFd";

static constexpr const char *TCP_SERVER_LISTEN_NAME = "TcpServerListen";
static constexpr const char *TCP_SERVER_CLOSE_NAME = "TcpServerClose";
static constexpr const char *TCP_SERVER_GET_STATE = "TcpServerGetState";
static constexpr const char *TCP_SERVER_GET_LOCAL_ADDRESS = "TcpServerGetLocalAddress";
static constexpr const char *TCP_SERVER_SET_EXTRA_OPTIONS_NAME = "TcpServerSetExtraOptions";
static constexpr const char *TCP_SERVER_GET_SOCKET_FD = "TcpServerGetSocketFd";

static constexpr const char *TCP_CONNECTION_SEND_NAME = "TcpConnectionSend";
static constexpr const char *TCP_CONNECTION_CLOSE_NAME = "TcpConnectionClose";
static constexpr const char *TCP_CONNECTION_GET_REMOTE_ADDRESS = "TcpConnectionGetRemoteAddress";
static constexpr const char *TCP_CONNECTION_GET_LOCAL_ADDRESS = "TcpConnectionGetLocalAddress";
static constexpr const char *TCP_CONNECTION_GET_SOCKET_FD = "TcpConnectionGetSocketFd";

static constexpr const char *KEY_SOCKET_FD = "socketFd";

static constexpr const char *SOCKETPROXYTYPE = "ProxyTypes";
static constexpr const char *SOCKETPROXYTYPE_NONE = "NONE";
static constexpr const char *SOCKETPROXYTYPE_SOCKS5 = "SOCKS5";

static constexpr int PARAM_COUNT_TWO = 2;

#define SOCKET_INTERFACE(Context, executor, callback, work, name) \
    ModuleTemplate::InterfaceWithSharedManager<Context>(env, info, name, work, \
        SocketAsyncWork::executor, SocketAsyncWork::callback)

namespace OHOS::NetStack::Socket {
void ExecFinalizeClose(napi_env env, void *data)
{
    auto context = reinterpret_cast<BaseContext *>(data);
    if (context == nullptr) {
        NETSTACK_LOGE("ExecFinalizeClose context is nullptr");
        return;
    }
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("ExecFinalizeClose manager is nullptr");
        return;
    }
    std::unique_lock<std::shared_mutex> lock(manager->GetDataMutex());
    int sock = static_cast<int>(reinterpret_cast<uint64_t>(manager->GetData()));
    NETSTACK_LOGI("ExecFinalizeClose socket is %{public}d", sock);
    if (sock < 0) {
        NETSTACK_LOGE("sock %{public}d is previous closed", sock);
        return;
    }
    close(sock);
    manager->SetData(reinterpret_cast<void *>(-1));
}
 
void ExecFinalizeCloseCallback(napi_env env, napi_status status, void *data)
{
    auto context = reinterpret_cast<BaseContext *>(data);
    if (context == nullptr) {
        return;
    }
    context->DeleteReference();
    delete context;
    context = nullptr;
}

void Finalize(napi_env env, void *data, void *)
{
    NETSTACK_LOGD("socket handle is finalized");
    auto sharedManager = reinterpret_cast<std::shared_ptr<EventManager> *>(data);
    if (sharedManager != nullptr && *sharedManager != nullptr) {
        auto manager = *sharedManager;
        int sock = static_cast<int>(reinterpret_cast<uint64_t>(manager->GetData()));
        NETSTACK_LOGI("Finalize, sock %{public}d", sock);
        if (sock == 0) {
            NETSTACK_LOGE("manager->GetData() got nullptr, Finalize() called before creating socket?");
        } else if (sock != -1) {
            auto context = new BaseContext(env, manager);
            context->CreateAsyncWork(FINALIZE_CLOSE_NAME, ExecFinalizeClose, ExecFinalizeCloseCallback);
        }
        delete sharedManager;
    }
}

void FinalizeTcpSocketServer(napi_env, void *data, void *)
{
    NETSTACK_LOGI("tcp socket server handle is finalized");
    auto sharedManager = reinterpret_cast<std::shared_ptr<EventManager> *>(data);
    if (sharedManager != nullptr && *sharedManager != nullptr) {
        auto manager = *sharedManager;
        int sock = static_cast<int>(reinterpret_cast<uint64_t>(manager->GetData()));
        if (sock != -1) {
            NETSTACK_LOGI("finalize close all listenfd");
            manager->SetData(reinterpret_cast<void *>(-1));
            auto config = SocketExec::GetSharedConfig(manager);
            if (config == nullptr) {
                return;
            }
            config->ShutdownAllSockets();
        }
        delete sharedManager;
    }
}

void FinalizeLocalsocketServer(napi_env, void *data, void *)
{
    auto sharedManager = reinterpret_cast<std::shared_ptr<EventManager> *>(data);
    if (sharedManager != nullptr && *sharedManager != nullptr) {
        auto manager = *sharedManager;
        if (auto serverMgr = reinterpret_cast<LocalSocketServerManager *>(manager->GetData()); serverMgr != nullptr) {
            NETSTACK_LOGI("localsocket server handle is finalized, fd: %{public}d", serverMgr->sockfd_);
#if !defined(MAC_PLATFORM) && !defined(IOS_PLATFORM)
            serverMgr->SetServerDestructStatus(true);
#else
            serverMgr->isServerDestruct_ = true;
#endif
            serverMgr->RemoveAllAccept();
            serverMgr->RemoveAllEventManager();
            if (serverMgr->sockfd_ > 0) {
                close(serverMgr->sockfd_);
                serverMgr->sockfd_ = -1;
            }
#if !defined(MAC_PLATFORM) && !defined(IOS_PLATFORM)
            close(serverMgr->epollFd_);
#endif
            serverMgr->WaitForEndingLoop();
            delete serverMgr;
        }
        delete sharedManager;
    }
}

void FinalizeLocalSocket(napi_env, void *data, void *)
{
    auto sharedManager = reinterpret_cast<std::shared_ptr<EventManager> *>(data);
    if (sharedManager != nullptr && *sharedManager != nullptr) {
        auto manager = *sharedManager;
        if (auto pMgr = reinterpret_cast<LocalSocketManager *>(manager->GetData()); pMgr != nullptr) {
            NETSTACK_LOGI("localsocket handle is finalized, fd: %{public}d", pMgr->sockfd_);
            if (pMgr->sockfd_ > 0) {
                close(pMgr->sockfd_);
                pMgr->sockfd_ = 0;
            }
            delete pMgr;
        }
        delete sharedManager;
    }
}

static bool SetSocket(napi_env env, napi_value thisVal, BaseContext *context, int sock)
{
    if (sock < 0) {
        napi_value error = NapiUtils::CreateObject(env);
        if (NapiUtils::GetValueType(env, error) != napi_object) {
            return false;
        }
        NapiUtils::SetUint32Property(env, error, KEY_ERROR_CODE, errno);
        context->EmitSharedManager(EVENT_ERROR, std::make_pair(NapiUtils::GetUndefined(env), error));
        return false;
    }

    std::shared_ptr<EventManager> *sharedManager = nullptr;
    if (napi_unwrap(env, thisVal, reinterpret_cast<void **>(&sharedManager)) != napi_ok || sharedManager == nullptr) {
        return false;
    }
    auto manager = *sharedManager;
    if (manager == nullptr) {
        return false;
    }
    NETSTACK_LOGD("SetSocket: sock %{public}d", sock);
    manager->SetData(reinterpret_cast<void *>(sock));
    NapiUtils::SetInt32Property(env, thisVal, KEY_SOCKET_FD, sock);
    return true;
}

static bool MakeTcpClientBindSocket(napi_env env, napi_value thisVal, BindContext *context)
{
    if (!context->IsParseOK()) {
        context->SetErrorCode(PARSE_ERROR_CODE);
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    NETSTACK_LOGD("bind ip family is %{public}d", context->address_.GetSaFamily());
    if (context->GetSharedManager()->GetData() != nullptr &&
        static_cast<int>(reinterpret_cast<uint64_t>(context->GetSharedManager()->GetData())) >= 0) {
        NETSTACK_LOGE("tcp connect has been called");
        return true;
    }
    int sock = ExecCommonUtils::MakeTcpSocket(context->address_.GetSaFamily());
    if (!SetSocket(env, thisVal, context, sock)) {
        return false;
    }
    context->SetExecOK(true);
    return true;
}

static bool MakeTcpClientConnectSocket(napi_env env, napi_value thisVal, ConnectContext *context)
{
    if (!context->IsParseOK()) {
        context->SetErrorCode(PARSE_ERROR_CODE);
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    NETSTACK_LOGD("connect ip family is %{public}d", context->options.address.GetSaFamily());

    auto manager = context->GetSharedManager();
    if (manager != nullptr &&
        manager->GetData() != nullptr &&
        static_cast<int>(reinterpret_cast<uint64_t>(manager->GetData())) != -1) {
        NETSTACK_LOGD("tcp bind has been called");
        return true;
    }
    int sock = ExecCommonUtils::MakeTcpSocket(context->options.address.GetSaFamily());
    if (!SetSocket(env, thisVal, context, sock)) {
        return false;
    }
    context->SetExecOK(true);
    return true;
}

static bool MakeTcpServerSocket(napi_env env, napi_value thisVal, TcpServerListenContext *context)
{
    if (!context->IsParseOK()) {
        context->SetErrorCode(PARSE_ERROR_CODE);
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    int sock = ExecCommonUtils::MakeTcpSocket(context->address_.GetSaFamily(), false);
    if (sock <= 0) {
        return false;
    }
    int reuse = 1; // 1 means enable reuseaddr feature
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<void *>(&reuse), sizeof(reuse)) < 0) {
        NETSTACK_LOGE("failed to set tcp server listen socket reuseaddr on, sockfd: %{public}d", sock);
    }
    if (!SetSocket(env, thisVal, context, sock)) {
        return false;
    }
    context->SetExecOK(true);
    return true;
}

static bool MakeUdpSocket(napi_env env, napi_value thisVal, BindContext *context)
{
    if (!context->IsParseOK()) {
        context->SetErrorCode(PARSE_ERROR_CODE);
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    int sock = ExecCommonUtils::MakeUdpSocket(context->address_.GetSaFamily());
    if (!SetSocket(env, thisVal, context, sock)) {
        return false;
    }
    context->SetExecOK(true);
    return true;
}

static bool MakeMulticastUdpSocket(napi_env env, napi_value thisVal, MulticastMembershipContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    if (context->GetSocketFd() > 0) {
        NETSTACK_LOGI("socket exist: %{public}d", context->GetSocketFd());
        return false;
    }
    if (!context->IsParseOK()) {
        context->SetErrorCode(PARSE_ERROR_CODE);
        return false;
    }
    int sock = ExecCommonUtils::MakeUdpSocket(context->address_.GetSaFamily());
    if (!SetSocket(env, thisVal, context, sock)) {
        return false;
    }
    context->SetExecOK(true);
    return true;
}

static bool SetSocketManager(napi_env env, napi_value thisVal, BaseContext *context, SocketBaseManager *mgr)
{
    if (mgr->sockfd_ <= 0) {
        NETSTACK_LOGE("SetSocketManager sockfd < 0");
        napi_value error = NapiUtils::CreateObject(env);
        if (NapiUtils::GetValueType(env, error) != napi_object) {
            return false;
        }
        NapiUtils::SetUint32Property(env, error, KEY_ERROR_CODE, errno);
        context->EmitSharedManager(EVENT_ERROR, std::make_pair(NapiUtils::GetUndefined(env), error));
        return false;
    }
    std::shared_ptr<EventManager> *sharedManager = nullptr;
    if (napi_unwrap(env, thisVal, reinterpret_cast<void **>(&sharedManager)) != napi_ok || sharedManager == nullptr) {
        NETSTACK_LOGE("SetSocketManager unwrap err");
        return false;
    }
    auto manager = *sharedManager;
    if (manager == nullptr) {
        return false;
    }
    NETSTACK_LOGD("SetSocketManager setData");
    manager->SetData(reinterpret_cast<void *>(mgr));
    NapiUtils::SetInt32Property(env, thisVal, KEY_SOCKET_FD, mgr->sockfd_);
    return true;
}

static bool MakeLocalSocketBind(napi_env env, napi_value thisVal, LocalSocketBindContext *context)
{
    if (context == nullptr) {
        return false;
    }
    if (context->GetSocketFd() > 0) {
        NETSTACK_LOGI("socket exist: %{public}d", context->GetSocketFd());
        return false;
    }
    int sock = ExecCommonUtils::MakeLocalSocket(SOCK_STREAM);
    if (sock < 0) {
        return false;
    }
    auto pManager = new (std::nothrow) LocalSocketManager(sock);
    if (pManager == nullptr) {
        return false;
    }
    if (!SetSocketManager(env, thisVal, context, pManager)) {
        delete pManager;
        return false;
    }
    context->SetExecOK(true);
    return true;
}

static bool MakeLocalSocketConnect(napi_env env, napi_value thisVal, LocalSocketConnectContext *context)
{
    if (context == nullptr) {
        return false;
    }
    if (context->GetSocketFd() > 0) {
        NETSTACK_LOGI("socket exist: %{public}d", context->GetSocketFd());
        return false;
    }
    int sock = ExecCommonUtils::MakeLocalSocket(SOCK_STREAM, false);
    if (sock < 0) {
        return false;
    }
    auto pManager = new (std::nothrow) LocalSocketManager(sock);
    if (pManager == nullptr) {
        return false;
    }
    if (!SetSocketManager(env, thisVal, context, pManager)) {
        delete pManager;
        return false;
    }
    context->SetExecOK(true);
    return true;
}

static bool MakeLocalServerSocket(napi_env env, napi_value thisVal, LocalSocketServerListenContext *context)
{
    if (context == nullptr) {
        return false;
    }
    if (int sock = context->GetSocketFd(); sock > 0) {
        NETSTACK_LOGI("socket exist: %{public}d", sock);
        return false;
    }
    int sock = ExecCommonUtils::MakeLocalSocket(SOCK_STREAM);
    if (sock < 0) {
        return false;
    }
    auto pManager = new (std::nothrow) LocalSocketServerManager(sock);
    if (pManager == nullptr) {
        return false;
    }
#if !defined(MAC_PLATFORM) && !defined(IOS_PLATFORM)
    if (pManager->StartEpoll() < 0) {
        NETSTACK_LOGE("localsocket server start epoll err, sock: %{public}d", sock);
        close(sock);
        delete pManager;
        return false;
    }
#endif
    if (!SetSocketManager(env, thisVal, context, pManager)) {
#if !defined(MAC_PLATFORM) && !defined(IOS_PLATFORM)
        close(sock);
        close(pManager->epollFd_);
#endif
        delete pManager;
        return false;
    }
    context->SetExecOK(true);
    return true;
}

napi_value SocketModuleExports::InitSocketModule(napi_env env, napi_value exports)
{
    TlsSocket::TLSSocketModuleExports::InitTLSSocketModule(env, exports);
    TlsSocketServer::TLSSocketServerModuleExports::InitTLSSocketServerModule(env, exports);
    DefineUDPSocketClass(env, exports);
    DefineMulticastSocketClass(env, exports);
    DefineTCPServerSocketClass(env, exports);
    DefineTCPSocketClass(env, exports);
    DefineLocalSocketClass(env, exports);
    DefineLocalSocketServerClass(env, exports);
    InitSocketProxyProperties(env, exports);
    InitSocketProperties(env, exports);
    NapiUtils::SetEnvValid(env);
    auto envWrapper = new (std::nothrow)napi_env;
    if (envWrapper == nullptr) {
        return exports;
    }
    *envWrapper = env;
    napi_add_env_cleanup_hook(env, NapiUtils::HookForEnvCleanup, envWrapper);
    return exports;
}

napi_value SocketModuleExports::ConstructUDPSocketInstance(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::NewInstanceWithSharedManager(env, info, INTERFACE_UDP_SOCKET, Finalize);
}

napi_value SocketModuleExports::ConstructMulticastSocketInstance(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::NewInstanceWithSharedManager(env, info, INTERFACE_MULTICAST_SOCKET, Finalize);
}

napi_value SocketModuleExports::ConstructLocalSocketInstance(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::NewInstanceWithSharedManager(env, info, INTERFACE_LOCAL_SOCKET, FinalizeLocalSocket);
}

napi_value SocketModuleExports::ConstructLocalSocketServerInstance(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::NewInstanceWithSharedManager(env, info, INTERFACE_LOCAL_SOCKET_SERVER,
        FinalizeLocalsocketServer);
}

void SocketModuleExports::DefineUDPSocketClass(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_WRITABLE_FUNCTION(UDPSocket::FUNCTION_BIND, UDPSocket::Bind),
        DECLARE_NAPI_WRITABLE_FUNCTION(UDPSocket::FUNCTION_SEND, UDPSocket::Send),
        DECLARE_NAPI_WRITABLE_FUNCTION(UDPSocket::FUNCTION_CLOSE, UDPSocket::Close),
        DECLARE_NAPI_WRITABLE_FUNCTION(UDPSocket::FUNCTION_GET_STATE, UDPSocket::GetState),
        DECLARE_NAPI_WRITABLE_FUNCTION(UDPSocket::FUNCTION_GET_LOCAL_ADDRESS, UDPSocket::GetLocalAddress),
        DECLARE_NAPI_WRITABLE_FUNCTION(UDPSocket::FUNCTION_SET_EXTRA_OPTIONS, UDPSocket::SetExtraOptions),
        DECLARE_NAPI_WRITABLE_FUNCTION(UDPSocket::FUNCTION_GET_SOCKET_FD, UDPSocket::GetSocketFd),
        DECLARE_NAPI_WRITABLE_FUNCTION(UDPSocket::FUNCTION_ON, UDPSocket::On),
        DECLARE_NAPI_WRITABLE_FUNCTION(UDPSocket::FUNCTION_OFF, UDPSocket::Off),
    };
    ModuleTemplate::DefineClass(env, exports, properties, INTERFACE_UDP_SOCKET);
}

void SocketModuleExports::DefineMulticastSocketClass(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(MulticastSocket::FUNCTION_BIND, MulticastSocket::Bind),
        DECLARE_NAPI_FUNCTION(MulticastSocket::FUNCTION_SEND, MulticastSocket::Send),
        DECLARE_NAPI_FUNCTION(MulticastSocket::FUNCTION_CLOSE, MulticastSocket::Close),
        DECLARE_NAPI_FUNCTION(MulticastSocket::FUNCTION_GET_STATE, MulticastSocket::GetState),
        DECLARE_NAPI_FUNCTION(MulticastSocket::FUNCTION_SET_EXTRA_OPTIONS, MulticastSocket::SetExtraOptions),
        DECLARE_NAPI_FUNCTION(MulticastSocket::FUNCTION_GET_SOCKET_FD, MulticastSocket::GetSocketFd),
        DECLARE_NAPI_FUNCTION(MulticastSocket::FUNCTION_GET_LOCAL_ADDRESS, MulticastSocket::GetLocalAddress),
        DECLARE_NAPI_FUNCTION(MulticastSocket::FUNCTION_ON, MulticastSocket::On),
        DECLARE_NAPI_FUNCTION(MulticastSocket::FUNCTION_OFF, MulticastSocket::Off),
        DECLARE_NAPI_FUNCTION(MulticastSocket::FUNCTION_ADD_MEMBER_SHIP, MulticastSocket::AddMembership),
        DECLARE_NAPI_FUNCTION(MulticastSocket::FUNCTION_DROP_MEMBER_SHIP, MulticastSocket::DropMembership),
        DECLARE_NAPI_FUNCTION(MulticastSocket::FUNCTION_SET_MULTICAST_TTL, MulticastSocket::SetMulticastTTL),
        DECLARE_NAPI_FUNCTION(MulticastSocket::FUNCTION_GET_MULTICAST_TTL, MulticastSocket::GetMulticastTTL),
        DECLARE_NAPI_FUNCTION(MulticastSocket::FUNCTION_SET_LOOPBACK_MODE, MulticastSocket::SetLoopbackMode),
        DECLARE_NAPI_FUNCTION(MulticastSocket::FUNCTION_GET_LOOPBACK_MODE, MulticastSocket::GetLoopbackMode),
    };
    ModuleTemplate::DefineClass(env, exports, properties, INTERFACE_MULTICAST_SOCKET);
}

napi_value SocketModuleExports::ConstructTCPSocketInstance(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::NewInstanceWithSharedManager(env, info, INTERFACE_TCP_SOCKET, Finalize);
}

void SocketModuleExports::DefineTCPSocketClass(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(TCPSocket::FUNCTION_BIND, TCPSocket::Bind),
        DECLARE_NAPI_FUNCTION(TCPSocket::FUNCTION_CONNECT, TCPSocket::Connect),
        DECLARE_NAPI_FUNCTION(TCPSocket::FUNCTION_SEND, TCPSocket::Send),
        DECLARE_NAPI_FUNCTION(TCPSocket::FUNCTION_CLOSE, TCPSocket::Close),
        DECLARE_NAPI_FUNCTION(TCPSocket::FUNCTION_GET_REMOTE_ADDRESS, TCPSocket::GetRemoteAddress),
        DECLARE_NAPI_FUNCTION(TCPSocket::FUNCTION_GET_LOCAL_ADDRESS, TCPSocket::GetLocalAddress),
        DECLARE_NAPI_FUNCTION(TCPSocket::FUNCTION_GET_STATE, TCPSocket::GetState),
        DECLARE_NAPI_FUNCTION(TCPSocket::FUNCTION_SET_EXTRA_OPTIONS, TCPSocket::SetExtraOptions),
        DECLARE_NAPI_FUNCTION(TCPSocket::FUNCTION_GET_SOCKET_FD, TCPSocket::GetSocketFd),
        DECLARE_NAPI_FUNCTION(TCPSocket::FUNCTION_ON, TCPSocket::On),
        DECLARE_NAPI_FUNCTION(TCPSocket::FUNCTION_OFF, TCPSocket::Off),
    };
    ModuleTemplate::DefineClass(env, exports, properties, INTERFACE_TCP_SOCKET);
}

void SocketModuleExports::DefineLocalSocketClass(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(LocalSocket::FUNCTION_BIND, LocalSocket::Bind),
        DECLARE_NAPI_FUNCTION(LocalSocket::FUNCTION_CONNECT, LocalSocket::Connect),
        DECLARE_NAPI_FUNCTION(LocalSocket::FUNCTION_SEND, LocalSocket::Send),
        DECLARE_NAPI_FUNCTION(LocalSocket::FUNCTION_CLOSE, LocalSocket::Close),
        DECLARE_NAPI_FUNCTION(LocalSocket::FUNCTION_GET_STATE, LocalSocket::GetState),
        DECLARE_NAPI_FUNCTION(LocalSocket::FUNCTION_GET_LOCAL_ADDRESS, LocalSocket::GetLocalAddress),
        DECLARE_NAPI_FUNCTION(LocalSocket::FUNCTION_SET_EXTRA_OPTIONS, LocalSocket::SetExtraOptions),
        DECLARE_NAPI_FUNCTION(LocalSocket::FUNCTION_GET_EXTRA_OPTIONS, LocalSocket::GetExtraOptions),
        DECLARE_NAPI_FUNCTION(LocalSocket::FUNCTION_GET_SOCKET_FD, LocalSocket::GetSocketFd),
        DECLARE_NAPI_FUNCTION(LocalSocket::FUNCTION_ON, LocalSocket::On),
        DECLARE_NAPI_FUNCTION(LocalSocket::FUNCTION_OFF, LocalSocket::Off),
    };
    ModuleTemplate::DefineClass(env, exports, properties, INTERFACE_LOCAL_SOCKET);
}

void SocketModuleExports::DefineLocalSocketServerClass(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(LocalSocketServer::FUNCTION_LISTEN, LocalSocketServer::Listen),
        DECLARE_NAPI_FUNCTION(LocalSocketServer::FUNCTION_CLOSE, LocalSocketServer::Close),
        DECLARE_NAPI_FUNCTION(LocalSocketServer::FUNCTION_GET_STATE, LocalSocketServer::GetState),
        DECLARE_NAPI_FUNCTION(LocalSocketServer::FUNCTION_GET_LOCAL_ADDRESS, LocalSocketServer::GetLocalAddress),
        DECLARE_NAPI_FUNCTION(LocalSocketServer::FUNCTION_SET_EXTRA_OPTIONS, LocalSocketServer::SetExtraOptions),
        DECLARE_NAPI_FUNCTION(LocalSocketServer::FUNCTION_GET_EXTRA_OPTIONS, LocalSocketServer::GetExtraOptions),
        DECLARE_NAPI_FUNCTION(LocalSocketServer::FUNCTION_GET_SOCKET_FD, LocalSocketServer::GetSocketFd),
        DECLARE_NAPI_FUNCTION(LocalSocketServer::FUNCTION_ON, LocalSocketServer::On),
        DECLARE_NAPI_FUNCTION(LocalSocketServer::FUNCTION_OFF, LocalSocketServer::Off),
    };
    ModuleTemplate::DefineClass(env, exports, properties, INTERFACE_LOCAL_SOCKET_SERVER);
}

napi_value SocketModuleExports::ConstructTCPSocketServerInstance(napi_env env, napi_callback_info info)
{
    NETSTACK_LOGI("create new instance for TCPSocketServer");
    return ModuleTemplate::NewInstanceWithSharedManager(env, info, INTERFACE_TCP_SOCKET_SERVER,
        FinalizeTcpSocketServer);
}

void SocketModuleExports::DefineTCPServerSocketClass(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(TCPServerSocket::FUNCTION_LISTEN, TCPServerSocket::Listen),
        DECLARE_NAPI_FUNCTION(TCPServerSocket::FUNCTION_CLOSE, TCPServerSocket::Close),
        DECLARE_NAPI_FUNCTION(TCPServerSocket::FUNCTION_GET_STATE, TCPServerSocket::GetState),
        DECLARE_NAPI_FUNCTION(TCPServerSocket::FUNCTION_GET_LOCAL_ADDRESS, TCPServerSocket::GetLocalAddress),
        DECLARE_NAPI_FUNCTION(TCPServerSocket::FUNCTION_SET_EXTRA_OPTIONS, TCPServerSocket::SetExtraOptions),
        DECLARE_NAPI_FUNCTION(TCPServerSocket::FUNCTION_GET_SOCKET_FD, TCPServerSocket::GetSocketFd),
        DECLARE_NAPI_FUNCTION(TCPServerSocket::FUNCTION_ON, TCPServerSocket::On),
        DECLARE_NAPI_FUNCTION(TCPServerSocket::FUNCTION_OFF, TCPServerSocket::Off),
    };
    ModuleTemplate::DefineClass(env, exports, properties, INTERFACE_TCP_SOCKET_SERVER);
}

void SocketModuleExports::InitSocketProxyProperties(napi_env env, napi_value exports)
{
    NapiUtils::DefineProperties(env, exports, {
        DECLARE_NAPI_STATIC_PROPERTY(SOCKETPROXYTYPE_NONE,
            NapiUtils::CreateUint32(env, static_cast<uint32_t>(ProxyType::NONE))),
        DECLARE_NAPI_STATIC_PROPERTY(SOCKETPROXYTYPE_SOCKS5,
            NapiUtils::CreateUint32(env, static_cast<uint32_t>(ProxyType::SOCKS5))),
    });

    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_STATIC_PROPERTY(SOCKETPROXYTYPE_NONE,
            NapiUtils::CreateUint32(env, static_cast<uint32_t>(ProxyType::NONE))),
        DECLARE_NAPI_STATIC_PROPERTY(SOCKETPROXYTYPE_SOCKS5,
            NapiUtils::CreateUint32(env, static_cast<uint32_t>(ProxyType::SOCKS5))),
    };

    napi_value socks5Properties = NapiUtils::CreateObject(env);
    NapiUtils::DefineProperties(env, socks5Properties, properties);

    NapiUtils::SetNamedProperty(env, exports, SOCKETPROXYTYPE, socks5Properties);
}

void SocketModuleExports::InitSocketProperties(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(FUNCTION_CONSTRUCTOR_UDP_SOCKET_INSTANCE, ConstructUDPSocketInstance),
        DECLARE_NAPI_FUNCTION(FUNCTION_CONSTRUCTOR_MULTICAST_SOCKET_INSTANCE, ConstructMulticastSocketInstance),
        DECLARE_NAPI_FUNCTION(FUNCTION_CONSTRUCTOR_TCP_SOCKET_SERVER_INSTANCE, ConstructTCPSocketServerInstance),
        DECLARE_NAPI_FUNCTION(FUNCTION_CONSTRUCTOR_TCP_SOCKET_INSTANCE, ConstructTCPSocketInstance),
        DECLARE_NAPI_FUNCTION(FUNCTION_CONSTRUCTOR_LOCAL_SOCKET_INSTANCE, ConstructLocalSocketInstance),
        DECLARE_NAPI_FUNCTION(FUNCTION_CONSTRUCTOR_LOCAL_SOCKET_SERVER_INSTANCE, ConstructLocalSocketServerInstance),
    };
    NapiUtils::DefineProperties(env, exports, properties);
}

/* udp async works */
napi_value SocketModuleExports::UDPSocket::Bind(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(BindContext, ExecUdpBind, BindCallback, MakeUdpSocket, UDP_BIND_NAME);
}

napi_value SocketModuleExports::UDPSocket::Send(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithOutAsyncWorkWithSharedManager<UdpSendContext>(
        env, info,
        [](napi_env, napi_value, UdpSendContext *context) -> bool {
            SocketAsyncWork::ExecUdpSend(context->GetEnv(), context);
            return true;
        },
        UDP_SEND_NAME, SocketAsyncWork::ExecUdpSend, SocketAsyncWork::UdpSendCallback);
}

napi_value SocketModuleExports::UDPSocket::Close(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(CloseContext, ExecClose, CloseCallback, nullptr, UDP_CLOSE_NAME);
}

napi_value SocketModuleExports::UDPSocket::GetState(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(GetStateContext, ExecGetState, GetStateCallback, nullptr, UDP_GET_STATE);
}

napi_value SocketModuleExports::UDPSocket::GetLocalAddress(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(GetLocalAddressContext, ExecGetLocalAddress, GetLocalAddressCallback, nullptr,
                            UDP_GET_LOCAL_ADDRESS);
}

napi_value SocketModuleExports::UDPSocket::SetExtraOptions(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(UdpSetExtraOptionsContext, ExecUdpSetExtraOptions, UdpSetExtraOptionsCallback, nullptr,
                            UDP_SET_EXTRA_OPTIONS_NAME);
}

napi_value SocketModuleExports::UDPSocket::GetSocketFd(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(GetSocketFdContext, ExecUdpGetSocketFd, UdpGetSocketFdCallback, nullptr, UDP_GET_SOCKET_FD);
}

napi_value SocketModuleExports::UDPSocket::On(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::OnSharedManager(env, info,
        {EVENT_MESSAGE, EVENT_LISTENING, EVENT_ERROR, EVENT_CLOSE}, false);
}

napi_value SocketModuleExports::UDPSocket::Off(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::OffSharedManager(env, info, {EVENT_MESSAGE, EVENT_LISTENING, EVENT_ERROR, EVENT_CLOSE});
}

/* udp multicast */
napi_value SocketModuleExports::MulticastSocket::AddMembership(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(MulticastMembershipContext, ExecUdpAddMembership, UdpAddMembershipCallback,
                            MakeMulticastUdpSocket, UDP_ADD_MEMBERSHIP);
}

napi_value SocketModuleExports::MulticastSocket::DropMembership(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(MulticastMembershipContext, ExecUdpDropMembership, UdpDropMembershipCallback, nullptr,
                            UDP_DROP_MEMBERSHIP);
}

napi_value SocketModuleExports::MulticastSocket::GetLocalAddress(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(GetLocalAddressContext, ExecGetLocalAddress, GetLocalAddressCallback, nullptr,
                            UDP_GET_LOCAL_ADDRESS);
}

napi_value SocketModuleExports::MulticastSocket::SetMulticastTTL(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(MulticastSetTTLContext, ExecSetMulticastTTL, UdpSetMulticastTTLCallback, nullptr,
                            UDP_SET_MULTICAST_TTL);
}

napi_value SocketModuleExports::MulticastSocket::GetMulticastTTL(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(MulticastGetTTLContext, ExecGetMulticastTTL, UdpGetMulticastTTLCallback, nullptr,
                            UDP_GET_MULTICAST_TTL);
}

napi_value SocketModuleExports::MulticastSocket::SetLoopbackMode(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(MulticastSetLoopbackContext, ExecSetLoopbackMode, UdpSetLoopbackModeCallback, nullptr,
                            UDP_SET_LOOPBACK_MODE);
}

napi_value SocketModuleExports::MulticastSocket::GetLoopbackMode(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(MulticastGetLoopbackContext, ExecGetLoopbackMode, UdpGetLoopbackModeCallback, nullptr,
                            UDP_GET_LOOPBACK_MODE);
}

/* tcp async works */
napi_value SocketModuleExports::TCPSocket::Bind(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(BindContext, ExecTcpBind, BindCallback, MakeTcpClientBindSocket, TCP_BIND_NAME);
}

napi_value SocketModuleExports::TCPSocket::Connect(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(ConnectContext, ExecConnect, ConnectCallback, MakeTcpClientConnectSocket, TCP_CONNECT_NAME);
}

napi_value SocketModuleExports::TCPSocket::Send(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithOutAsyncWorkWithSharedManager<TcpSendContext>(
        env, info,
        [](napi_env, napi_value, TcpSendContext *context) -> bool {
            SocketAsyncWork::ExecTcpSend(context->GetEnv(), context);
            return true;
        },
        TCP_SEND_NAME, SocketAsyncWork::ExecTcpSend, SocketAsyncWork::TcpSendCallback);
}

napi_value SocketModuleExports::TCPSocket::Close(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(CloseContext, ExecClose, CloseCallback, nullptr, TCP_CLOSE_NAME);
}

napi_value SocketModuleExports::TCPSocket::GetRemoteAddress(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(GetRemoteAddressContext, ExecGetRemoteAddress, GetRemoteAddressCallback, nullptr,
                            TCP_GET_REMOTE_ADDRESS);
}

napi_value SocketModuleExports::TCPSocket::GetLocalAddress(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(GetLocalAddressContext, ExecGetLocalAddress, GetLocalAddressCallback, nullptr,
                            TCP_GET_LOCAL_ADDRESS);
}

napi_value SocketModuleExports::TCPSocket::GetState(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(GetStateContext, ExecGetState, GetStateCallback, nullptr, TCP_GET_STATE);
}

napi_value SocketModuleExports::TCPSocket::SetExtraOptions(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(TcpSetExtraOptionsContext, ExecTcpSetExtraOptions, TcpSetExtraOptionsCallback, nullptr,
                            TCP_SET_EXTRA_OPTIONS_NAME);
}

napi_value SocketModuleExports::TCPSocket::GetSocketFd(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(GetSocketFdContext, ExecTcpGetSocketFd, TcpGetSocketFdCallback, nullptr, TCP_GET_SOCKET_FD);
}

napi_value SocketModuleExports::TCPSocket::On(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::OnSharedManager(env, info, {EVENT_MESSAGE, EVENT_CONNECT, EVENT_ERROR, EVENT_CLOSE}, false);
}

napi_value SocketModuleExports::TCPSocket::Off(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::OffSharedManager(env, info, {EVENT_MESSAGE, EVENT_CONNECT, EVENT_ERROR, EVENT_CLOSE});
}

/* tcp connection async works */
napi_value SocketModuleExports::TCPConnection::Send(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(
        TcpServerSendContext, ExecTcpConnectionSend, TcpConnectionSendCallback,
        [](napi_env theEnv, napi_value thisVal, TcpServerSendContext *context) -> bool {
            context->clientId_ = NapiUtils::GetInt32Property(theEnv, thisVal, PROPERTY_CLIENT_ID);
            return true;
        },
        TCP_CONNECTION_SEND_NAME);
}

napi_value SocketModuleExports::TCPConnection::Close(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(
        TcpServerCloseContext, ExecTcpConnectionClose, TcpConnectionCloseCallback,
        [](napi_env theEnv, napi_value thisVal, TcpServerCloseContext *context) -> bool {
            context->clientId_ = NapiUtils::GetInt32Property(theEnv, thisVal, PROPERTY_CLIENT_ID);
            return true;
        },
        TCP_CONNECTION_CLOSE_NAME);
}

napi_value SocketModuleExports::TCPConnection::GetRemoteAddress(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(
        TcpServerGetRemoteAddressContext, ExecTcpConnectionGetRemoteAddress, TcpConnectionGetRemoteAddressCallback,
        [](napi_env theEnv, napi_value thisVal, TcpServerGetRemoteAddressContext *context) -> bool {
            context->clientId_ = NapiUtils::GetInt32Property(theEnv, thisVal, PROPERTY_CLIENT_ID);
            return true;
        },
        TCP_CONNECTION_GET_REMOTE_ADDRESS);
}

napi_value SocketModuleExports::TCPConnection::GetLocalAddress(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(
        TcpConnectionGetLocalAddressContext, ExecTcpConnectionGetLocalAddress, TcpConnectionGetLocalAddressCallback,
        [](napi_env theEnv, napi_value thisVal, TcpServerGetLocalAddressContext *context) -> bool {
            context->clientId_ = NapiUtils::GetInt32Property(theEnv, thisVal, PROPERTY_CLIENT_ID);
            return true;
        },
        TCP_CONNECTION_GET_LOCAL_ADDRESS);
}

napi_value SocketModuleExports::TCPConnection::GetSocketFd(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(TcpServerGetSocketFdContext, ExecTcpConnectionGetSocketFd, TcpConnectionGetSocketFdCallback,
        [](napi_env theEnv, napi_value thisVal, TcpServerGetSocketFdContext *context) -> bool {
            context->clientId_ = NapiUtils::GetInt32Property(theEnv, thisVal, PROPERTY_CLIENT_ID);
            return true;
        }, TCP_CONNECTION_GET_SOCKET_FD);
}

napi_value SocketModuleExports::TCPConnection::On(napi_env env, napi_callback_info info)
{
    napi_value ret = ModuleTemplate::OnSharedManager(env, info,
        {EVENT_MESSAGE, EVENT_CONNECT, EVENT_ERROR, EVENT_CLOSE}, false);
    SocketExec::NotifyRegisterEvent();
    return ret;
}

napi_value SocketModuleExports::TCPConnection::Off(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::OffSharedManager(env, info, {EVENT_MESSAGE, EVENT_CONNECT, EVENT_ERROR, EVENT_CLOSE});
}

/* tcp server async works */
napi_value SocketModuleExports::TCPServerSocket::Listen(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(TcpServerListenContext, ExecTcpServerListen, ListenCallback, MakeTcpServerSocket,
                            TCP_SERVER_LISTEN_NAME);
}

napi_value SocketModuleExports::TCPServerSocket::Close(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(TcpServerCloseContext, ExecTcpServerClose, TcpServerCloseCallback, nullptr,
                            TCP_SERVER_CLOSE_NAME);
}

napi_value SocketModuleExports::TCPServerSocket::GetState(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(TcpServerGetStateContext, ExecTcpServerGetState, TcpServerGetStateCallback, nullptr,
                            TCP_SERVER_GET_STATE);
}

napi_value SocketModuleExports::TCPServerSocket::GetLocalAddress(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(TcpServerGetLocalAddressContext, ExecTcpServerGetLocalAddress,
                            TcpServerGetLocalAddressCallback, nullptr, TCP_SERVER_GET_LOCAL_ADDRESS);
}

napi_value SocketModuleExports::TCPServerSocket::SetExtraOptions(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(TcpServerSetExtraOptionsContext, ExecTcpServerSetExtraOptions,
                            TcpServerSetExtraOptionsCallback, nullptr, TCP_SERVER_SET_EXTRA_OPTIONS_NAME);
}

napi_value SocketModuleExports::TCPServerSocket::GetSocketFd(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(TcpServerGetSocketFdContext, ExecTcpServerGetSocketFd,
                            TcpServerGetSocketFdCallback, nullptr, TCP_SERVER_GET_SOCKET_FD);
}

napi_value SocketModuleExports::TCPServerSocket::On(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::OnSharedManager(env, info, {EVENT_MESSAGE, EVENT_CONNECT, EVENT_ERROR, EVENT_CLOSE}, false);
}

napi_value SocketModuleExports::TCPServerSocket::Off(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::OffSharedManager(env, info, {EVENT_MESSAGE, EVENT_CONNECT, EVENT_ERROR, EVENT_CLOSE});
}

/* local socket */
napi_value SocketModuleExports::LocalSocket::Bind(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(LocalSocketBindContext, ExecLocalSocketBind, LocalSocketBindCallback, MakeLocalSocketBind,
                            LOCAL_SOCKET_BIND);
}

napi_value SocketModuleExports::LocalSocket::Connect(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(LocalSocketConnectContext, ExecLocalSocketConnect, LocalSocketConnectCallback,
                            MakeLocalSocketConnect, LOCAL_SOCKET_CONNECT);
}

napi_value SocketModuleExports::LocalSocket::Send(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithOutAsyncWorkWithSharedManager<LocalSocketSendContext>(
        env, info,
        [](napi_env, napi_value, LocalSocketSendContext *context) -> bool {
            SocketAsyncWork::ExecLocalSocketSend(context->GetEnv(), context);
            return true;
        },
        LOCAL_SOCKET_SEND, SocketAsyncWork::ExecLocalSocketSend, SocketAsyncWork::LocalSocketSendCallback);
}

napi_value SocketModuleExports::LocalSocket::Close(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(LocalSocketCloseContext, ExecLocalSocketClose, LocalSocketCloseCallback, nullptr,
                            LOCAL_SOCKET_CLOSE);
}

napi_value SocketModuleExports::LocalSocket::GetState(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(LocalSocketGetStateContext, ExecLocalSocketGetState, LocalSocketGetStateCallback, nullptr,
                            LOCAL_SOCKET_GET_STATE);
}

napi_value SocketModuleExports::LocalSocket::GetLocalAddress(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(LocalSocketGetLocalAddressContext, ExecLocalSocketGetLocalAddress,
                            LocalSocketGetLocalAddressCallback, nullptr, LOCAL_SOCKET_GET_LOCAL_ADDRESS);
}

napi_value SocketModuleExports::LocalSocket::GetSocketFd(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(LocalSocketGetSocketFdContext, ExecLocalSocketGetSocketFd, LocalSocketGetSocketFdCallback,
                            nullptr, LOCAL_SOCKET_GET_SOCKET_FD);
}

napi_value SocketModuleExports::LocalSocket::SetExtraOptions(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(LocalSocketSetExtraOptionsContext, ExecLocalSocketSetExtraOptions,
                            LocalSocketSetExtraOptionsCallback, nullptr, LOCAL_SOCKET_SET_EXTRA_OPTIONS);
}

napi_value SocketModuleExports::LocalSocket::GetExtraOptions(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(LocalSocketGetExtraOptionsContext, ExecLocalSocketGetExtraOptions,
                            LocalSocketGetExtraOptionsCallback, nullptr, LOCAL_SOCKET_GET_EXTRA_OPTIONS);
}

napi_value SocketModuleExports::LocalSocket::On(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::OnSharedManager(env, info, {EVENT_MESSAGE, EVENT_CONNECT, EVENT_ERROR, EVENT_CLOSE}, false);
}

napi_value SocketModuleExports::LocalSocket::Off(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::OffSharedManager(env, info, {EVENT_MESSAGE, EVENT_CONNECT, EVENT_ERROR, EVENT_CLOSE});
}

/* local socket server */
napi_value SocketModuleExports::LocalSocketServer::Listen(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(LocalSocketServerListenContext, ExecLocalSocketServerListen,
                            LocalSocketServerListenCallback, MakeLocalServerSocket, LOCAL_SOCKET_SERVER_LISTEN);
}

napi_value SocketModuleExports::LocalSocketServer::Close(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(LocalSocketServerEndContext, ExecLocalSocketServerEnd,
                            LocalSocketServerEndCallback, nullptr, LOCAL_SOCKET_SERVER_END);
}

napi_value SocketModuleExports::LocalSocketServer::GetState(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(LocalSocketServerGetStateContext, ExecLocalSocketServerGetState,
                            LocalSocketServerGetStateCallback, nullptr, LOCAL_SOCKET_SERVER_GET_STATE);
}

napi_value SocketModuleExports::LocalSocketServer::GetLocalAddress(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(LocalSocketServerGetLocalAddressContext, ExecLocalSocketServerGetLocalAddress,
                            LocalSocketServerGetLocalAddressCallback, nullptr, LOCAL_SOCKET_SERVER_GET_LOCAL_ADDRESS);
}

napi_value SocketModuleExports::LocalSocketServer::SetExtraOptions(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(LocalSocketServerSetExtraOptionsContext, ExecLocalSocketServerSetExtraOptions,
                            LocalSocketServerSetExtraOptionsCallback, nullptr, LOCAL_SOCKET_SERVER_SET_EXTRA_OPTIONS);
}

napi_value SocketModuleExports::LocalSocketServer::GetExtraOptions(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(LocalSocketServerGetExtraOptionsContext, ExecLocalSocketServerGetExtraOptions,
                            LocalSocketServerGetExtraOptionsCallback, nullptr, LOCAL_SOCKET_SERVER_GET_EXTRA_OPTIONS);
}

napi_value SocketModuleExports::LocalSocketServer::GetSocketFd(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(LocalSocketServerGetSocketFdContext, ExecLocalSocketServerGetSocketFd,
                            LocalSocketServerGetSocketFdCallback, nullptr, LOCAL_SOCKET_SERVER_GET_SOCKET_FD);
}

napi_value SocketModuleExports::LocalSocketServer::On(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::OnSharedManager(env, info, {EVENT_MESSAGE, EVENT_CONNECT, EVENT_ERROR, EVENT_CLOSE}, false);
}

napi_value SocketModuleExports::LocalSocketServer::Off(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::OffSharedManager(env, info, {EVENT_MESSAGE, EVENT_CONNECT, EVENT_ERROR, EVENT_CLOSE});
}

/* localsocket connection */
napi_value SocketModuleExports::LocalSocketConnection::Send(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(
        LocalSocketServerSendContext, ExecLocalSocketConnectionSend, LocalSocketConnectionSendCallback,
        [](napi_env theEnv, napi_value thisVal, LocalSocketServerSendContext *context) -> bool {
            context->SetClientId(NapiUtils::GetInt32Property(theEnv, thisVal, PROPERTY_CLIENT_ID));
            return true;
        },
        LOCAL_SOCKET_CONNECTION_SEND);
}

napi_value SocketModuleExports::LocalSocketConnection::Close(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(
        LocalSocketServerCloseContext, ExecLocalSocketConnectionClose, LocalSocketConnectionCloseCallback,
        [](napi_env theEnv, napi_value thisVal, LocalSocketServerCloseContext *context) -> bool {
            context->SetClientId(NapiUtils::GetInt32Property(theEnv, thisVal, PROPERTY_CLIENT_ID));
            return true;
        },
        LOCAL_SOCKET_CONNECTION_CLOSE);
}

napi_value SocketModuleExports::LocalSocketConnection::GetLocalAddress(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(
        LocalSocketServerGetLocalAddressContext, ExecLocalSocketConnectionGetLocalAddress,
        LocalSocketConnectionGetLocalAddressCallback,
        [](napi_env theEnv, napi_value thisVal, LocalSocketServerGetLocalAddressContext *context) -> bool {
            context->SetClientId(NapiUtils::GetInt32Property(theEnv, thisVal, PROPERTY_CLIENT_ID));
            return true;
        }, LOCAL_SOCKET_CONNECTION_GET_LOCAL_ADDRESS);
}

napi_value SocketModuleExports::LocalSocketConnection::GetSocketFd(napi_env env, napi_callback_info info)
{
    return SOCKET_INTERFACE(
        LocalSocketServerGetSocketFdContext, ExecLocalSocketConnectionGetSocketFd,
        LocalSocketConnectionGetSocketFdCallback,
        [](napi_env theEnv, napi_value thisVal, LocalSocketServerGetSocketFdContext *context) -> bool {
            context->SetClientId(NapiUtils::GetInt32Property(theEnv, thisVal, PROPERTY_CLIENT_ID));
            return true;
        }, LOCAL_SOCKET_CONNECTION_GET_SOCKET_FD);
}

napi_value SocketModuleExports::LocalSocketConnection::On(napi_env env, napi_callback_info info)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    if (paramsCount != PARAM_COUNT_TWO || NapiUtils::GetValueType(env, params[0]) != napi_string ||
        NapiUtils::GetValueType(env, params[PARAM_COUNT_TWO - 1]) != napi_function) {
        NETSTACK_LOGE("localsocket connection on, err param");
        napi_throw_error(env, std::to_string(PARSE_ERROR_CODE).c_str(), PARSE_ERROR_MSG);
        return NapiUtils::GetUndefined(env);
    }
    std::initializer_list<std::string> events = {EVENT_MESSAGE, EVENT_CONNECT, EVENT_ERROR, EVENT_CLOSE};
    std::string event = NapiUtils::GetStringFromValueUtf8(env, params[0]);
    if (std::find(events.begin(), events.end(), event) == events.end()) {
        return NapiUtils::GetUndefined(env);
    }
    std::shared_ptr<EventManager> *sharedManager = nullptr;
    napi_unwrap(env, thisVal, reinterpret_cast<void **>(&sharedManager));
    if (sharedManager == nullptr || *sharedManager == nullptr) {
        NETSTACK_LOGE("failed to unwrap");
        return NapiUtils::GetUndefined(env);
    }
    auto manager = *sharedManager;
    manager->AddListener(env, event, params[PARAM_COUNT_TWO - 1], false, false);
    if (event == EVENT_MESSAGE) {
        if (auto mgr = reinterpret_cast<LocalSocketExec::LocalSocketConnectionData *>(manager->GetData());
            mgr != nullptr) {
            mgr->serverManager_->NotifyRegisterEvent();
        }
    }
    return NapiUtils::GetUndefined(env);
}

napi_value SocketModuleExports::LocalSocketConnection::Off(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::OffSharedManager(env, info, {EVENT_MESSAGE, EVENT_CONNECT, EVENT_ERROR, EVENT_CLOSE});
}

static napi_module g_socketModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = SocketModuleExports::InitSocketModule,
    .nm_modname = SOCKET_MODULE_NAME,
    .nm_priv = nullptr,
    .reserved = {nullptr},
};
/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void RegisterSocketModule(void)
{
    napi_module_register(&g_socketModule);
}
} // namespace OHOS::NetStack::Socket
