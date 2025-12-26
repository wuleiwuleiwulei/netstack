/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <map>
#include <vector>
#include <cstring>
#include <iostream>
#include <string>
#include <atomic>
#include <memory>
#include <queue>
#include <thread>
#include <unistd.h>
#include <sstream>
#include <algorithm>
#include <shared_mutex>
#include <arpa/inet.h>
#include <unordered_set>
#include <unordered_map>
#include <securec.h>

#include "netstack_log.h"
#include "netstack_common_utils.h"
#include "websocket_server_innerapi.h"

#define LWS_PLUGIN_STATIC

static constexpr const char *WEBSOCKET_SERVER_THREAD_RUN = "OS_NET_WSJsSer";

static constexpr const char *LINK_DOWN = "The link is down";

static constexpr const uint32_t MAX_CONCURRENT_CLIENTS_NUMBER = 10;

static constexpr const uint32_t MAX_CONNECTIONS_FOR_ONE_CLIENT = 10;

static constexpr const int32_t COMMON_ERROR_CODE = 200;

namespace OHOS::NetStack::WebSocketServer {
enum WebsocketErrorCode {
    WEBSOCKET_CONNECT_FAILED = -1,
    WEBSOCKET_ERROR_PERMISSION_DENIED = 201,
    WEBSOCKET_ERROR_CODE_BASE = 2302000,
    WEBSOCKET_ERROR_CODE_URL_ERROR = WEBSOCKET_ERROR_CODE_BASE + 1,
    WEBSOCKET_ERROR_CODE_FILE_NOT_EXIST = WEBSOCKET_ERROR_CODE_BASE + 2,
    WEBSOCKET_ERROR_CODE_CONNECT_ALREADY_EXIST = WEBSOCKET_ERROR_CODE_BASE + 3,
    WEBSOCKET_ERROR_CODE_INVALID_NIC = WEBSOCKET_ERROR_CODE_BASE + 4,
    WEBSOCKET_ERROR_CODE_INVALID_PORT = WEBSOCKET_ERROR_CODE_BASE + 5,
    WEBSOCKET_ERROR_CODE_CONNECTION_NOT_EXIST = WEBSOCKET_ERROR_CODE_BASE + 6,
    WEBSOCKET_NOT_ALLOWED_HOST = 2302998,
    WEBSOCKET_UNKNOWN_OTHER_ERROR = 2302999
};

static const std::map<int32_t, std::string> WEBSOCKET_ERR_MAP = { { WEBSOCKET_CONNECT_FAILED,
    "Websocket connect failed" },
    { WEBSOCKET_ERROR_PERMISSION_DENIED, "Permission denied" },
    { WEBSOCKET_ERROR_CODE_URL_ERROR, "Websocket url error" },
    { WEBSOCKET_ERROR_CODE_FILE_NOT_EXIST, "Websocket file not exist" },
    { WEBSOCKET_ERROR_CODE_CONNECT_ALREADY_EXIST, "Websocket connection exist" },
    { WEBSOCKET_ERROR_CODE_INVALID_NIC, "Can't listen to the given NIC" },
    { WEBSOCKET_ERROR_CODE_INVALID_PORT, "Can't listen to the given Port" },
    { WEBSOCKET_ERROR_CODE_CONNECTION_NOT_EXIST, "websocket connection does not exist" },
    { WEBSOCKET_NOT_ALLOWED_HOST, "It is not allowed to access this domain" },
    { WEBSOCKET_UNKNOWN_OTHER_ERROR, "Websocket Unknown Other Error" } };

enum {
    CLOSE_REASON_NORMAL_CLOSE [[maybe_unused]] = 1000,
    CLOSE_REASON_SERVER_CLOSED [[maybe_unused]] = 1001,
    CLOSE_REASON_PROTOCOL_ERROR [[maybe_unused]] = 1002,
    CLOSE_REASON_UNSUPPORT_DATA_TYPE [[maybe_unused]] = 1003,
    CLOSE_REASON_RESERVED1 [[maybe_unused]],
    CLOSE_REASON_RESERVED2 [[maybe_unused]],
    CLOSE_REASON_RESERVED3 [[maybe_unused]],
    CLOSE_REASON_RESERVED4 [[maybe_unused]],
    CLOSE_REASON_RESERVED5 [[maybe_unused]],
    CLOSE_REASON_RESERVED6 [[maybe_unused]],
    CLOSE_REASON_RESERVED7 [[maybe_unused]],
    CLOSE_REASON_RESERVED8 [[maybe_unused]],
    CLOSE_REASON_RESERVED9 [[maybe_unused]],
    CLOSE_REASON_RESERVED10 [[maybe_unused]],
    CLOSE_REASON_RESERVED11 [[maybe_unused]],
    CLOSE_REASON_RESERVED12 [[maybe_unused]],
};

struct CallbackDispatcher {
    lws_callback_reasons reason;
    int (*callback)(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);
};

static const lws_http_mount mount = {
    NULL, "/", "./mount-origin", "index.html", NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, LWSMPRO_FILE, 1, NULL,
};

void OnServerError(WebSocketServer *server, int32_t code)
{
    if (server == nullptr || server->GetServerContext() == nullptr) {
        NETSTACK_LOGE("server or context is null");
        return;
    }
    if (server->onErrorCallback_ == nullptr) {
        NETSTACK_LOGE("onErrorCallback_ is null");
        return;
    }
    ErrorResult errorResult;
    errorResult.errorCode = static_cast<unsigned int>(code);
    auto it = WEBSOCKET_ERR_MAP.find(code);
    if (it != WEBSOCKET_ERR_MAP.end()) {
        errorResult.errorMessage = it->second.c_str();
    }
    server->onErrorCallback_(server, errorResult);
}

// LCOV_EXCL_START
void RunServerService(WebSocketServer *server)
{
    NETSTACK_LOGI("websocket run service start");
    int res = 0;
    lws_context *context = server->GetServerContext()->GetContext();
    if (context == nullptr) {
        NETSTACK_LOGE("context is null");
        return;
    }
    while (res >= 0 && !server->GetServerContext()->IsThreadStop()) {
        res = lws_service(context, 0);
    }
    server->Destroy();
}
// LCOV_EXCL_STOP

int RaiseServerError(WebSocketServer *server)
{
    OnServerError(server, COMMON_ERROR_CODE);
    return -1;
}

// LCOV_EXCL_START
int HttpDummy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    int ret = lws_callback_http_dummy(wsi, reason, user, in, len);
    if (ret < 0) {
        OnServerError(reinterpret_cast<WebSocketServer *>(user), COMMON_ERROR_CODE);
    }
    return 0;
}

bool GetPeerConnMsg(lws *wsi, std::string &clientId, SocketConnection &conn)
{
    struct sockaddr_storage addr {};
    socklen_t addrLen = sizeof(addr);
    int ret = getpeername(lws_get_socket_fd(wsi), reinterpret_cast<sockaddr *>(&addr), &addrLen);
    if (ret != 0) {
        NETSTACK_LOGE("getpeername failed");
        return false;
    }
    char ipStr[INET6_ADDRSTRLEN] = {0};
    if (addr.ss_family == AF_INET) {
        NETSTACK_LOGI("family is ipv4");
        auto *addrIn = reinterpret_cast<struct sockaddr_in *>(&addr);
        inet_ntop(AF_INET, &addrIn->sin_addr, ipStr, sizeof(ipStr));
        uint16_t port = ntohs(addrIn->sin_port);
        conn.clientPort = static_cast<uint32_t>(port);
        conn.clientIP = ipStr;
        clientId = std::string(ipStr) + ":" + std::to_string(port);
    } else if (addr.ss_family == AF_INET6) {
        NETSTACK_LOGI("family is ipv6");
        auto *addrIn6 = reinterpret_cast<struct sockaddr_in6 *>(&addr);
        inet_ntop(AF_INET6, &addrIn6->sin6_addr, ipStr, sizeof(ipStr));
        uint16_t port = ntohs(addrIn6->sin6_port);
        conn.clientPort = static_cast<uint32_t>(port);
        conn.clientIP = ipStr;
        clientId = std::string(ipStr) + ":" + std::to_string(port);
    } else {
        NETSTACK_LOGE("getpeer Ipv4 or Ipv6 failed");
        return false;
    }
    return true;
}

int LwsCallbackEstablished(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback server established");
    lws_context *context = lws_get_context(wsi);
    WebSocketServer *server = static_cast<WebSocketServer *>(lws_context_user(context));
    if (server == nullptr) {
        NETSTACK_LOGE("server is null");
        return RaiseServerError(server);
    }
    if (server->GetServerContext() == nullptr) {
        NETSTACK_LOGE("server context is null");
        return RaiseServerError(server);
    }
    if (server->GetServerContext()->IsClosed() || server->GetServerContext()->IsThreadStop()) {
        NETSTACK_LOGE("server is closed or thread is stopped");
        return RaiseServerError(server);
    }
    lws_context *lwsContext = lws_get_context(wsi);
    auto clientUserData = std::make_shared<UserData>(lwsContext);
    lws_set_wsi_user(wsi, clientUserData.get());
    server->GetServerContext()->AddClientUserData(wsi, clientUserData);
    std::string clientId;
    SocketConnection connection;
    bool ret = GetPeerConnMsg(wsi, clientId, connection);
    if (!ret) {
        NETSTACK_LOGE("GetPeerConnMsg failed");
        return RaiseServerError(server);
    }
    server->GetServerContext()->AddConnections(clientId, wsi, connection);
    clientUserData->SetLws(wsi);
    clientUserData->TriggerWritable();
    if (server->onConnectCallback_ != nullptr) {
        server->onConnectCallback_(server, connection);
    }
    return HttpDummy(wsi, reason, user, in, len);
}
// LCOV_EXCL_STOP

bool IsOverMaxConcurrentClientsCnt(WebSocketServer *server, const std::vector<SocketConnection> &connections,
    const std::string &ip)
{
    std::unordered_set<std::string> uniqueIp;
    for (const auto &conn : connections) {
        uniqueIp.insert(conn.clientIP);
    }
    if (uniqueIp.find(ip) != uniqueIp.end()) {
        return uniqueIp.size() > static_cast<size_t>(
            server->GetServerContext()->startServerConfig_.maxConcurrentClientsNumber);
    } else {
        return (uniqueIp.size() + 1) > static_cast<size_t>(
            server->GetServerContext()->startServerConfig_.maxConcurrentClientsNumber);
    }
}

bool IsOverMaxCntForOneClient(WebSocketServer *server, const std::vector<SocketConnection> &connections,
    const std::string &ip)
{
    uint32_t cnt = 0;
    for (auto it = connections.begin(); it != connections.end(); ++it) {
        if (ip == it->clientIP) {
            ++cnt;
        }
    }
    if (cnt + 1 > static_cast<uint32_t>(server->GetServerContext()->startServerConfig_.maxConnectionsForOneClient)) {
        return true;
    }
    return false;
}

bool IsOverMaxClientConns(WebSocketServer *server, const std::string &ip)
{
    std::vector<SocketConnection> connections;
    server->ListAllConnections(connections);
    if (IsOverMaxConcurrentClientsCnt(server, connections, ip)) {
        NETSTACK_LOGI("current client connections is over max concurrent number");
        return true;
    }
    if (IsOverMaxCntForOneClient(server, connections, ip)) {
        NETSTACK_LOGI("current connections for one client is over max number");
        return true;
    }
    return false;
}

// LCOV_EXCL_START
int LwsCallbackClosed(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback server closed");
    lws_context *context = lws_get_context(wsi);
    WebSocketServer *server = static_cast<WebSocketServer *>(lws_context_user(context));
    if (server == nullptr) {
        NETSTACK_LOGE("server is null");
        return -1;
    }
    if (server->GetServerContext() == nullptr) {
        NETSTACK_LOGE("server context is null");
        return -1;
    }
    if (server->GetServerContext()->IsClosed() || server->GetServerContext()->IsThreadStop()) {
        NETSTACK_LOGE("server is closed or thread is stopped");
        return -1;
    }
    if (wsi == nullptr) {
        NETSTACK_LOGE("wsi is null");
        return -1;
    }
    auto clientUserData = reinterpret_cast<UserData *>(lws_wsi_user(wsi));
    if (clientUserData == nullptr) {
        NETSTACK_LOGE("clientUserData is null");
        return RaiseServerError(server);
    }
    clientUserData->SetThreadStop(true);
    if ((clientUserData->closeReason).empty()) {
        clientUserData->Close(clientUserData->closeStatus, LINK_DOWN);
    }
    if (clientUserData->closeStatus == LWS_CLOSE_STATUS_NOSTATUS) {
        NETSTACK_LOGE("The link is down, onError");
        OnServerError(server, COMMON_ERROR_CODE);
    }
    std::string clientId = server->GetServerContext()->GetClientIdFromConnectionByWsi(wsi);
    if (server->onCloseCallback_ != nullptr) {
        SocketConnection sc = server->GetServerContext()->GetConnectionFromWsi(wsi);
        CloseResult cr;
        cr.code = clientUserData->closeStatus;
        cr.reason = clientUserData->closeReason.c_str();
        server->onCloseCallback_(server, cr, sc);
    }
    server->GetServerContext()->RemoveConnections(clientId);
    server->GetServerContext()->RemoveClientUserData(wsi);
    lws_set_wsi_user(wsi, nullptr);
    if (server->GetServerContext()->IsClosed() && !server->GetServerContext()->IsThreadStop()) {
        NETSTACK_LOGI("server service is stopped");
        server->GetServerContext()->SetThreadStop(true);
    }
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackWsiDestroyServer(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws server callback wsi destroy");
    lws_context *context = lws_get_context(wsi);
    WebSocketServer *server = static_cast<WebSocketServer *>(lws_context_user(context));
    if (wsi == nullptr) {
        NETSTACK_LOGE("wsi is null");
        return -1;
    }
    if (server == nullptr) {
        NETSTACK_LOGE("server is null");
        return RaiseServerError(server);
    }
    if (server->GetServerContext() == nullptr) {
        NETSTACK_LOGE("server context is null");
        return RaiseServerError(server);
    }
    server->GetServerContext()->SetContext(nullptr);
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackProtocolDestroyServer(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws server callback protocol destroy");
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackServerWriteable(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback Server writable");
    lws_context *context = lws_get_context(wsi);
    WebSocketServer *server = static_cast<WebSocketServer *>(lws_context_user(context));
    if (server == nullptr) {
        NETSTACK_LOGE("server is null");
        return -1;
    }
    if (server->GetServerContext() == nullptr) {
        NETSTACK_LOGE("server context is null");
        return -1;
    }
    if (server->GetServerContext()->IsThreadStop()) {
        NETSTACK_LOGE("server is closed or thread is stopped");
        return -1;
    }
    // client
    auto *clientUserData = reinterpret_cast<UserData *>(lws_wsi_user(wsi));
    if (clientUserData == nullptr) {
        NETSTACK_LOGE("clientUserData is null");
        return RaiseServerError(server);
    }
    if (clientUserData->IsClosed()) {
        NETSTACK_LOGI("client is closed, need to close");
        lws_close_reason(wsi, clientUserData->closeStatus,
            reinterpret_cast<unsigned char *>(const_cast<char *>(clientUserData->closeReason.c_str())),
            strlen(clientUserData->closeReason.c_str()));
        return -1;
    }
    auto sendData = clientUserData->Pop();
    if (sendData.data == nullptr || sendData.length == 0) {
        NETSTACK_LOGE("send data is empty");
        return HttpDummy(wsi, reason, user, in, len);
    }
    int sendLength = lws_write(wsi, reinterpret_cast<unsigned char *>(sendData.data) + LWS_SEND_BUFFER_PRE_PADDING,
        sendData.length, sendData.protocol);
    free(sendData.data);
    NETSTACK_LOGD("lws send data length is %{public}d", sendLength);
    if (!clientUserData->IsEmpty()) {
        NETSTACK_LOGE("userData is not empty");
        clientUserData->TriggerWritable();
    }
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackWsPeerInitiatedCloseServer(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws server callback ws peer initiated close");
    if (wsi == nullptr) {
        NETSTACK_LOGE("wsi is null");
        return -1;
    }
    lws_context *context = lws_get_context(wsi);
    WebSocketServer *server = static_cast<WebSocketServer *>(lws_context_user(context));
    if (server == nullptr) {
        NETSTACK_LOGE("server is null");
        return -1;
    }
    if (server->GetServerContext() == nullptr) {
        NETSTACK_LOGE("server context is null");
        return -1;
    }
    if (in == nullptr || len < sizeof(uint16_t)) {
        NETSTACK_LOGI("No close reason");
        server->GetServerContext()->Close(LWS_CLOSE_STATUS_NORMAL, "");
        return HttpDummy(wsi, reason, user, in, len);
    }
    uint16_t closeStatus = ntohs(*reinterpret_cast<uint16_t *>(in));
    std::string closeReason;
    closeReason.append(reinterpret_cast<char *>(in) + sizeof(uint16_t), len - sizeof(uint16_t));
    auto *clientUserData = reinterpret_cast<UserData *>(lws_wsi_user(wsi));
    clientUserData->Close(static_cast<lws_close_status>(closeStatus), closeReason);
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackFilterProtocolConnection(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    lws_context *context = lws_get_context(wsi);
    WebSocketServer *server = static_cast<WebSocketServer *>(lws_context_user(context));
    if (server == nullptr) {
        NETSTACK_LOGE("server is null");
        return -1;
    }
    if (server->GetServerContext() == nullptr) {
        NETSTACK_LOGE("server context is null");
        return -1;
    }
    if (server->GetServerContext()->IsClosed() || server->GetServerContext()->IsThreadStop()) {
        NETSTACK_LOGE("server is closed or thread is stopped");
        return -1;
    }
    std::string clientId;
    SocketConnection connection;
    bool ret = GetPeerConnMsg(wsi, clientId, connection);
    if (!ret) {
        NETSTACK_LOGE("GetPeerConnMsg failed");
        return RaiseServerError(server);
    }
    if (IsOverMaxClientConns(server, connection.clientIP)) {
        NETSTACK_LOGE("current connections count is more than limit, need to close");
        return RaiseServerError(server);
    }
    if (!server->GetServerContext()->IsAllowConnection(connection.clientIP)) {
        NETSTACK_LOGE("Rejected malicious connection");
        return RaiseServerError(server);
    }
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackReceive(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback server receive");
    lws_context *context = lws_get_context(wsi);
    WebSocketServer *server = static_cast<WebSocketServer *>(lws_context_user(context));
    if (server == nullptr) {
        NETSTACK_LOGE("server is null");
        return -1;
    }
    if (server->GetServerContext() == nullptr) {
        NETSTACK_LOGE("server context is null");
        return -1;
    }
    if (len > INT32_MAX) {
        NETSTACK_LOGE("data length too long");
        return -1;
    }
    bool isBinary = lws_frame_is_binary(wsi);
    if (isBinary) {
        server->GetServerContext()->AppendWsServerBinaryData(wsi, in, len);
    } else {
        server->GetServerContext()->AppendWsServerTextData(wsi, in, len);
    }
    auto isFinal = lws_is_final_fragment(wsi);
    if (!isFinal) {
        return HttpDummy(wsi, reason, user, in, len);
    }
    SocketConnection connection = server->GetServerContext()->GetConnectionFromWsi(wsi);
    if (server->onMessageReceiveCallback_ != nullptr) {
        if (isBinary) {
            auto data = server->GetServerContext()->GetWsServerBinaryData(wsi);
            server->onMessageReceiveCallback_(server, data, data.size(), connection);
        } else {
            auto data = server->GetServerContext()->GetWsServerTextData(wsi);
            server->onMessageReceiveCallback_(server, data, data.size(), connection);
        }
    }
    server->GetServerContext()->ClearWsServerBinaryData(wsi);
    server->GetServerContext()->ClearWsServerTextData(wsi);
    return HttpDummy(wsi, reason, user, in, len);
}
// LCOV_EXCL_STOP

int lwsServerCallback(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGI("lws server callback reason is %{public}d", reason);
    CallbackDispatcher dispatchers[] = {
        {LWS_CALLBACK_ESTABLISHED, LwsCallbackEstablished},
        {LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION, LwsCallbackFilterProtocolConnection},
        {LWS_CALLBACK_RECEIVE, LwsCallbackReceive},
        {LWS_CALLBACK_SERVER_WRITEABLE, LwsCallbackServerWriteable},
        {LWS_CALLBACK_WS_PEER_INITIATED_CLOSE, LwsCallbackWsPeerInitiatedCloseServer},
        {LWS_CALLBACK_CLOSED, LwsCallbackClosed},
        {LWS_CALLBACK_WSI_DESTROY, LwsCallbackWsiDestroyServer},
        {LWS_CALLBACK_PROTOCOL_DESTROY, LwsCallbackProtocolDestroyServer},
    };
    for (const auto dispatcher : dispatchers) {
        if (dispatcher.reason == reason) {
            return dispatcher.callback(wsi, reason, user, in, len);
        }
    }
    return HttpDummy(wsi, reason, user, in, len);
}

static const lws_protocols LWS_SERVER_PROTOCOLS[] = {
    {"lws_server1", lwsServerCallback, 0, 0},
    {NULL, NULL, 0, 0}, // this line is needed
};

void FillServerContextInfo(WebSocketServer *server, lws_context_creation_info &info)
{
    info.options = LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;
    info.port = static_cast<int32_t>(server->GetServerContext()->startServerConfig_.serverPort);
    info.mounts = &mount;
    info.protocols = LWS_SERVER_PROTOCOLS;
    info.vhost_name = "localhost";
    info.user = server;
    // maybe
    info.gid = -1;
    info.uid = -1;
}

static bool CheckFilePath(std::string &path)
{
    char tmpPath[PATH_MAX] = {0};
    if (!realpath(static_cast<const char *>(path.c_str()), tmpPath)) {
        NETSTACK_LOGE("path is error");
        return false;
    }
    path = tmpPath;
    return true;
}

bool FillServerCertPath(ServerContext *context, lws_context_creation_info &info)
{
    ServerCert sc = context->startServerConfig_.serverCert;
    if (!sc.certPath.empty()) {
        if (!CheckFilePath(sc.certPath) || !CheckFilePath(sc.keyPath)) {
            NETSTACK_LOGE("client cert not exist");
            return false;
        }
        info.ssl_cert_filepath = sc.certPath.c_str();
        info.ssl_private_key_filepath = sc.keyPath.c_str();
    }
    return true;
}

void CloseAllConnection(ServerContext *serverContext)
{
    if (serverContext == nullptr) {
        NETSTACK_LOGE("server context is nullptr");
        return;
    }
    auto connListTmp = serverContext->GetWebSocketConnection();
    if (connListTmp.empty()) {
        NETSTACK_LOGE("webSocketConnection is empty");
        if (!serverContext->IsThreadStop()) {
            NETSTACK_LOGI("server service is stopped");
            serverContext->SetThreadStop(true);
        }
        return;
    }
    const char *closeReason = "server is going away";
    for (auto [id, connPair] : connListTmp) {
        if (connPair.first == nullptr) {
            NETSTACK_LOGE("clientId not found:%{public}s", id.c_str());
            continue;
        }
        auto *clientUserData = reinterpret_cast<UserData *>(lws_wsi_user(connPair.first));
        clientUserData->Close(LWS_CLOSE_STATUS_GOINGAWAY, closeReason);
        clientUserData->TriggerWritable();
    }
    NETSTACK_LOGI("CloseAllConnection OK");
}

WebSocketServer::WebSocketServer()
{
    serverContext_ = new ServerContext();
}

WebSocketServer::~WebSocketServer()
{
    Destroy();
    delete serverContext_;
    serverContext_ = nullptr;
}

int WebSocketServer::Start(const ServerConfig &config)
{
    NETSTACK_LOGD("websocket server start exec");
    if (!CommonUtils::HasInternetPermission()) {
        serverContext_->SetPermissionDenied(true);
        NETSTACK_LOGE("Start: Permission denied");
        return WEBSOCKET_ERROR_PERMISSION_DENIED;
    }
    if (!CommonUtils::IsValidIPV4(config.serverIP) && !CommonUtils::IsValidIPV6(config.serverIP)) {
        NETSTACK_LOGE("IPV4 and IPV6 are not valid");
        return WEBSOCKET_ERROR_CODE_INVALID_NIC;
    }
    if (!CommonUtils::IsValidPort(config.serverPort)) {
        NETSTACK_LOGE("Port is not valid");
        return WEBSOCKET_ERROR_CODE_INVALID_PORT;
    }
    if (config.maxConcurrentClientsNumber > static_cast<int>(MAX_CONCURRENT_CLIENTS_NUMBER)) {
        NETSTACK_LOGE("max concurrent clients number is set over limit");
        return WEBSOCKET_UNKNOWN_OTHER_ERROR;
    }
    if (config.maxConnectionsForOneClient > static_cast<int>(MAX_CONNECTIONS_FOR_ONE_CLIENT)) {
        NETSTACK_LOGE("max connection number for one client is set over limit");
        return WEBSOCKET_UNKNOWN_OTHER_ERROR;
    }
    serverContext_->startServerConfig_ = config;
    lws_context_creation_info info = {};
    FillServerContextInfo(this, info);
    if (!FillServerCertPath(serverContext_, info)) {
        NETSTACK_LOGE("FillServerCertPath error");
        return WEBSOCKET_ERROR_CODE_FILE_NOT_EXIST;
    }
    lws_context *lwsContext = nullptr;
    std::shared_ptr<UserData> userData;
    lwsContext = lws_create_context(&info);
    serverContext_->SetContext(lwsContext);
    std::thread serviceThread(RunServerService, this);
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(WEBSOCKET_SERVER_THREAD_RUN);
#else
    pthread_setname_np(serviceThread.native_handle(), WEBSOCKET_SERVER_THREAD_RUN);
#endif
    serviceThread.detach();
    return 0;
}

int WebSocketServer::Stop()
{
    if (serverContext_->GetContext() == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return -1;
    }
    if (!CommonUtils::HasInternetPermission()) {
        serverContext_->SetPermissionDenied(true);
        return -1;
    }
    if (serverContext_->IsClosed() || serverContext_->IsThreadStop()) {
        NETSTACK_LOGE("session is closed or stopped");
        return -1;
    }
    CloseAllConnection(serverContext_);
    serverContext_->Close(LWS_CLOSE_STATUS_GOINGAWAY, "");
    NETSTACK_LOGI("CloseServer OK");
    return 0;
}

int WebSocketServer::Close(const SocketConnection &connection, const CloseOption &option)
{
    if (serverContext_->GetContext() == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return -1;
    }
    if (!CommonUtils::HasInternetPermission()) {
        serverContext_->SetPermissionDenied(true);
        return -1;
    }
    if (connection.clientIP.empty()) {
        NETSTACK_LOGE("connection is empty");
        return -1;
    }
    std::string clientId = connection.clientIP + ":" + std::to_string(connection.clientPort);
    NETSTACK_LOGI("Close, clientID:%{public}s", clientId.c_str());
    auto wsi = serverContext_->GetClientWsi(clientId);
    if (wsi == nullptr) {
        NETSTACK_LOGE("clientId not found:%{public}s", clientId.c_str());
        return WEBSOCKET_ERROR_CODE_CONNECTION_NOT_EXIST;
    }
    auto *clientUserData = reinterpret_cast<UserData *>(lws_wsi_user(wsi));
    if (clientUserData == nullptr) {
        NETSTACK_LOGE("clientUser data is nullptr");
        return -1;
    }
    if (clientUserData->IsClosed() || clientUserData->IsThreadStop()) {
        NETSTACK_LOGE("session is closed or stopped");
        return -1;
    }
    clientUserData->Close(static_cast<lws_close_status>(option.code), option.reason);
    clientUserData->TriggerWritable();
    NETSTACK_LOGI("Close OK");
    return 0;
}

int WebSocketServer::Send(const char *data, int length, const SocketConnection &connection)
{
    if (serverContext_->GetContext() == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return -1;
    }
    if (!CommonUtils::HasInternetPermission()) {
        serverContext_->SetPermissionDenied(true);
        return -1;
    }
    if (connection.clientIP.empty()) {
        NETSTACK_LOGE("connection is empty");
        return -1;
    }
    std::string clientId = connection.clientIP + ":" + std::to_string(connection.clientPort);
    NETSTACK_LOGI("connection clientid:%{public}s", clientId.c_str());
    auto wsi = serverContext_->GetClientWsi(clientId);
    if (wsi == nullptr) {
        NETSTACK_LOGE("clientId not found:%{public}s", clientId.c_str());
        return WEBSOCKET_ERROR_CODE_CONNECTION_NOT_EXIST;
    }
    auto *clientUserData = reinterpret_cast<UserData *>(lws_wsi_user(wsi));
    if (clientUserData == nullptr) {
        NETSTACK_LOGE("clientUser data is nullptr");
        return -1;
    }
    if (clientUserData->IsClosed() || clientUserData->IsThreadStop()) {
        NETSTACK_LOGE("session is closed or stopped");
        return -1;
    }
    lws_write_protocol protocol = (strlen(data) == static_cast<size_t>(length)) ? LWS_WRITE_TEXT : LWS_WRITE_BINARY;
    size_t dataLen = static_cast<size_t>(LWS_SEND_BUFFER_PRE_PADDING + length + LWS_SEND_BUFFER_POST_PADDING);
    char *tmpData = (char *)malloc(dataLen);
    if (tmpData == nullptr) {
        NETSTACK_LOGE("malloc failed");
        return -1;
    }
    if (memcpy_s(reinterpret_cast<void *>(reinterpret_cast<uint8_t *>(tmpData) + LWS_SEND_BUFFER_PRE_PADDING), length,
        data, length) < 0) {
        NETSTACK_LOGE("copy failed");
        free(tmpData);
        return -1;
    }
    clientUserData->Push((void *)tmpData, length, protocol);
    clientUserData->TriggerWritable();
    NETSTACK_LOGD("lws ts send success");
    return 0;
}

int WebSocketServer::ListAllConnections(std::vector<SocketConnection> &connections) const
{
    NETSTACK_LOGD("websocket server list all connections exec");
    if (serverContext_->GetContext() == nullptr) {
        NETSTACK_LOGE("websocket server context is null");
        return -1;
    }
    if (!CommonUtils::HasInternetPermission()) {
        serverContext_->SetPermissionDenied(true);
        NETSTACK_LOGE("ListAllConnections: Permission denied");
        return WEBSOCKET_ERROR_PERMISSION_DENIED;
    }
    serverContext_->ListAllConnections(connections);
    return 0;
}

int WebSocketServer::Registcallback(OnErrorCallback onError, OnConnectCallback onConnect, OnCloseCallback onClose,
    OnMessageReceiveCallback onMessageReceive)
{
    onErrorCallback_ = onError;
    onConnectCallback_ = onConnect;
    onCloseCallback_ = onClose;
    onMessageReceiveCallback_ = onMessageReceive;
    return 0;
}

ServerContext *WebSocketServer::GetServerContext() const
{
    return serverContext_;
}

int WebSocketServer::Destroy()
{
    NETSTACK_LOGI("websocket server destroy exec");
    if (this->GetServerContext()->GetContext() == nullptr) {
        return -1;
    }
    lws_context_destroy(this->GetServerContext()->GetContext());
    this->GetServerContext()->SetContext(nullptr);
    return 0;
}
}