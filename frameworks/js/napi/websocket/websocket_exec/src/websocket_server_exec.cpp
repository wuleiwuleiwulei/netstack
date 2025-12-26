/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "websocket_server_exec.h"
#include <atomic>
#include <memory>
#include <queue>
#include <thread>
#include <unistd.h>
#include <sstream>
#include <algorithm>
#include <shared_mutex>
#include "constant.h"
#include "napi_utils.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "securec.h"
#define LWS_PLUGIN_STATIC

static constexpr const char *EVENT_KEY_CLIENT_PORT = "clientPort";

static constexpr const char *EVENT_KEY_CLIENT_IP = "clientIP";

static constexpr const char *EVENT_KEY_CONNECTION = "clientConnection";

static constexpr const char *EVENT_KEY_DATA = "data";

static constexpr const char *EVENT_KEY_CODE = "code";

static constexpr const char *EVENT_KEY_REASON = "closeReason";

static constexpr const char *WEBSOCKET_SERVER_THREAD_RUN = "OS_NET_WSJsSer";

static constexpr const char *LINK_DOWN = "The link is down";

static constexpr const uint32_t MAX_CONCURRENT_CLIENTS_NUMBER = 10;

static constexpr const uint32_t MAX_CONNECTIONS_FOR_ONE_CLIENT = 10;

static constexpr const uint64_t ONE_MINUTE_IN_SEC = 60;

static constexpr const int32_t MAX_CONNECTIONS_PER_MINUTE = 50;

static constexpr const int32_t COMMON_ERROR_CODE = 200;

static constexpr const int32_t ARRAY_LEN_TWO = 2;
namespace OHOS::NetStack::Websocket {

static std::shared_mutex wsMutex_;

static std::shared_mutex connListMutex_;

static std::shared_mutex banListMutex_;

static std::unordered_map<std::string, uint64_t> banList;

static std::unordered_map<std::string, ClientInfo> clientList;

static const lws_protocols LWS_SERVER_PROTOCOLS[] = {
    {"lws_server", WebSocketServerExec::lwsServerCallback, 0, 0},
    {NULL, NULL, 0, 0}, // this line is needed
};

struct CloseResult {
    uint32_t code;
    std::string reason;
};

struct ClientConnectionCloseCallback {
    WebSocketConnection connection;
    CloseResult closeResult;
};

struct CallbackDispatcher {
    lws_callback_reasons reason;
    int (*callback)(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);
};

using WebSocketConnMap = std::map<
    std::string,
    std::pair<lws*, OHOS::NetStack::Websocket::WebSocketConnection>
>;

static const lws_http_mount mount = {
    NULL,
    "/",
    "./mount-origin",
    "index.html",
    NULL,
    NULL,
    NULL,
    NULL,
    0,
    0,
    0,
    0,
    0,
    0,
    LWSMPRO_FILE,
    1,
    NULL,
};

template <napi_value (*MakeJsValue)(napi_env, void *)> static void CallbackTemplate(uv_work_t *work, int status)
{
    (void)status;

    auto workWrapper = static_cast<UvWorkWrapperShared *>(work->data);
    napi_env env = workWrapper->env;
    auto closeScope = [env](napi_handle_scope scope) { NapiUtils::CloseScope(env, scope); };
    std::unique_ptr<napi_handle_scope__, decltype(closeScope)> scope(NapiUtils::OpenScope(env), closeScope);

    napi_value obj = MakeJsValue(env, workWrapper->data);
    auto undefined = NapiUtils::GetUndefined(workWrapper->env);
    std::pair<napi_value, napi_value> arg = {undefined, obj};
    if (workWrapper->manager) {
        workWrapper->manager->Emit(workWrapper->type, arg);
        if (workWrapper->type == EventName::EVENT_MESSAGE &&
            workWrapper->manager->HasEventListener(EventName::EVENT_DATA_END)) {
            workWrapper->manager->Emit(EventName::EVENT_DATA_END, {undefined, undefined});
        }
    }
    delete workWrapper;
    delete work;
}

template <napi_value (*MakeJsValue)(napi_env, void *)> static void CallbackTemplateWithTwoPara(uv_work_t *work,
    int status)
{
    (void)status;

    auto workWrapper = static_cast<UvWorkWrapperShared *>(work->data);
    napi_env env = workWrapper->env;
    auto closeScope = [env](napi_handle_scope scope) { NapiUtils::CloseScope(env, scope); };
    std::unique_ptr<napi_handle_scope__, decltype(closeScope)> scope(NapiUtils::OpenScope(env), closeScope);

    napi_value obj = MakeJsValue(env, workWrapper->data);
    auto undefined = NapiUtils::GetUndefined(workWrapper->env);
    if (NapiUtils::GetArrayLength(env, obj) != ARRAY_LEN_TWO) {
        NETSTACK_LOGE("array length is not 2");
        delete workWrapper;
        delete work;
        return;
    }

    napi_value firstValue = NapiUtils::GetArrayElement(env, obj, 0);
    napi_value secValue = NapiUtils::GetArrayElement(env, obj, 1);
    std::tuple<napi_value, napi_value, napi_value> arg = {undefined, firstValue, secValue};

    if (workWrapper->manager) {
        workWrapper->manager->EmitWithTwoPara(workWrapper->type, arg);
    }
    delete workWrapper;
    delete work;
}

void RunServerService(std::shared_ptr<UserData> userData, std::shared_ptr<EventManager> manager)
{
    NETSTACK_LOGI("websocket run service start");
    int res = 0;
    lws_context *context = userData->GetContext();
    if (context == nullptr) {
        NETSTACK_LOGE("context is null");
        return;
    }
    while (res >= 0 && !userData->IsThreadStop()) {
        res = lws_service(context, 0);
    }
    NETSTACK_LOGE("lws_service stop");
    lws_context_destroy(context);
    userData->SetContext(nullptr);
    manager->SetWebSocketUserData(nullptr);
    std::unique_lock<std::shared_mutex> lock_set(manager->GetDataMutex());
    auto realMap = reinterpret_cast<WebSocketConnMap*>(manager->GetData());
    if (realMap == nullptr) {
        return;
    }
    delete realMap;
    manager->SetData(static_cast<void*>(nullptr));
    NETSTACK_LOGI("websocket run service end");
}

int WebSocketServerExec::RaiseServerError(EventManager *manager)
{
    OnServerError(manager, COMMON_ERROR_CODE);
    return -1;
}

int WebSocketServerExec::HttpDummy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    int ret = lws_callback_http_dummy(wsi, reason, user, in, len);
    if (ret < 0) {
        OnServerError(reinterpret_cast<EventManager *>(user), COMMON_ERROR_CODE);
    }
    return 0;
}

int WebSocketServerExec::lwsServerCallback(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
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

int WebSocketServerExec::LwsCallbackEstablished(lws *wsi, lws_callback_reasons reason, void *user, void *in,
    size_t len)
{
    NETSTACK_LOGD("lws callback server established");
    lws_context *context = lws_get_context(wsi);
    EventManager *manager = static_cast<EventManager *>(lws_context_user(context));
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is null");
        return RaiseServerError(manager);
    }
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseServerError(manager);
    }
    // bind clientuserdata with wsi
    lws_context *lwsContext = lws_get_context(wsi);
    auto clientUserData = std::make_shared<UserData>(lwsContext);
    lws_set_wsi_user(wsi, clientUserData.get());
    manager->AddClientUserData(wsi, clientUserData);

    std::string clientId;
    WebSocketConnection connection;
    bool ret = GetPeerConnMsg(wsi, manager, clientId, connection);
    if (!ret) {
        NETSTACK_LOGE("GetPeerConnMsg failed");
        return RaiseServerError(manager);
    }
    AddConnections(clientId, wsi, userData, connection, manager);
    clientUserData->SetLws(wsi);
    clientUserData->TriggerWritable();
    OnConnect(wsi, manager);
    return HttpDummy(wsi, reason, user, in, len);
}

bool WebSocketServerExec::GetPeerConnMsg(lws *wsi, EventManager *manager, std::string &clientId,
    WebSocketConnection &conn)
{
    struct sockaddr_storage addr{};
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

bool WebSocketServerExec::IsOverMaxClientConns(EventManager *manager, const std::string ip)
{
    std::vector<WebSocketConnection> connections = GetConnections(manager);
    if (IsOverMaxConcurrentClientsCnt(manager, connections, ip)) {
        NETSTACK_LOGI("current client connections is over max concurrent number");
        return true;
    }
    if (IsOverMaxCntForOneClient(manager, connections, ip)) {
        NETSTACK_LOGI("current connections for one client is over max number");
        return true;
    }
    return false;
}

void WebSocketServerExec::AddConnections(const std::string &id, lws *wsi,
    std::shared_ptr<UserData> &userData, WebSocketConnection &conn, EventManager *manager)
{
    if (userData->IsClosed() || userData->IsThreadStop()) {
        NETSTACK_LOGE("AddConnections failed: session %s", userData->IsClosed() ? "closed" : "thread stopped");
        return;
    }
    {
        std::shared_lock<std::shared_mutex> lock_get(manager->GetDataMutex());
        auto realMap = reinterpret_cast<WebSocketConnMap*>(manager->GetData());
        if (realMap == nullptr) {
            return;
        }
        auto& webSocketConnection_ = *realMap;
        std::unique_lock<std::shared_mutex> lock(wsMutex_);
        webSocketConnection_[id].first = wsi;
        webSocketConnection_[id].second = conn;
        NETSTACK_LOGI("AddConnections success");
    }
}

bool WebSocketServerExec::IsOverMaxConcurrentClientsCnt(EventManager *manager,
    const std::vector<WebSocketConnection> connections, const std::string ip)
{
    std::unordered_set<std::string> uniqueIp;
    for (const auto &conn : connections) {
        uniqueIp.insert(conn.clientIP);
    }
    if (uniqueIp.find(ip) != uniqueIp.end()) {
        return uniqueIp.size() > manager->GetMaxConcurrentClientCnt();
    } else {
        return (uniqueIp.size() + 1) > manager->GetMaxConcurrentClientCnt();
    }
}

bool WebSocketServerExec::IsOverMaxCntForOneClient(EventManager *manager,
    const std::vector<WebSocketConnection> connections, const std::string ip)
{
    uint32_t cnt = 0;
    for (auto it = connections.begin(); it != connections.end(); ++it) {
        if (ip == it->clientIP) {
            ++cnt;
        }
    }
    if (cnt + 1 > manager->GetMaxConnForOneClient()) {
        return true;
    }
    return false;
}

void WebSocketServerExec::ClearWebSocketConnection(WebSocketConnMap &webSocketConnection_,
                                                   lws *wsi, std::string &clientId)
{
    std::shared_lock<std::shared_mutex> lock(wsMutex_);
    for (auto it = webSocketConnection_.begin(); it != webSocketConnection_.end(); ++it) {
        if (it->second.first == wsi) {
            clientId = it->first;
        }
    }
    return;
}

int WebSocketServerExec::LwsCallbackClosed(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback server closed");
    if (wsi == nullptr) {
        NETSTACK_LOGE("wsi is null");
        return -1;
    }
    lws_context *context = lws_get_context(wsi);
    EventManager *manager = static_cast<EventManager *>(lws_context_user(context));
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is null");
        return RaiseServerError(manager);
    }
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseServerError(manager);
    }
    auto clientUserData = reinterpret_cast<UserData *>(lws_wsi_user(wsi));
    if (clientUserData == nullptr) {
        NETSTACK_LOGE("clientUserData is null");
        return RaiseServerError(manager);
    }
    clientUserData->SetThreadStop(true);
    if ((clientUserData->closeReason).empty()) {
        clientUserData->Close(clientUserData->closeStatus, LINK_DOWN);
    }
    if (clientUserData->closeStatus == LWS_CLOSE_STATUS_NOSTATUS) {
        NETSTACK_LOGE("The link is down, onError");
        OnServerError(manager, COMMON_ERROR_CODE);
    }
    std::string clientId;
    {
        std::shared_lock<std::shared_mutex> lock_get(manager->GetDataMutex());
        auto realMap = reinterpret_cast<WebSocketConnMap*>(manager->GetData());
        if (realMap == nullptr) {
            return -1;
        }
        auto& webSocketConnection_ = *realMap;
        ClearWebSocketConnection(webSocketConnection_, wsi, clientId);
    }
    OnServerClose(wsi, manager, clientUserData->closeStatus, clientUserData->closeReason);
    RemoveConnections(clientId, *clientUserData, manager);
    manager->RemoveClientUserData(wsi);
    lws_set_wsi_user(wsi, nullptr);

    if (userData->IsClosed() && !userData->IsThreadStop()) {
        NETSTACK_LOGI("server service is stopped");
        userData->SetThreadStop(true);
    }
    return HttpDummy(wsi, reason, user, in, len);
}

void WebSocketServerExec::RemoveConnections(const std::string &id, UserData &userData, EventManager *manager)
{
    std::shared_lock<std::shared_mutex> lock_get(manager->GetDataMutex());
    auto realMap = reinterpret_cast<WebSocketConnMap*>(manager->GetData());
    if (realMap == nullptr) {
        return;
    }
    auto& webSocketConnection_ = *realMap;
    if (webSocketConnection_.empty()) {
        NETSTACK_LOGE("connection list is empty");
        return;
    }
    {
        std::unique_lock<std::shared_mutex> lock(wsMutex_);
        if (webSocketConnection_.find(id) == webSocketConnection_.end()) {
            NETSTACK_LOGE("connection list find clientId failed");
            return;
        }
        webSocketConnection_.erase(id);
        NETSTACK_LOGI("connection erase success");
    }
}

int WebSocketServerExec::LwsCallbackWsiDestroyServer(lws *wsi, lws_callback_reasons reason, void *user, void *in,
    size_t len)
{
    NETSTACK_LOGD("lws server callback wsi destroy");
    if (wsi == nullptr) {
        NETSTACK_LOGE("wsi is null");
        return -1;
    }
    lws_context *context = lws_get_context(wsi);
    EventManager *manager = static_cast<EventManager *>(lws_context_user(context));
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is null");
        return RaiseServerError(manager);
    }
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseServerError(manager);
    }
    userData->SetLws(nullptr);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketServerExec::LwsCallbackProtocolDestroyServer(lws *wsi, lws_callback_reasons reason, void *user, void *in,
    size_t len)
{
    NETSTACK_LOGD("lws server callback protocol destroy");
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketServerExec::LwsCallbackServerWriteable(lws *wsi, lws_callback_reasons reason, void *user, void *in,
    size_t len)
{
    NETSTACK_LOGD("lws callback Server writable");
    lws_context *context = lws_get_context(wsi);
    EventManager *manager = static_cast<EventManager *>(lws_context_user(context));
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return RaiseServerError(manager);
    }
    // server
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseServerError(manager);
    }
    if (userData->IsThreadStop()) {
        NETSTACK_LOGI("session is stopped");
        return -1;
    }
    // client
    auto *clientUserData = reinterpret_cast<UserData *>(lws_wsi_user(wsi));
    if (clientUserData == nullptr) {
        NETSTACK_LOGE("clientUserData is null");
        return RaiseServerError(manager);
    }
    if (clientUserData->IsClosed()) {
        NETSTACK_LOGI("client is closed, need to close");
        lws_close_reason(wsi, clientUserData->closeStatus,
            reinterpret_cast<unsigned char *>(const_cast<char *>(clientUserData->closeReason.c_str())),
            strlen(clientUserData->closeReason.c_str()));
        return -1;
    }
    auto sendData = clientUserData->Pop();
    if (sendData.data == nullptr) {
        NETSTACK_LOGE("send data is empty");
        return HttpDummy(wsi, reason, user, in, len);
    }
    int sendLength = lws_write(wsi, reinterpret_cast<unsigned char *>(sendData.data) + LWS_SEND_BUFFER_PRE_PADDING,
        sendData.length, sendData.protocol);
    free(sendData.data);
    NETSTACK_LOGD("lws send data length is %{public}d", sendLength);
    if (!clientUserData->IsEmpty()) {
        NETSTACK_LOGE("userData is not empty");
        userData->TriggerWritable();
    }
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketServerExec::LwsCallbackWsPeerInitiatedCloseServer(lws *wsi, lws_callback_reasons reason,
    void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws server callback ws peer initiated close");
    if (wsi == nullptr) {
        NETSTACK_LOGE("wsi is null");
        return -1;
    }
    lws_context *context = lws_get_context(wsi);
    EventManager *manager = static_cast<EventManager *>(lws_context_user(context));
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseServerError(manager);
    }
    if (in == nullptr || len < sizeof(uint16_t)) {
        NETSTACK_LOGI("No close reason");
        userData->Close(LWS_CLOSE_STATUS_NORMAL, "");
        return HttpDummy(wsi, reason, user, in, len);
    }
    uint16_t closeStatus = ntohs(*reinterpret_cast<uint16_t *>(in));
    std::string closeReason;
    closeReason.append(reinterpret_cast<char *>(in) + sizeof(uint16_t), len - sizeof(uint16_t));
    auto *clientUserData = reinterpret_cast<UserData *>(lws_wsi_user(wsi));
    clientUserData->Close(static_cast<lws_close_status>(closeStatus), closeReason);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketServerExec::LwsCallbackFilterProtocolConnection(lws *wsi, lws_callback_reasons reason,
    void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws server callback filter ProtocolConnection");
    lws_context *context = lws_get_context(wsi);
    EventManager *manager = static_cast<EventManager *>(lws_context_user(context));
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is null");
        return RaiseServerError(manager);
    }
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseServerError(manager);
    }
    if (userData->IsClosed() || userData->IsThreadStop()) {
        NETSTACK_LOGE("session is closed or thread is stopped");
        return RaiseServerError(manager);
    }
    std::string clientId;
    WebSocketConnection connection;
    bool ret = GetPeerConnMsg(wsi, manager, clientId, connection);
    if (!ret) {
        NETSTACK_LOGE("GetPeerConnMsg failed");
        return RaiseServerError(manager);
    }
    /* 是否超过最大连接数 */
    if (IsOverMaxClientConns(manager, connection.clientIP)) {
        NETSTACK_LOGE("current connections count is more than limit, need to close");
        return RaiseServerError(manager);
    }
    /* 添加防止恶意连接的业务逻辑 */
    if (!IsAllowConnection(connection.clientIP)) {
        NETSTACK_LOGE("Rejected malicious connection");
        return RaiseServerError(manager);
    }
    return HttpDummy(wsi, reason, user, in, len);
}

bool WebSocketServerExec::IsAllowConnection(const std::string &ip)
{
    if (IsIpInBanList(ip)) {
        NETSTACK_LOGE("client is in banlist");
        return false;
    }
    if (IsHighFreqConnection(ip)) {
        NETSTACK_LOGE("client reach high frequency connection");
        AddBanList(ip);
        return false;
    }
    UpdataClientList(ip);
    return true;
}

void WebSocketServerExec::UpdataClientList(const std::string &ip)
{
    std::shared_lock<std::shared_mutex> lock(connListMutex_);
    auto it = clientList.find(ip);
    if (it == clientList.end()) {
        NETSTACK_LOGI("add clientid to clientlist");
        clientList[ip] = {1, GetCurrentSecond()};
    } else {
        auto now = GetCurrentSecond() - it->second.lastConnectionTime;
        if (now > ONE_MINUTE_IN_SEC) {
            NETSTACK_LOGI("reset clientid connections cnt");
            it->second = {1, GetCurrentSecond()};
        } else {
            it->second.cnt++;
        }
    }
}

void WebSocketServerExec::AddBanList(const std::string &ip)
{
    std::shared_lock<std::shared_mutex> lock(banListMutex_);
    banList[ip] = GetCurrentSecond() + ONE_MINUTE_IN_SEC;
}

bool WebSocketServerExec::IsIpInBanList(const std::string &ip)
{
    std::shared_lock<std::shared_mutex> lock(banListMutex_);
    auto it = banList.find(ip);
    if (it != banList.end()) {
        auto now = GetCurrentSecond();
        if (now < it->second) {
            return true;
        } else {
            banList.erase(it);
        }
    }
    return false;
}

uint64_t WebSocketServerExec::GetCurrentSecond()
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool WebSocketServerExec::IsHighFreqConnection(const std::string &ip)
{
    std::shared_lock<std::shared_mutex> lock(connListMutex_);
    auto it = clientList.find(ip);
    if (it != clientList.end()) {
        auto duration = GetCurrentSecond() - it->second.lastConnectionTime;
        if (duration <= ONE_MINUTE_IN_SEC) {
            return it->second.cnt > MAX_CONNECTIONS_PER_MINUTE;
        }
    }
    return false;
}

int WebSocketServerExec::LwsCallbackReceive(lws *wsi, lws_callback_reasons reason, void *user, void *in,
    size_t len)
{
    NETSTACK_LOGD("lws callback server receive");
    lws_context *context = lws_get_context(wsi);
    EventManager *manager = static_cast<EventManager *>(lws_context_user(context));
    auto isFinal = lws_is_final_fragment(wsi);
    OnServerMessage(wsi, manager, in, len, lws_frame_is_binary(wsi), isFinal);
    return HttpDummy(wsi, reason, user, in, len);
}

static napi_value CreateServerClosePara(napi_env env, void *callbackPara)
{
    auto para = reinterpret_cast<ClientConnectionCloseCallback *>(callbackPara);
    auto deleter = [](const ClientConnectionCloseCallback *p) { delete p; };
    std::unique_ptr<ClientConnectionCloseCallback, decltype(deleter)> handler(para, deleter);
    napi_value obj = NapiUtils::CreateArray(env, ARRAY_LEN_TWO);
    if (NapiUtils::GetValueType(env, obj) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    napi_value jsConn = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, jsConn) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetStringPropertyUtf8(env, jsConn, EVENT_KEY_CLIENT_IP, para->connection.clientIP);
    NapiUtils::SetUint32Property(env, jsConn, EVENT_KEY_CLIENT_PORT, para->connection.clientPort);
    NapiUtils::SetArrayElement(env, obj, 0, jsConn);
    napi_value jsRes = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, jsRes) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetUint32Property(env, jsRes, EVENT_KEY_CODE, para->closeResult.code);
    NapiUtils::SetStringPropertyUtf8(env, jsRes, EVENT_KEY_REASON, para->closeResult.reason);
    NapiUtils::SetArrayElement(env, obj, 1, jsRes);
    return obj;
}

static napi_value ConvertWsBinaryMessageToJs(napi_env env, const WebSocketMessage *msg)
{
    napi_value jsMsg = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, jsMsg) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    void *data = nullptr;
    napi_value arrayBuffer = NapiUtils::CreateArrayBuffer(env, msg->data.size(), &data);
    if (!NapiUtils::ValueIsArrayBuffer(env, arrayBuffer)) {
        return NapiUtils::GetUndefined(env);
    }
    if (msg->data.size() > 0) {
        if (data == nullptr) {
            return NapiUtils::GetUndefined(env);
        }
        if (memcpy_s(data, msg->data.size(), msg->data.c_str(), msg->data.size()) != EOK) {
            return NapiUtils::GetUndefined(env);
        }
    }
    NapiUtils::SetNamedProperty(env, jsMsg, "data", arrayBuffer);
    napi_value jsConn = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, jsConn) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetStringPropertyUtf8(env, jsConn, EVENT_KEY_CLIENT_IP, msg->connection.clientIP);
    NapiUtils::SetUint32Property(env, jsConn, EVENT_KEY_CLIENT_PORT, msg->connection.clientPort);
    NapiUtils::SetNamedProperty(env, jsMsg, EVENT_KEY_CONNECTION, jsConn);
    return jsMsg;
}

static napi_value CreateServerBinaryMessagePara(napi_env env, void *callbackPara)
{
    auto pair = reinterpret_cast<std::pair<lws *, EventManager *> *>(callbackPara);
    if (pair == nullptr) {
        NETSTACK_LOGE("pair is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    lws *wsi = pair->first;
    if (wsi == nullptr) {
        NETSTACK_LOGE("wsi is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    auto &manager = pair->second;
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is nullptr");
        return NapiUtils::CreateStringUtf8(env, "");
    }
    auto msg = reinterpret_cast<WebSocketMessage *>(manager->GetServerQueueData(wsi));
    if (!msg) {
        NETSTACK_LOGE("msg is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    napi_value jsMsg = ConvertWsBinaryMessageToJs(env, msg);
    if (NapiUtils::GetValueType(env, jsMsg) != napi_object) {
        delete msg;
        return NapiUtils::GetUndefined(env);
    }
    delete msg;
    return jsMsg;
}

static napi_value ConvertWsTextMessageToJs(napi_env env, const WebSocketMessage *msg)
{
    napi_value jsMsg = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, jsMsg) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetStringPropertyUtf8(env, jsMsg, EVENT_KEY_DATA, msg->data);
    napi_value jsConn = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, jsConn) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetStringPropertyUtf8(env, jsConn, EVENT_KEY_CLIENT_IP, msg->connection.clientIP);
    NapiUtils::SetUint32Property(env, jsConn, EVENT_KEY_CLIENT_PORT, msg->connection.clientPort);
    NapiUtils::SetNamedProperty(env, jsMsg, EVENT_KEY_CONNECTION, jsConn);
    return jsMsg;
}

static napi_value CreateServerTextMessagePara(napi_env env, void *callbackPara)
{
    auto pair = reinterpret_cast<std::pair<lws *, EventManager *> *>(callbackPara);
    if (pair == nullptr) {
        NETSTACK_LOGE("pair is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    lws *wsi = pair->first;
    if (wsi == nullptr) {
        NETSTACK_LOGE("wsi is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    auto &manager = pair->second;
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is nullptr");
        return NapiUtils::CreateStringUtf8(env, "");
    }
    auto msg = reinterpret_cast<WebSocketMessage *>(manager->GetServerQueueData(wsi));
    if (!msg) {
        NETSTACK_LOGE("msg is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    napi_value jsMsg = ConvertWsTextMessageToJs(env, msg);
    if (NapiUtils::GetValueType(env, jsMsg) != napi_object) {
        NETSTACK_LOGE("jsMsg is not object");
        delete msg;
        return NapiUtils::GetUndefined(env);
    }
    delete msg;
    return jsMsg;
}

static napi_value CreateConnectPara(napi_env env, void *callbackPara)
{
    auto para = reinterpret_cast<WebSocketConnection *>(callbackPara);
    auto deleter = [](const WebSocketConnection *p) { delete p; };
    std::unique_ptr<WebSocketConnection, decltype(deleter)> handler(para, deleter);
    napi_value obj = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, obj) != napi_object) {
        NETSTACK_LOGE("napi_object not found");
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetUint32Property(env, obj, EVENT_KEY_CLIENT_PORT, para->clientPort);
    NapiUtils::SetStringPropertyUtf8(env, obj, EVENT_KEY_CLIENT_IP, para->clientIP);
    return obj;
}

static napi_value CreateServerError(napi_env env, void *callbackPara)
{
    auto code = reinterpret_cast<int32_t *>(callbackPara);
    auto deleter = [](int32_t *p) { delete p; };
    std::unique_ptr<int32_t, decltype(deleter)> handler(code, deleter);
    napi_value err = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, err) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetInt32Property(env, err, EVENT_KEY_CODE, *code);
    return err;
}
   
void WebSocketServerExec::OnServerError(EventManager *manager, int32_t code)
{
    NETSTACK_LOGI("OnServerError %{public}d", code);
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    bool hasServerEventListener = manager->HasEventListener(EventName::EVENT_SERVER_ERROR);
    if (!hasServerEventListener) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_SERVER_ERROR);
        return;
    }
    auto para = new int32_t(code);
    manager->EmitByUvWithoutCheckShared(EventName::EVENT_SERVER_ERROR, para, CallbackTemplate<CreateServerError>);
}

void WebSocketServerExec::OnConnect(lws *wsi, EventManager *manager)
{
    NETSTACK_LOGI("OnConnect enter");
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    bool hasServerConnectListener = manager->HasEventListener(EventName::EVENT_SERVER_CONNECT);
    if (!hasServerConnectListener) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_SERVER_CONNECT);
        return;
    }
    {
        std::shared_lock<std::shared_mutex> lock_get(manager->GetDataMutex());
        auto realMap = reinterpret_cast<WebSocketConnMap*>(manager->GetData());
        if (realMap == nullptr) {
            return;
        }
        auto& webSocketConnection_ = *realMap;
        std::shared_lock<std::shared_mutex> lock(wsMutex_);
        for (auto [id, connPair] : webSocketConnection_) {
            if (connPair.first == wsi) {
                auto para = new WebSocketConnection;
                para->clientIP = connPair.second.clientIP;
                para->clientPort = connPair.second.clientPort;
                NETSTACK_LOGI("connection find ok, clientId:%{public}s", id.c_str());
                manager->EmitByUvWithoutCheckShared(EventName::EVENT_SERVER_CONNECT,
                    para, CallbackTemplate<CreateConnectPara>);
                return;
            }
        }
    }
    NETSTACK_LOGE("not found client msg");
}

void WebSocketServerExec::OnServerClose(lws *wsi, EventManager *manager, lws_close_status closeStatus,
    const std::string &closeReason)
{
    NETSTACK_LOGI("OnServerClose %{public}u %{public}s", closeStatus, closeReason.c_str());
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    if (wsi == nullptr) {
        NETSTACK_LOGE("wsi is nullptr");
        return;
    }
    bool hasServerCloseListener = manager->HasEventListener(EventName::EVENT_SERVER_CLOSE);
    if (!hasServerCloseListener) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_SERVER_CLOSE);
        return;
    }
    {
        std::shared_lock<std::shared_mutex> lock_get(manager->GetDataMutex());
        std::shared_lock<std::shared_mutex> lock(wsMutex_);
        auto realMap = reinterpret_cast<WebSocketConnMap*>(manager->GetData());
        if (realMap == nullptr) {
            return;
        }
        auto& webSocketConnection_ = *realMap;
        for (auto [id, connPair] : webSocketConnection_) {
            if (connPair.first == wsi) {
                auto conn = new ClientConnectionCloseCallback;
                if (conn == nullptr) {
                    return;
                }
                conn->closeResult.code = closeStatus;
                conn->closeResult.reason = closeReason;
                conn->connection = connPair.second;
                NETSTACK_LOGI("clientId: %{public}s", id.c_str());
                manager->EmitByUvWithoutCheckShared(EventName::EVENT_SERVER_CLOSE,
                    conn, CallbackTemplateWithTwoPara<CreateServerClosePara>);
                return;
            }
        }
    }
    NETSTACK_LOGE("not found client msg");
}

void WebSocketServerExec::OnServerMessage(lws *wsi, EventManager *manager, void *data,
    size_t length, bool isBinary, bool isFinal)
{
    NETSTACK_LOGD("server OnMessage %{public}d", isBinary);
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    bool hasServerEventListener = manager->HasEventListener(EventName::EVENT_SERVER_MESSAGE_RECEIVE);
    if (!hasServerEventListener) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_SERVER_MESSAGE_RECEIVE);
        return;
    }
    if (length > INT32_MAX) {
        NETSTACK_LOGE("data length too long");
        return;
    }
    HandleServerRcvMessage(wsi, manager, data, length, isBinary, isFinal);
}

void WebSocketServerExec::HandleServerRcvMessage(lws *wsi, EventManager *manager, void *data,
    size_t length, bool isBinary, bool isFinal)
{
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return;
    }
    if (isBinary) {
        manager->AppendWsServerBinaryData(wsi, data, length);
        if (isFinal) {
            const std::string &msgFromManager = manager->GetWsServerBinaryData(wsi);
            auto msg = new WebSocketMessage;
            if (msg == nullptr) {
                return;
            }
            SetWebsocketMessage(wsi, manager, msgFromManager, msg);
            manager->SetServerQueueData(wsi, msg);
            auto callbackPara = new std::pair<lws *, EventManager *>(wsi, manager);
            manager->EmitByUvWithoutCheckShared(EventName::EVENT_SERVER_MESSAGE_RECEIVE, callbackPara,
                CallbackTemplate<CreateServerBinaryMessagePara>);
            manager->ClearWsServerBinaryData(wsi);
        }
    } else {
        manager->AppendWsServerTextData(wsi, data, length);
        if (isFinal) {
            const std::string &msgFromManager = manager->GetWsServerTextData(wsi);
            auto msg = new WebSocketMessage;
            if (msg == nullptr) {
                return;
            }
            SetWebsocketMessage(wsi, manager, msgFromManager, msg);
            manager->SetServerQueueData(wsi, msg);
            auto callbackPara = new std::pair<lws *, EventManager *>(wsi, manager);
            manager->EmitByUvWithoutCheckShared(EventName::EVENT_SERVER_MESSAGE_RECEIVE, callbackPara,
                CallbackTemplate<CreateServerTextMessagePara>);
            manager->ClearWsServerTextData(wsi);
        }
    }
}

void WebSocketServerExec::SetWebsocketMessage(lws *wsi, EventManager *manager,
    const std::string &msgFromManager, void *dataMsg)
{
    NETSTACK_LOGD("SetWebsocketMessage enter");
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    if (wsi == nullptr) {
        NETSTACK_LOGE("wsi is nullptr");
        return;
    }
    auto webSocketMessage = static_cast<WebSocketMessage *>(dataMsg);
    webSocketMessage->data = msgFromManager;

    {
        std::shared_lock<std::shared_mutex> lock_get(manager->GetDataMutex());
        auto realMap = reinterpret_cast<WebSocketConnMap*>(manager->GetData());
        if (realMap == nullptr) {
            return;
        }
        auto& webSocketConnection_ = *realMap;
        std::shared_lock<std::shared_mutex> lock(wsMutex_);
        if (webSocketConnection_.empty()) {
            NETSTACK_LOGE("webSocketConnection_ is empty");
            return;
        }
        for (auto [_, connPair] : webSocketConnection_) {
            if (connPair.first == wsi) {
                webSocketMessage->connection = connPair.second;
                return;
            }
        }
    }
    NETSTACK_LOGE("not found client msgFromManager");
}

bool WebSocketServerExec::ExecServerStart(ServerStartContext *context)
{
    NETSTACK_LOGD("websocket server start exec");
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    if (!CommonUtils::IsValidIPV4(context->GetServerIP()) &&
        !CommonUtils::IsValidIPV6(context->GetServerIP())) {
        NETSTACK_LOGE("IPV4 and IPV6 are not valid");
        context->SetErrorCode(WEBSOCKET_ERROR_CODE_INVALID_NIC);
        return false;
    }
    if (!CommonUtils::IsValidPort(context->GetServerPort())) {
        context->SetErrorCode(WEBSOCKET_ERROR_CODE_INVALID_PORT);
        NETSTACK_LOGE("Port is not valid");
        return false;
    }
    if (context->GetMaxConcurrentClientsNumber() > MAX_CONCURRENT_CLIENTS_NUMBER) {
        NETSTACK_LOGE("max concurrent clients number is set over limit");
        return false;
    }
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        return false;
    }
    manager->SetMaxConnClientCnt(context->GetMaxConcurrentClientsNumber());
    if (context->GetMaxConnectionsForOneClient() > MAX_CONNECTIONS_FOR_ONE_CLIENT) {
        NETSTACK_LOGE("max connection number for one client is set over limit");
        return false;
    }
    manager->SetMaxConnForOneClient(context->GetMaxConnectionsForOneClient());
    lws_context_creation_info info = {};
    FillServerContextInfo(context, manager, info);
    if (!FillServerCertPath(context, info)) {
        NETSTACK_LOGE("FillServerCertPath error");
        return false;
    }
    bool needNewErrorCode_ = context->GetNeedNewErrorCode();
    bool result = StartService(info, manager, needNewErrorCode_);
    if (!result) {
        context->SetErrorCode(WEBSOCKET_ERROR_CODE_PORT_ALREADY_OCCUPIED);
        NETSTACK_LOGE("Websocket port already occupied.");
        return false;
    }
    return true;
}

bool WebSocketServerExec::StartService(lws_context_creation_info &info, std::shared_ptr<EventManager> &manager,
                                       bool &needNewErrorCode_)
{
    lws_context *lwsContext = nullptr;
    std::shared_ptr<UserData> userData;
    lwsContext = lws_create_context(&info);
    if (needNewErrorCode_ && lwsContext == nullptr) {
        return false;
    }
    WebSocketConnMap* connMapPtr = new WebSocketConnMap();
    std::unique_lock<std::shared_mutex> lock_set(manager->GetDataMutex());
    manager->SetData(static_cast<void*>(connMapPtr));
    userData = std::make_shared<UserData>(lwsContext);
    manager->SetWebSocketUserData(userData);
    std::thread serviceThread(RunServerService, userData, manager);
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(WEBSOCKET_SERVER_THREAD_RUN);
#else
    pthread_setname_np(serviceThread.native_handle(), WEBSOCKET_SERVER_THREAD_RUN);
#endif
    serviceThread.detach();
    return true;
}

void WebSocketServerExec::FillServerContextInfo(ServerStartContext *context, std::shared_ptr<EventManager> &manager,
    lws_context_creation_info &info)
{
    info.options = LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;
    info.port = static_cast<int32_t>(context->GetServerPort());
    info.mounts = &mount;
    info.protocols = LWS_SERVER_PROTOCOLS;
    info.vhost_name = "localhost";
    info.user = manager.get();
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

bool WebSocketServerExec::FillServerCertPath(ServerStartContext *context, lws_context_creation_info &info)
{
    if (!context->certPath_.empty()) {
        if (!CheckFilePath(context->certPath_) || !CheckFilePath(context->keyPath_)) {
            NETSTACK_LOGE("client cert not exist");
            context->SetErrorCode(WEBSOCKET_ERROR_CODE_FILE_NOT_EXIST);
            return false;
        }
        info.ssl_cert_filepath = context->certPath_.c_str();
        info.ssl_private_key_filepath = context->keyPath_.c_str();
    }
    return true;
}

bool WebSocketServerExec::ExecListAllConnections(ListAllConnectionsContext *context)
{
    NETSTACK_LOGD("ListAllConnections start exec");
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("context is null");
        return false;
    }
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is nullptr");
        return false;
    }
    if (userData->IsClosed() || userData->IsThreadStop()) {
        NETSTACK_LOGE("session is closed or stopped");
        return false;
    }
    std::vector<WebSocketConnection> connection = GetConnections(manager.get());
    context->SetAllConnections(connection);
    NETSTACK_LOGI("ExecListAllConnections OK");
    return true;
}

std::vector<WebSocketConnection> WebSocketServerExec::GetConnections(EventManager *manager)
{
    std::vector<WebSocketConnection> conn;
    std::shared_lock<std::shared_mutex> lock_get(manager->GetDataMutex());
    std::shared_lock<std::shared_mutex> lock(wsMutex_);
    auto realMap = reinterpret_cast<WebSocketConnMap*>(manager->GetData());
    if (realMap == nullptr) {
        return conn;
    }
    auto& webSocketConnection_ = *realMap;
    if (!webSocketConnection_.empty()) {
        for (auto [_, connPair] : webSocketConnection_) {
            conn.emplace_back(connPair.second);
        }
    }
    return conn;
}

bool WebSocketServerExec::ExecServerClose(ServerCloseContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    if (context->GetSharedManager() == nullptr) {
        NETSTACK_LOGE("context is null");
        return false;
    }
    WebSocketConnection conn = context->GetConnection();
    if (conn.clientIP.empty()) {
        NETSTACK_LOGE("connection is empty");
        return false;
    }
    std::string clientId = conn.clientIP + ":" + std::to_string(conn.clientPort);
    NETSTACK_LOGI("ExecServerClose, clientID:%{public}s", clientId.c_str());
    auto manager = context->GetSharedManager();
    auto wsi = GetClientWsi(clientId, manager);
    if (wsi == nullptr) {
        context->SetErrorCode(WEBSOCKET_ERROR_CODE_CONNECTION_NOT_EXIST);
        NETSTACK_LOGE("clientId not found:%{public}s", clientId.c_str());
        return false;
    }
    auto *clientUserData = reinterpret_cast<UserData *>(lws_wsi_user(wsi));
    if (clientUserData == nullptr) {
        NETSTACK_LOGE("clientUser data is nullptr");
        return false;
    }
    if (clientUserData->IsClosed() || clientUserData->IsThreadStop()) {
        NETSTACK_LOGE("session is closed or stopped");
        return false;
    }
    clientUserData->Close(static_cast<lws_close_status>(context->code), context->reason);
    clientUserData->TriggerWritable();
    NETSTACK_LOGI("ExecServerClose OK");
    return true;
}

bool WebSocketServerExec::ExecServerSend(ServerSendContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    WebSocketConnection conn = context->GetConnection();
    if (conn.clientIP.empty()) {
        NETSTACK_LOGE("connection is empty");
        return false;
    }
    std::string clientId = conn.clientIP + ":" + std::to_string(conn.clientPort);
    NETSTACK_LOGI("connection clientid:%{public}s", clientId.c_str());
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        return false;
    }
    auto wsi = GetClientWsi(clientId, manager);
    if (wsi == nullptr) {
        context->SetErrorCode(WEBSOCKET_ERROR_CODE_CONNECTION_NOT_EXIST);
        NETSTACK_LOGE("clientId not found:%{public}s", clientId.c_str());
        return false;
    }
    auto *clientUserData = reinterpret_cast<UserData *>(lws_wsi_user(wsi));
    if (clientUserData == nullptr) {
        NETSTACK_LOGE("clientUser data is nullptr");
        return false;
    }
    if (clientUserData->IsClosed() || clientUserData->IsThreadStop()) {
        NETSTACK_LOGE("session is closed or stopped");
        return false;
    }
    clientUserData->Push(context->data, context->length, context->protocol);
    clientUserData->TriggerWritable();
    NETSTACK_LOGD("lws ts send success");
    return true;
}

lws *WebSocketServerExec::GetClientWsi(const std::string clientId, std::shared_ptr<EventManager> &manager)
{
    std::shared_lock<std::shared_mutex> lock_get(manager->GetDataMutex());
    std::shared_lock<std::shared_mutex> lock(wsMutex_);
    auto realMap = reinterpret_cast<WebSocketConnMap*>(manager->GetData());
    if (realMap == nullptr) {
        return nullptr;
    }
    auto& webSocketConnection_ = *realMap;
    if (webSocketConnection_.empty()) {
        NETSTACK_LOGE("webSocketConnection is empty");
        return nullptr;
    }
    auto it = webSocketConnection_.find(clientId);
    if (it == webSocketConnection_.end()) {
        NETSTACK_LOGE("can't find clientId");
        return nullptr;
    }
    return it->second.first;
}

bool WebSocketServerExec::ExecServerStop(ServerStopContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("context is null");
        return false;
    }
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is nullptr");
        return false;
    }
    if (userData->IsClosed() || userData->IsThreadStop()) {
        NETSTACK_LOGE("session is closed or stopped");
        return false;
    }
    CloseAllConnection(userData, manager);
    userData->Close(LWS_CLOSE_STATUS_GOINGAWAY, "");
    NETSTACK_LOGI("ExecServerStop OK");
    return true;
}

void WebSocketServerExec::CloseAllConnection(const std::shared_ptr<UserData> &userData,
                                             std::shared_ptr<EventManager> &manager)
{
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is nullptr");
        return;
    }
    std::shared_lock<std::shared_mutex> lock_get(manager->GetDataMutex());
    auto realMap = reinterpret_cast<WebSocketConnMap*>(manager->GetData());
    if (realMap == nullptr) {
        return;
    }
    auto& webSocketConnection_ = *realMap;
    WebSocketConnMap connListTmp;
    {
        std::shared_lock<std::shared_mutex> lock(wsMutex_);
        if (webSocketConnection_.empty()) {
            NETSTACK_LOGE("webSocketConnection is empty");
            if (!userData->IsThreadStop()) {
                NETSTACK_LOGI("server service is stopped");
                userData->SetThreadStop(true);
            }
            return;
        }
        connListTmp = webSocketConnection_;
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

napi_value WebSocketServerExec::ServerStartCallback(ServerStartContext *context)
{
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}

napi_value WebSocketServerExec::ListAllConnectionsCallback(ListAllConnectionsContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("Context is null");
        return nullptr;
    }
    napi_value connectionsArray = NapiUtils::CreateArray(context->GetEnv(), 0);
    const std::vector<WebSocketConnection> connections = context->GetAllConnections();
    if (connections.empty()) {
        NETSTACK_LOGE("connections list is null");
        return connectionsArray;
    }
    uint32_t index = 0;
    for (const auto &conn : connections) {
        napi_value jsConn = NapiUtils::CreateObject(context->GetEnv());
        NapiUtils::SetUint32Property(context->GetEnv(), jsConn, EVENT_KEY_CLIENT_PORT, conn.clientPort);
        NapiUtils::SetStringPropertyUtf8(context->GetEnv(), jsConn, EVENT_KEY_CLIENT_IP, conn.clientIP);
        NapiUtils::SetArrayElement(context->GetEnv(), connectionsArray, index, jsConn);
        ++index;
    }
    return connectionsArray;
}

napi_value WebSocketServerExec::ServerSendCallback(ServerSendContext *context)
{
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}

napi_value WebSocketServerExec::ServerCloseCallback(ServerCloseContext *context)
{
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}

napi_value WebSocketServerExec::ServerStopCallback(ServerStopContext *context)
{
    auto manager = context->GetSharedManager();
    if (manager != nullptr) {
        NETSTACK_LOGD("websocket close, delete js ref");
        manager->DeleteEventReference(context->GetEnv());
    }
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}
}