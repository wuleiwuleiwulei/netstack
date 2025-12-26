/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "net_websocket_exec.h"

#include <atomic>
#include <memory>
#include <queue>
#include <thread>
#include <unistd.h>

#include "libwebsockets.h"
#include "net_websocket_base_context.h"
#include "net_websocket_impl.h"
#include "securec.h"
#include "net_websocket_utils.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"

#ifdef HAS_NETMANAGER_BASE
#include "http_proxy.h"
#include "net_conn_client.h"
#include "network_security_config.h"
#endif

static constexpr const char *PROTOCOL_DELIMITER = "//";
static constexpr const char *NAME_END = ":";
static constexpr const char *STATUS_LINE_SEP = " ";
static constexpr const size_t STATUS_LINE_ELEM_NUM = 2;
static constexpr const char *PREFIX_HTTPS = "https";
static constexpr const char *PREFIX_WSS = "wss";
static constexpr const char *PREFIX_WS = "ws";
static constexpr const int MAX_URI_LENGTH = 1024;
static constexpr const int MAX_HDR_LENGTH = 1024;
static constexpr const int MAX_PROTOCOL_LENGTH = 1024;
static constexpr const int MAX_ADDRESS_LENGTH = 1024;
static constexpr const int FD_LIMIT_PER_THREAD = 1 + 1 + 1;
static constexpr const int COMMON_ERROR_CODE = 200;
static constexpr const char *LINK_DOWN = "The link is down";
static constexpr const int32_t UID_TRANSFORM_DIVISOR = 200000;
static constexpr const char *BASE_PATH = "/data/certificates/user_cacerts/";
static constexpr const char *WEBSOCKET_SYSTEM_PREPARE_CA_PATH = "/etc/security/certificates";
static constexpr const int FUNCTION_PARAM_TWO = 2;
static constexpr const char *WEBSOCKET_CLIENT_THREAD_RUN = "OS_NET_WSJsCli";

static const std::vector<std::string> WS_PREFIX = {PREFIX_WSS, PREFIX_WS};

namespace OHOS::NetStack::NetWebSocket {
static const lws_protocols WEBSOCKET_PROTOCOLS[] = {
    {"lws-minimal-client-cj", NetWebSocketExec::LwsCallback, 0, 0},
    {nullptr, nullptr, 0, 0}, // this line is needed
};

static const lws_retry_bo_t RETRY = {
    .secs_since_valid_ping = 30,    /* force PINGs after secs idle */
    .secs_since_valid_hangup = 60,  /* hangup after secs idle */
    .jitter_percent = 20,
};

struct CallbackDispatcher {
    lws_callback_reasons reason;
    int (*callback)(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);
};


class WebSocketContext {
public:
    struct SendData {
        SendData(void *paraData, size_t paraLength, lws_write_protocol paraProtocol)
            : data(paraData), length(paraLength), protocol(paraProtocol)
        {
        }

        SendData() = delete;

        ~SendData() = default;

        void *data;
        size_t length;
        lws_write_protocol protocol;
    };

    explicit WebSocketContext(lws_context *context)
        : closeStatus(LWS_CLOSE_STATUS_NOSTATUS), openStatus(0), closed_(false), threadStop_(false), context_(context)
    {
    }

    bool IsClosed()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return closed_;
    }

    bool IsThreadStop()
    {
        return threadStop_.load();
    }

    void SetThreadStop(bool threadStop)
    {
        threadStop_.store(threadStop);
    }

    void Close(lws_close_status status, const std::string &reason)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        closeStatus = status;
        closeReason = reason;
        closed_ = true;
    }

    void Push(void *data, size_t length, lws_write_protocol protocol)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        dataQueue_.emplace(data, length, protocol);
    }

    SendData Pop()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (dataQueue_.empty()) {
            return {nullptr, 0, LWS_WRITE_TEXT};
        }
        SendData data = dataQueue_.front();
        dataQueue_.pop();
        return data;
    }

    void SetContext(lws_context *context)
    {
        context_ = context;
    }

    lws_context *GetContext()
    {
        return context_;
    }

    bool IsEmpty()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (dataQueue_.empty()) {
            return true;
        }
        return false;
    }

    void SetLws(lws *wsi)
    {
        std::lock_guard<std::mutex> lock(mutexForLws_);
        if (wsi == nullptr) {
            NETSTACK_LOGD("set wsi nullptr");
        }
        wsi_ = wsi;
    }

    void TriggerWritable()
    {
        std::lock_guard<std::mutex> lock(mutexForLws_);
        if (wsi_ == nullptr) {
            NETSTACK_LOGE("wsi is nullptr, can not trigger");
            return;
        }
        lws_callback_on_writable(wsi_);
    }

    std::map<std::string, std::string> header;

    lws_close_status closeStatus;

    std::string closeReason;

    uint32_t openStatus;

    std::string openMessage;

private:
    volatile bool closed_;

    std::atomic_bool threadStop_;

    std::mutex mutex_;

    std::mutex mutexForLws_;

    lws_context *context_;

    std::queue<SendData> dataQueue_;

    lws *wsi_ = nullptr;
};

static uint8_t* CreateOpenPara(uint32_t status, const std::string &message)
{
    COpenResponse* res = new COpenResponse;
    res->status = status;
    res->message = MallocCString(message);
    return reinterpret_cast<uint8_t*>(res);
}

static uint8_t* CreateClosePara(uint32_t code, const std::string &reason)
{
    CCloseResponse* res = new CCloseResponse;
    res->code = code;
    res->reason = MallocCString(reason);
    return reinterpret_cast<uint8_t*>(res);
}

static uint8_t* CreateMessagePara(CJWebsocketProxy *websocketProxy, bool isBinary)
{
    CMessageResponse* res = new CMessageResponse;
    res->resultType = isBinary ? ARRAY_BUFFER : STRING;
    auto msg = reinterpret_cast<std::string *>(websocketProxy->GetQueueData());
    if (!msg) {
        NETSTACK_LOGE("msg is nullptr");
        delete res;
        return nullptr;
    }
    CArrUI8 body;
    body.head = reinterpret_cast<uint8_t*>(MallocCString(*msg));
    body.size = static_cast<int64_t>(msg->size());
    res->result = body;
    return reinterpret_cast<uint8_t*>(res);
}

static uint8_t* CreateResponseHeader(const std::map<std::string, std::string> &headers)
{
    CReceiveResponse* res = new CReceiveResponse;
    if (headers.empty()) {
        res->headerType = UNDEFINED;
        res->header.head = nullptr;
        res->header.size = 0;
    }
    res->headerType = MAP;
    res->header = Map2CArrString(headers);
    return reinterpret_cast<uint8_t*>(res);
}

static uint8_t* CreateError(int32_t code, uint32_t httpResponse)
{
    CErrorResponse* res = new CErrorResponse;
    res->code = code;
    res->httpResponse = httpResponse;
    return reinterpret_cast<uint8_t*>(res);
}

void OnConnectError(CJWebsocketProxy *websocketProxy, int32_t code, uint32_t httpResponse)
{
    NETSTACK_LOGI("OnConnectError code is %{public}d, httpResponse is %{public}d", code, httpResponse);
    if (websocketProxy == nullptr) {
        NETSTACK_LOGE("websocketProxy is null");
        return;
    }
    if (auto webSocketContext = websocketProxy->GetWebSocketContext(); webSocketContext != nullptr) {
        NETSTACK_LOGI("OnConnectError SetThreadStop");
        webSocketContext->SetThreadStop(true);
    }
    if (websocketProxy->FindCallback(EVENT_OPEN) == std::nullopt) {
        NETSTACK_LOGI("no event listener: ERROR");
        return;
    }
    CWebSocketCallbackData* para = new CWebSocketCallbackData;
    para->code = ERR_OK;
    para->typeId = EVENT_ERROR;
    para->data = CreateError(code, httpResponse);
    para->dataLen = sizeof(CErrorResponse);
    websocketProxy->EmitCallBack(para);
    delete reinterpret_cast<CErrorResponse*>(para->data);
    delete para;
}

bool NetWebSocketExec::CreatConnectInfo(WebSocketConnectContext *context,
                                        lws_context *lwsContext, CJWebsocketProxy *websocketProxy)
{
    lws_client_connect_info connectInfo = {};
    char protocol[MAX_URI_LENGTH] = {0};
    char address[MAX_URI_LENGTH] = {0};
    char path[MAX_URI_LENGTH] = {0};
    char customizedProtocol[MAX_PROTOCOL_LENGTH] = {0};
    int port = 0;

    if (!ParseUrl(context, protocol, MAX_URI_LENGTH, address, MAX_URI_LENGTH, path, MAX_URI_LENGTH, &port)) {
        NETSTACK_LOGE("ParseUrl failed");
        context->SetErrorCode(WEBSOCKET_ERROR_CODE_URL_ERROR);
        return false;
    }
    if (lwsContext == nullptr) {
        NETSTACK_LOGE("no memory");
        return false;
    }
    std::string tempHost = std::string(address) + NAME_END + std::to_string(port);
    std::string tempOrigin = std::string(protocol) + NAME_END + PROTOCOL_DELIMITER + tempHost;
    NETSTACK_LOGD("tempOrigin = %{private}s", tempOrigin.c_str());
    if (strcpy_s(customizedProtocol, context->GetProtocol().length() + 1, context->GetProtocol().c_str()) != ERR_OK) {
        NETSTACK_LOGE("memory copy failed");
    }

    connectInfo.context = lwsContext;
    connectInfo.port = port;
    connectInfo.address = address;
    connectInfo.path = path;
    connectInfo.host = address;
    connectInfo.origin = address;
    connectInfo.protocol = customizedProtocol;

    if (strcmp(protocol, PREFIX_HTTPS) == 0 || strcmp(protocol, PREFIX_WSS) == 0) {
        connectInfo.ssl_connection = LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK | LCCSCF_ALLOW_SELFSIGNED;
    }
    lws *wsi = nullptr;
    connectInfo.pwsi = &wsi;
    connectInfo.retry_and_idle_policy = &RETRY;
    connectInfo.userdata = websocketProxy;
    if (lws_client_connect_via_info(&connectInfo) == nullptr) {
        NETSTACK_LOGI("ExecConnect websocket connect failed");
        context->SetErrorCode(-1);
        OnConnectError(websocketProxy, COMMON_ERROR_CODE, 0);
        return false;
    }
    return true;
}

void RunService(std::shared_ptr<WebSocketContext> webSocketContext, CJWebsocketProxy* websocketProxy)
{
    NETSTACK_LOGI("websocket run service start");
    int res = 0;
    lws_context *context = webSocketContext->GetContext();
    if (context == nullptr) {
        NETSTACK_LOGE("context is null");
        return;
    }
    while (res >= 0 && !webSocketContext->IsThreadStop()) {
        res = lws_service(context, 0);
    }
    lws_context_destroy(context);
    webSocketContext->SetContext(nullptr);
    websocketProxy->SetWebSocketContext(nullptr);
    NETSTACK_LOGI("websocket run service end");
}


bool NetWebSocketExec::ExecConnect(WebSocketConnectContext *context)
{
    NETSTACK_LOGD("websocket Connect exec");
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    auto websocketProxy = context->GetWebsocketProxy();
    if (websocketProxy == nullptr) {
        return false;
    }
    lws_context_creation_info info = {};
    char proxyAds[MAX_ADDRESS_LENGTH] = {0};
    FillContextInfo(context, info, proxyAds);
    if (!FillCaPath(context, info)) {
        return false;
    }
    lws_context *lwsContext = nullptr;
    std::shared_ptr<WebSocketContext> webSocketContext;
    if (websocketProxy->GetWebSocketContext() == nullptr) {
        lwsContext = lws_create_context(&info);
        webSocketContext = std::make_shared<WebSocketContext>(lwsContext);
        webSocketContext->header = context->header;
        websocketProxy->SetWebSocketContext(webSocketContext);
    } else {
        NETSTACK_LOGE("Websocket connect already exist");
        context->SetErrorCode(WEBSOCKET_ERROR_CODE_CONNECT_AlREADY_EXIST);
        return false;
    }
    if (!CreatConnectInfo(context, lwsContext, websocketProxy)) {
        webSocketContext->SetContext(nullptr);
        lws_context_destroy(lwsContext);
        websocketProxy->SetWebSocketContext(nullptr);
        return false;
    }
    std::thread serviceThread(RunService, webSocketContext, websocketProxy);

#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(WEBSOCKET_CLIENT_THREAD_RUN);
#else
    pthread_setname_np(serviceThread.native_handle(), WEBSOCKET_CLIENT_THREAD_RUN);
#endif
    serviceThread.detach();
    return true;
}

bool NetWebSocketExec::ExecSend(WebSocketSendContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    auto websocketProxy = context->GetWebsocketProxy();
    if (websocketProxy == nullptr) {
        NETSTACK_LOGE("context is null");
        return false;
    }
    auto webSocketContext = websocketProxy->GetWebSocketContext();
    if (webSocketContext == nullptr) {
        NETSTACK_LOGE("user data is nullptr");
        return false;
    }
    if (webSocketContext->IsClosed() || webSocketContext->IsThreadStop()) {
        NETSTACK_LOGE("session is closed or stopped");
        return false;
    }
    webSocketContext->Push(context->data, context->length, context->protocol);
    webSocketContext->TriggerWritable();
    NETSTACK_LOGD("lws ts send success");
    return true;
}

bool NetWebSocketExec::ExecClose(WebSocketCloseContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    if (context->GetWebsocketProxy() == nullptr) {
        NETSTACK_LOGE("context is null");
        return false;
    }

    auto websocketProxy = context->GetWebsocketProxy();
    auto webSocketContext = websocketProxy->GetWebSocketContext();
    if (webSocketContext == nullptr) {
        NETSTACK_LOGE("user data is nullptr");
        return false;
    }

    if (webSocketContext->IsClosed()) {
        NETSTACK_LOGE("connection has been closed");
        return false;
    }
    webSocketContext->Close(static_cast<lws_close_status>(context->code), context->reason);
    webSocketContext->TriggerWritable();
    NETSTACK_LOGI("ExecClose OK");
    return true;
}

bool NetWebSocketExec::ParseUrl(WebSocketConnectContext *context, char *protocol, size_t protocolLen, char *address,
                                size_t addressLen, char *path, size_t pathLen, int *port)
{
    char uri[MAX_URI_LENGTH] = {0};
    if (strcpy_s(uri, MAX_URI_LENGTH, context->url.c_str()) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    const char *tempProt = nullptr;
    const char *tempAddress = nullptr;
    const char *tempPath = nullptr;
    (void)lws_parse_uri(uri, &tempProt, &tempAddress, port, &tempPath);
    if (strcpy_s(protocol, protocolLen, tempProt) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    if (std::find(WS_PREFIX.begin(), WS_PREFIX.end(), protocol) == WS_PREFIX.end()) {
        NETSTACK_LOGE("protocol failed");
        return false;
    }
    if (strcpy_s(address, addressLen, tempAddress) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    if (strcpy_s(path, pathLen, tempPath) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    return true;
}

int NetWebSocketExec::RaiseError(CJWebsocketProxy *websocketProxy, uint32_t httpResponse)
{
    OnError(websocketProxy, COMMON_ERROR_CODE, httpResponse);
    return -1;
}

int NetWebSocketExec::LwsCallback(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGI("lws callback reason is %{public}d", reason);
    CallbackDispatcher dispatchers[] = {
        {LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER, LwsCallbackClientAppendHandshakeHeader},
        {LWS_CALLBACK_WS_PEER_INITIATED_CLOSE, LwsCallbackWsPeerInitiatedClose},
        {LWS_CALLBACK_CLIENT_WRITEABLE, LwsCallbackClientWritable},
        {LWS_CALLBACK_CLIENT_CONNECTION_ERROR, LwsCallbackClientConnectionError},
        {LWS_CALLBACK_CLIENT_RECEIVE, LwsCallbackClientReceive},
        {LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH, LwsCallbackClientFilterPreEstablish},
        {LWS_CALLBACK_CLIENT_ESTABLISHED, LwsCallbackClientEstablished},
        {LWS_CALLBACK_CLIENT_CLOSED, LwsCallbackClientClosed},
        {LWS_CALLBACK_WSI_DESTROY, LwsCallbackWsiDestroy},
        {LWS_CALLBACK_PROTOCOL_DESTROY, LwsCallbackProtocolDestroy},
        {LWS_CALLBACK_VHOST_CERT_AGING, LwsCallbackVhostCertAging},
    };

    for (const auto dispatcher : dispatchers) {
        if (dispatcher.reason == reason) {
            return dispatcher.callback(wsi, reason, user, in, len);
        }
    }

    return HttpDummy(wsi, reason, user, in, len);
}

int NetWebSocketExec::HttpDummy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    int ret = lws_callback_http_dummy(wsi, reason, user, in, len);
    if (ret < 0) {
        OnError(reinterpret_cast<CJWebsocketProxy *>(user), COMMON_ERROR_CODE, GetHttpResponseFromWsi(wsi));
    }
    return 0;
}

int NetWebSocketExec::LwsCallbackClientAppendHandshakeHeader(lws *wsi, lws_callback_reasons reason,
                                                             void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback client append handshake header");
    auto websocketProxy = reinterpret_cast<CJWebsocketProxy *>(user);
    auto webSocketContext = websocketProxy->GetWebSocketContext();
    if (webSocketContext == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(websocketProxy, GetHttpResponseFromWsi(wsi));
    }

    auto payload = reinterpret_cast<unsigned char **>(in);
    if (payload == nullptr || (*payload) == nullptr || len == 0) {
        NETSTACK_LOGE("header payload is null, do not append header");
        return RaiseError(websocketProxy, GetHttpResponseFromWsi(wsi));
    }
    auto payloadEnd = (*payload) + len;
    for (const auto &pair : webSocketContext->header) {
        std::string name = pair.first + NAME_END;
        if (lws_add_http_header_by_name(wsi, reinterpret_cast<const unsigned char *>(name.c_str()),
                                        reinterpret_cast<const unsigned char *>(pair.second.c_str()),
                                        static_cast<int>(strlen(pair.second.c_str())), payload, payloadEnd)) {
            NETSTACK_LOGE("add header failed");
            return RaiseError(websocketProxy, GetHttpResponseFromWsi(wsi));
        }
    }
    NETSTACK_LOGI("add header OK");
    return HttpDummy(wsi, reason, user, in, len);
}

int NetWebSocketExec::LwsCallbackWsPeerInitiatedClose(lws *wsi, lws_callback_reasons reason,
                                                      void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback ws peer initiated close");
    auto websocketProxy = reinterpret_cast<CJWebsocketProxy *>(user);
    auto webSocketContext = websocketProxy->GetWebSocketContext();
    if (webSocketContext == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(websocketProxy, GetHttpResponseFromWsi(wsi));
    }

    if (in == nullptr || len < sizeof(uint16_t)) {
        NETSTACK_LOGI("No close reason");
        webSocketContext->Close(LWS_CLOSE_STATUS_NORMAL, "");
        return HttpDummy(wsi, reason, user, in, len);
    }

    uint16_t closeStatus = ntohs(*reinterpret_cast<uint16_t *>(in));
    std::string closeReason;
    closeReason.append(reinterpret_cast<char *>(in) + sizeof(uint16_t), len - sizeof(uint16_t));
    webSocketContext->Close(static_cast<lws_close_status>(closeStatus), closeReason);
    return HttpDummy(wsi, reason, user, in, len);
}

int NetWebSocketExec::LwsCallbackClientWritable(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback client writable");
    auto websocketProxy = reinterpret_cast<CJWebsocketProxy *>(user);
    auto webSocketContext = websocketProxy->GetWebSocketContext();
    if (webSocketContext == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(websocketProxy, GetHttpResponseFromWsi(wsi));
    }
    if (webSocketContext->IsClosed()) {
        NETSTACK_LOGI("need to close");
        lws_close_reason(wsi, webSocketContext->closeStatus,
                         reinterpret_cast<unsigned char *>(const_cast<char *>(webSocketContext->closeReason.c_str())),
                         strlen(webSocketContext->closeReason.c_str()));
        // here do not emit error, because we close it
        return -1;
    }
    auto sendData = webSocketContext->Pop();
    if (sendData.data == nullptr || sendData.length == 0) {
        return HttpDummy(wsi, reason, user, in, len);
    }
    int sendLength = lws_write(wsi, reinterpret_cast<unsigned char *>(sendData.data) + LWS_SEND_BUFFER_PRE_PADDING,
                               sendData.length, sendData.protocol);
    free(sendData.data);
    NETSTACK_LOGD("lws send data length is %{public}d", sendLength);
    if (!webSocketContext->IsEmpty()) {
        lws_callback_on_writable(wsi);
    }
    return HttpDummy(wsi, reason, user, in, len);
}

int NetWebSocketExec::LwsCallbackClientConnectionError(lws *wsi, lws_callback_reasons reason,
                                                       void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback client connection error");
    NETSTACK_LOGI("Lws client connection error %{public}s", (in == nullptr) ? "null" : reinterpret_cast<char *>(in));
    // 200 means connect failed
    OnConnectError(reinterpret_cast<CJWebsocketProxy *>(user), COMMON_ERROR_CODE, GetHttpResponseFromWsi(wsi));
    return HttpDummy(wsi, reason, user, in, len);
}

int NetWebSocketExec::LwsCallbackClientReceive(lws *wsi, lws_callback_reasons reason,
                                               void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback client receive");
    auto websocketProxy = reinterpret_cast<CJWebsocketProxy *>(user);
    auto isFinal = lws_is_final_fragment(wsi);
    OnMessage(websocketProxy, in, len, lws_frame_is_binary(wsi), isFinal);
    return HttpDummy(wsi, reason, user, in, len);
}

int NetWebSocketExec::LwsCallbackClientFilterPreEstablish(lws *wsi, lws_callback_reasons reason,
                                                          void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback client filter preEstablish");
    auto websocketProxy = reinterpret_cast<CJWebsocketProxy *>(user);
    auto webSocketContext = websocketProxy->GetWebSocketContext();
    if (webSocketContext == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(websocketProxy, GetHttpResponseFromWsi(wsi));
    }

    webSocketContext->openStatus = GetHttpResponseFromWsi(wsi);
    char statusLine[MAX_HDR_LENGTH] = {0};
    if (lws_hdr_copy(wsi, statusLine, MAX_HDR_LENGTH, WSI_TOKEN_HTTP) < 0 || strlen(statusLine) == 0) {
        return HttpDummy(wsi, reason, user, in, len);
    }

    auto vec = CommonUtils::Split(statusLine, STATUS_LINE_SEP, STATUS_LINE_ELEM_NUM);
    if (vec.size() >= FUNCTION_PARAM_TWO) {
        webSocketContext->openMessage = vec[1];
    }

    char buffer[MAX_HDR_LENGTH] = {};
    std::map<std::string, std::string> responseHeader;
    for (int i = 0; i < WSI_TOKEN_COUNT; i++) {
        if (lws_hdr_total_length(wsi, static_cast<lws_token_indexes>(i)) > 0) {
            lws_hdr_copy(wsi, buffer, sizeof(buffer), static_cast<lws_token_indexes>(i));
            std::string str;
            if (lws_token_to_string(static_cast<lws_token_indexes>(i))) {
                str =
                    std::string(reinterpret_cast<const char *>(lws_token_to_string(static_cast<lws_token_indexes>(i))));
            }
            if (!str.empty() && str.back() == ':') {
                responseHeader.emplace(str.substr(0, str.size() - 1), std::string(buffer));
            }
        }
    }
    lws_hdr_custom_name_foreach(
        wsi,
        [](const char *name, int nlen, void *opaque) -> void {
            auto header = static_cast<std::map<std::string, std::string> *>(opaque);
            if (header == nullptr) {
                return;
            }
            header->emplace(std::string(name).substr(0, nlen - 1), std::string(name).substr(nlen));
        },
        &responseHeader);
    OnHeaderReceive(websocketProxy, responseHeader);
    return HttpDummy(wsi, reason, user, in, len);
}

int NetWebSocketExec::LwsCallbackClientEstablished(lws *wsi, lws_callback_reasons reason,
    void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback client established");
    auto websocketProxy = reinterpret_cast<CJWebsocketProxy *>(user);
    auto webSocketContext = websocketProxy->GetWebSocketContext();
    if (webSocketContext == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(websocketProxy, GetHttpResponseFromWsi(wsi));
    }
    lws_callback_on_writable(wsi);
    webSocketContext->SetLws(wsi);
    OnOpen(reinterpret_cast<CJWebsocketProxy *>(user), webSocketContext->openStatus, webSocketContext->openMessage);
    return HttpDummy(wsi, reason, user, in, len);
}

int NetWebSocketExec::LwsCallbackClientClosed(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback client closed");
    auto websocketProxy = reinterpret_cast<CJWebsocketProxy *>(user);
    auto webSocketContext = websocketProxy->GetWebSocketContext();
    if (webSocketContext == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(websocketProxy, GetHttpResponseFromWsi(wsi));
    }
    webSocketContext->SetThreadStop(true);
    if ((webSocketContext->closeReason).empty()) {
        webSocketContext->Close(webSocketContext->closeStatus, LINK_DOWN);
    }
    if (webSocketContext->closeStatus == LWS_CLOSE_STATUS_NOSTATUS) {
        NETSTACK_LOGE("The link is down, onError");
        OnError(websocketProxy, COMMON_ERROR_CODE, GetHttpResponseFromWsi(wsi));
    }
    OnClose(reinterpret_cast<CJWebsocketProxy *>(user), webSocketContext->closeStatus, webSocketContext->closeReason);
    return HttpDummy(wsi, reason, user, in, len);
}

int NetWebSocketExec::LwsCallbackWsiDestroy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback wsi destroy");
    auto websocketProxy = reinterpret_cast<CJWebsocketProxy *>(user);
    if (websocketProxy == nullptr) {
        NETSTACK_LOGE("websocketProxy is null");
        return RaiseError(websocketProxy, GetHttpResponseFromWsi(wsi));
    }
    auto webSocketContext = websocketProxy->GetWebSocketContext();
    if (webSocketContext == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(websocketProxy, GetHttpResponseFromWsi(wsi));
    }
    webSocketContext->SetLws(nullptr);
    return HttpDummy(wsi, reason, user, in, len);
}

int NetWebSocketExec::LwsCallbackProtocolDestroy(lws *wsi, lws_callback_reasons reason,
                                                 void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback protocol destroy");
    return HttpDummy(wsi, reason, user, in, len);
}

int NetWebSocketExec::LwsCallbackVhostCertAging(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGI("lws callback vhost cert aging. len: %{public}zu", len);
    return HttpDummy(wsi, reason, user, in, len);
}

void NetWebSocketExec::FillContextInfo(WebSocketConnectContext *context,
    lws_context_creation_info &info, char *proxyAds)
{
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = WEBSOCKET_PROTOCOLS;
    info.fd_limit_per_thread = FD_LIMIT_PER_THREAD;

    char tempUri[MAX_URI_LENGTH] = {0};
    const char *tempProtocol = nullptr;
    const char *tempAddress = nullptr;
    const char *tempPath = nullptr;
    int32_t tempPort = 0;

    std::string host;
    uint32_t port = 0;
    std::string exclusions;

    if (strcpy_s(tempUri, MAX_URI_LENGTH, context->url.c_str()) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return;
    }
    if (lws_parse_uri(tempUri, &tempProtocol, &tempAddress, &tempPort, &tempPath) != 0) {
        NETSTACK_LOGE("get websocket hostname failed");
        return;
    }
    GetWebsocketProxyInfo(context, host, port, exclusions);
    if (!host.empty() && !CommonUtils::IsHostNameExcluded(tempAddress, exclusions, ",")) {
        if (strcpy_s(proxyAds, host.length() + 1, host.c_str()) != ERR_OK) {
            NETSTACK_LOGE("memory copy failed");
        }
        info.http_proxy_address = proxyAds;
        info.http_proxy_port = port;
    }
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

bool NetWebSocketExec::FillCaPath(WebSocketConnectContext *context, lws_context_creation_info &info)
{
    if (!context->caPath_.empty()) {
        if (!CheckFilePath(context->caPath_)) {
            NETSTACK_LOGE("ca not exist");
            context->SetErrorCode(WEBSOCKET_ERROR_CODE_FILE_NOT_EXIST);
            return false;
        }
        info.client_ssl_ca_filepath = context->caPath_.c_str();
        NETSTACK_LOGD("load customize CA: %{public}s", info.client_ssl_ca_filepath);
    } else {
        info.client_ssl_ca_dirs[0] = WEBSOCKET_SYSTEM_PREPARE_CA_PATH;
#ifdef HAS_NETMANAGER_BASE
        if (NetManagerStandard::NetworkSecurityConfig::GetInstance().TrustUserCa()) {
            context->userCertPath_ = BASE_PATH + std::to_string(getuid() / UID_TRANSFORM_DIVISOR);
            info.client_ssl_ca_dirs[1] = context->userCertPath_.c_str();
        }
#endif
        NETSTACK_LOGD("load system CA");
    }
    if (!context->clientCert_.empty()) {
        char realKeyPath[PATH_MAX] = {0};
        if (!CheckFilePath(context->clientCert_) || !realpath(context->clientKey_.Data(), realKeyPath)) {
            NETSTACK_LOGE("client cert not exist");
            context->SetErrorCode(WEBSOCKET_ERROR_CODE_FILE_NOT_EXIST);
            return false;
        }
        context->clientKey_ = SecureChar(realKeyPath);
        info.client_ssl_cert_filepath = context->clientCert_.c_str();
        info.client_ssl_private_key_filepath = context->clientKey_.Data();
        info.client_ssl_private_key_password = context->keyPassword_.Data();
    }
    return true;
}

void NetWebSocketExec::GetWebsocketProxyInfo(WebSocketConnectContext *context, std::string &host,
                                             uint32_t &port, std::string &exclusions)
{
    if (context->GetUsingWebsocketProxyType() == WebsocketProxyType::USE_SYSTEM) {
#ifdef HAS_NETMANAGER_BASE
        using namespace NetManagerStandard;
        HttpProxy websocketProxy;
        NetConnClient::GetInstance().GetDefaultHttpProxy(websocketProxy);
        host = websocketProxy.GetHost();
        port = websocketProxy.GetPort();
        exclusions = CommonUtils::ToString(websocketProxy.GetExclusionList());
#endif
    } else if (context->GetUsingWebsocketProxyType() == WebsocketProxyType::USE_SPECIFIED) {
        context->GetSpecifiedWebsocketProxy(host, port, exclusions);
    }
}

uint32_t NetWebSocketExec::GetHttpResponseFromWsi(lws *wsi)
{
    if (wsi == nullptr) {
        return 0;
    }
    return lws_http_client_http_response(wsi);
}

void NetWebSocketExec::OnOpen(CJWebsocketProxy *websocketProxy, uint32_t status, const std::string &message)
{
    NETSTACK_LOGI("OnOpen %{public}u %{public}s", status, message.c_str());
    if (websocketProxy == nullptr) {
        NETSTACK_LOGE("websocketProxy is null");
        return;
    }
    if (websocketProxy->FindCallback(EVENT_OPEN) == std::nullopt) {
        NETSTACK_LOGI("no event listener: OPEN");
        return;
    }

    CWebSocketCallbackData* para = new CWebSocketCallbackData;
    para->code = ERR_OK;
    para->typeId = EVENT_OPEN;
    para->data = CreateOpenPara(status, message);
    para->dataLen = sizeof(COpenResponse);
    websocketProxy->EmitCallBack(para);
    auto openResponse = reinterpret_cast<COpenResponse*>(para->data);
    free(openResponse->message);
    delete openResponse;
    delete para;
}

void NetWebSocketExec::OnError(CJWebsocketProxy *websocketProxy, int32_t code, uint32_t httpResponse)
{
    NETSTACK_LOGI("OnError code is %{public}d, httpResponse is %{public}d", code, httpResponse);
    if (websocketProxy == nullptr) {
        NETSTACK_LOGE("websocketProxy is null");
        return;
    }
    if (websocketProxy->FindCallback(EVENT_OPEN) == std::nullopt) {
        NETSTACK_LOGI("no event listener: ERROR");
        return;
    }

    CWebSocketCallbackData* para = new CWebSocketCallbackData;
    para->code = ERR_OK;
    para->typeId = EVENT_ERROR;
    para->data = CreateError(code, httpResponse);
    para->dataLen = sizeof(CErrorResponse);
    websocketProxy->EmitCallBack(para);
    delete reinterpret_cast<CErrorResponse*>(para->data);
    delete para;
}

void NetWebSocketExec::OnMessage(CJWebsocketProxy *websocketProxy, void *data,
                                 size_t length, bool isBinary, bool isFinal)
{
    NETSTACK_LOGD("OnMessage %{public}d", isBinary);
    if (websocketProxy == nullptr) {
        NETSTACK_LOGE("websocketProxy is null");
        return;
    }
    if (websocketProxy->FindCallback(EVENT_OPEN) == std::nullopt) {
        NETSTACK_LOGI("no event listener: MESSAGE");
        return;
    }
        if (length > INT32_MAX) {
        NETSTACK_LOGE("data length too long");
        return;
    }
    HandleRcvMessage(websocketProxy, data, length, isBinary, isFinal);
}

void NetWebSocketExec::OnClose(CJWebsocketProxy *websocketProxy,
    lws_close_status closeStatus, const std::string &closeReason)
{
    NETSTACK_LOGI("OnClose %{public}u %{public}s", closeStatus, closeReason.c_str());
    if (websocketProxy == nullptr) {
        NETSTACK_LOGE("websocketProxy is null");
        return;
    }
    if (websocketProxy->FindCallback(EVENT_CLOSE) == std::nullopt) {
        NETSTACK_LOGI("no event listener: CLOSE");
        return;
    }

    CWebSocketCallbackData* para = new CWebSocketCallbackData;
    para->code = ERR_OK;
    para->typeId = EVENT_CLOSE;
    para->data = CreateClosePara(closeStatus, closeReason);
    para->dataLen = sizeof(CCloseResponse);
    websocketProxy->EmitCallBack(para);
    auto closeResponse = reinterpret_cast<CCloseResponse*>(para->data);
    free(closeResponse->reason);
    delete closeResponse;
    delete para;
}

void NetWebSocketExec::OnDataEnd(CJWebsocketProxy *websocketProxy)
{
    if (websocketProxy == nullptr) {
        NETSTACK_LOGE("websocketProxy is null");
        return;
    }
    if (websocketProxy->FindCallback(EVENT_DATA_END) == std::nullopt) {
        NETSTACK_LOGI("no event listener: EVENT_DATA_END");
        return;
    }
    CWebSocketCallbackData* para = new CWebSocketCallbackData;
    para->code = ERR_OK;
    para->typeId = EVENT_DATA_END;
    websocketProxy->EmitCallBack(para);
    delete para;
}

void NetWebSocketExec::OnHeaderReceive(CJWebsocketProxy *websocketProxy,
                                       const std::map<std::string, std::string> &headers)
{
    if (websocketProxy == nullptr) {
        NETSTACK_LOGE("websocketProxy is null");
        return;
    }
    if (websocketProxy->FindCallback(EVENT_HEADER_RECEIVE) == std::nullopt) {
        NETSTACK_LOGI("no event listener: EVENT_HEADER_RECEIVE");
        return;
    }

    CWebSocketCallbackData* para = new CWebSocketCallbackData;
    para->code = ERR_OK;
    para->typeId = EVENT_HEADER_RECEIVE;
    para->data = CreateResponseHeader(headers);
    para->dataLen = sizeof(CReceiveResponse);
    websocketProxy->EmitCallBack(para);
    auto receiveResponse = reinterpret_cast<CReceiveResponse*>(para->data);
    FreeCArrString(receiveResponse->header);
    delete receiveResponse;
    delete para;
}

void NetWebSocketExec::HandleRcvMessage(CJWebsocketProxy *websocketProxy,
    void *data, size_t length, bool isBinary, bool isFinal)
{
    if (isBinary) {
        websocketProxy->AppendWebSocketBinaryData(data, length);
        if (isFinal) {
            const std::string &msgFromManager = websocketProxy->GetWebSocketBinaryData();
            auto msg = new std::string;
            msg->append(msgFromManager.data(), msgFromManager.size());
            websocketProxy->SetQueueData(msg);
            CWebSocketCallbackData* para = new CWebSocketCallbackData;
            para->code = ERR_OK;
            para->typeId = EVENT_MESSAGE;
            para->data = CreateMessagePara(websocketProxy, isBinary);
            para->dataLen = sizeof(CMessageResponse);
            websocketProxy->EmitCallBack(para);
            if (para->data) {
                auto msgResponse = reinterpret_cast<CMessageResponse*>(para->data);
                free(msgResponse->result.head);
                delete msgResponse;
            }
            delete para;
            websocketProxy->ClearWebSocketTextData();
            OnDataEnd(websocketProxy);
        }
    } else {
        websocketProxy->AppendWebSocketTextData(data, length);
        if (isFinal) {
            const std::string &msgFromManager = websocketProxy->GetWebSocketTextData();
            auto msg = new (std::nothrow) std::string;
            if (msg == nullptr) {
                return;
            }
            msg->append(msgFromManager.data(), msgFromManager.size());
            websocketProxy->SetQueueData(msg);
            CWebSocketCallbackData* para = new CWebSocketCallbackData;
            para->code = ERR_OK;
            para->typeId = EVENT_MESSAGE;
            para->data = CreateMessagePara(websocketProxy, isBinary);
            para->dataLen = sizeof(CMessageResponse);
            websocketProxy->EmitCallBack(para);
            if (para->data) {
                auto msgResponse = reinterpret_cast<CMessageResponse*>(para->data);
                free(msgResponse->result.head);
                delete msgResponse;
            }
            delete para;
            websocketProxy->ClearWebSocketTextData();
            OnDataEnd(websocketProxy);
        }
    }
}
} // namespace OHOS::NetStack::NetWebSocket