/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstring>
#include <iostream>
#include <securec.h>
#include <string>

#include "netstack_log.h"
#include "websocket_client_innerapi.h"
#include "netstack_common_utils.h"

#ifdef HAS_NETMANAGER_BASE
#include "http_proxy.h"
#include "net_conn_client.h"
#endif

enum WebsocketErrorCodeEx {
    WEBSOCKET_CONNECT_FAILED = -1,
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

static constexpr const char *PATH_START = "/";
static constexpr const char *NAME_END = ":";
static constexpr const char *STATUS_LINE_SEP = " ";
static constexpr const size_t STATUS_LINE_ELEM_NUM = 2;
static constexpr const char *PREFIX_HTTPS = "https";
static constexpr const char *PREFIX_WS = "ws";
static constexpr const char *PREFIX_WSS = "wss";
static constexpr const int MAX_URI_LENGTH = 1024;
static constexpr const int MAX_ADDRESS_LENGTH = 1024;
static constexpr const int MAX_HDR_LENGTH = 1024;
static constexpr const int MAX_HEADER_LENGTH = 8192;
static constexpr const size_t MAX_DATA_LENGTH = 4 * 1024 * 1024;
static constexpr const int FD_LIMIT_PER_THREAD = 1 + 1 + 1;
static constexpr const int CLOSE_RESULT_FROM_SERVER_CODE = 1001;
static constexpr const int CLOSE_RESULT_FROM_CLIENT_CODE = 1000;
static constexpr const char *LINK_DOWN = "The link is down";
static constexpr const char *CLOSE_REASON_FORM_SERVER = "websocket close from server";
static constexpr const int FUNCTION_PARAM_TWO = 2;
static constexpr const char *WEBSOCKET_CLIENT_THREAD_RUN = "OS_NET_WSCli";
static constexpr const char *WEBSOCKET_SYSTEM_PREPARE_CA_PATH = "/etc/security/certificates";
#ifdef HAS_NETMANAGER_BASE
static constexpr const int32_t UID_TRANSFORM_DIVISOR = 200000;
static constexpr const char *BASE_PATH = "/data/certificates/user_cacerts/";
#endif
static constexpr const int WS_DEFAULT_PORT = 80;
static constexpr const int WSS_DEFAULT_PORT = 443;
static std::atomic<int> g_clientID(0);
namespace OHOS::NetStack::WebSocketClient {
static const lws_retry_bo_t RETRY = {
    .secs_since_valid_ping = 30,    /* force PINGs after secs idle */
    .secs_since_valid_hangup = 60, /* hangup after secs idle */
    .jitter_percent = 20,
};
static const std::vector<std::string> WS_PREFIX = {PREFIX_WSS, PREFIX_WS};

WebSocketClient::WebSocketClient()
{
    clientContext = new ClientContext();
    clientContext->SetClientId(++g_clientID);
}

WebSocketClient::~WebSocketClient()
{
    delete clientContext;
    clientContext = nullptr;
}

ClientContext *WebSocketClient::GetClientContext() const
{
    return clientContext;
}

void RunService(WebSocketClient *Client)
{
    if (Client->GetClientContext()->GetContext() == nullptr) {
        return;
    }
    while (!Client->GetClientContext()->IsThreadStop()) {
        lws_service(Client->GetClientContext()->GetContext(), 0);
    }
}

int HttpDummy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    int ret = lws_callback_http_dummy(wsi, reason, user, in, len);
    return ret;
}

struct CallbackDispatcher {
    lws_callback_reasons reason;
    int (*callback)(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);
};

int LwsCallbackClientAppendHandshakeHeader(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    WebSocketClient *client = static_cast<WebSocketClient *>(user);
    if (client->GetClientContext() == nullptr) {
        NETSTACK_LOGE("Callback ClientContext is nullptr");
        return -1;
    }
    NETSTACK_LOGD("ClientId:%{public}d, Lws Callback AppendHandshakeHeader,",
                  client->GetClientContext()->GetClientId());
    auto payload = reinterpret_cast<unsigned char **>(in);
    if (payload == nullptr || (*payload) == nullptr || len == 0) {
        return -1;
    }
    auto payloadEnd = (*payload) + len;
    for (const auto &pair : client->GetClientContext()->header) {
        std::string name = pair.first + NAME_END;
        // LCOV_EXCL_START
        if (lws_add_http_header_by_name(wsi, reinterpret_cast<const unsigned char *>(name.c_str()),
                                        reinterpret_cast<const unsigned char *>(pair.second.c_str()),
                                        static_cast<int>(strlen(pair.second.c_str())), payload, payloadEnd)) {
            return -1;
        }
        // LCOV_EXCL_STOP
    }
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackWsPeerInitiatedClose(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    WebSocketClient *client = static_cast<WebSocketClient *>(user);
    if (client->GetClientContext() == nullptr) {
        NETSTACK_LOGE("Lws Callback ClientContext is nullptr");
        return -1;
    }
    NETSTACK_LOGD("ClientId:%{public}d,Callback WsPeerInitiatedClose", client->GetClientContext()->GetClientId());
    if (in == nullptr || len < sizeof(uint16_t)) {
        NETSTACK_LOGE("Lws Callback WsPeerInitiatedClose");
        client->GetClientContext()->Close(LWS_CLOSE_STATUS_NORMAL, "");
        return HttpDummy(wsi, reason, user, in, len);
    }
    uint16_t closeStatus = ntohs(*reinterpret_cast<uint16_t *>(in));
    std::string closeReason;
    closeReason.append(reinterpret_cast<char *>(in) + sizeof(uint16_t), len - sizeof(uint16_t));
    client->GetClientContext()->Close(static_cast<lws_close_status>(closeStatus), closeReason);
    return HttpDummy(wsi, reason, user, in, len);
}

// LCOV_EXCL_START
int LwsCallbackClientWritable(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    WebSocketClient *client = static_cast<WebSocketClient *>(user);
    if (client->GetClientContext() == nullptr) {
        NETSTACK_LOGE("Lws Callback ClientContext is nullptr");
        return -1;
    }
    NETSTACK_LOGD("ClientId:%{public}d,Callback CallbackClientWritable,",
                  client->GetClientContext()->GetClientId());
    if (client->GetClientContext()->IsClosed()) {
        NETSTACK_LOGD("ClientId:%{public}d,Callback ClientWritable need to close",
                      client->GetClientContext()->GetClientId());
        lws_close_reason(
            wsi, client->GetClientContext()->closeStatus,
            reinterpret_cast<unsigned char *>(const_cast<char *>(client->GetClientContext()->closeReason.c_str())),
            strlen(client->GetClientContext()->closeReason.c_str()));
        // here do not emit error, because we close it
        return -1;
    }
    SendData sendData = client->GetClientContext()->Pop();
    if (sendData.data == nullptr || sendData.length == 0) {
        return HttpDummy(wsi, reason, user, in, len);
    }
    const char *message = sendData.data;
    size_t messageLen = sendData.length;
    auto buffer = std::make_unique<unsigned char[]>(LWS_PRE + messageLen);
    if (buffer == nullptr) {
        return -1;
    }
    int result = memcpy_s(buffer.get() + LWS_PRE, LWS_PRE + messageLen, message, messageLen);
    if (result != 0) {
        return -1;
    }
    free(sendData.data);
    int bytesSent = lws_write(wsi, buffer.get() + LWS_PRE, messageLen, sendData.protocol);
    NETSTACK_LOGD("ClientId:%{public}d,Client Writable send data length = %{public}d",
                  client->GetClientContext()->GetClientId(), bytesSent);
    if (!client->GetClientContext()->IsEmpty()) {
        client->GetClientContext()->TriggerWritable();
    }
    return HttpDummy(wsi, reason, user, in, len);
}
// LCOV_EXCL_STOP

int LwsCallbackClientConnectionError(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    WebSocketClient *client = static_cast<WebSocketClient *>(user);
    NETSTACK_LOGE("ClientId:%{public}d,Callback ClientConnectionError", client->GetClientContext()->GetClientId());
    std::string buf;
    char *data = static_cast<char *>(in);
    buf.assign(data, len);
    ErrorResult errorResult;
    errorResult.errorCode = WebSocketErrorCode::WEBSOCKET_CONNECTION_ERROR;
    errorResult.errorMessage = data;
    if (client->onErrorCallback_) {
        client->onErrorCallback_(client, errorResult);
    }
    return HttpDummy(wsi, reason, user, in, len);
}

// LCOV_EXCL_START
int LwsCallbackClientReceive(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    WebSocketClient *client = static_cast<WebSocketClient *>(user);
    NETSTACK_LOGD("ClientId:%{public}d,Callback ClientReceive", client->GetClientContext()->GetClientId());
    auto isFinal = lws_is_final_fragment(wsi);
    client->AppendData(in, len);
    if (!isFinal) {
        return HttpDummy(wsi, reason, user, in, len);
    }
    std::string data = client->GetData();
    if (client->onMessageCallback_) {
        client->onMessageCallback_(client, data.c_str(), data.size());
    }
    if (client->onDataEndCallback_) {
        client->onDataEndCallback_(client);
    }
    client->ClearData();
    return HttpDummy(wsi, reason, user, in, len);
}
// LCOV_EXCL_STOP
 
void WebSocketClient::AppendData(void *data, size_t length)
{
    data_.append(reinterpret_cast<char *>(data), length);
}
 
const std::string &WebSocketClient::GetData()
{
    return data_;
}
 
void WebSocketClient::ClearData()
{
    data_.clear();
}

std::vector<std::string> Split(const std::string &str, const std::string &sep, size_t size)
{
    std::string s = str;
    std::vector<std::string> res;
    while (!s.empty()) {
        if (res.size() + 1 == size) {
            res.emplace_back(s);
            break;
        }
        auto pos = s.find(sep);
        if (pos == std::string::npos) {
            res.emplace_back(s);
            break;
        }
        res.emplace_back(s.substr(0, pos));
        s = s.substr(pos + sep.size());
    }
    return res;
}

// LCOV_EXCL_START
int LwsCallbackClientFilterPreEstablish(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    WebSocketClient *client = static_cast<WebSocketClient *>(user);
    if (client->GetClientContext() == nullptr) {
        NETSTACK_LOGE("Callback ClientContext is nullptr");
        return -1;
    }
    client->GetClientContext()->openStatus = lws_http_client_http_response(wsi);
    NETSTACK_LOGD("ClientId:%{public}d, libwebsockets Callback ClientFilterPreEstablish openStatus = %{public}d",
                  client->GetClientContext()->GetClientId(), client->GetClientContext()->openStatus);
    char statusLine[MAX_HDR_LENGTH] = {0};
    if (lws_hdr_copy(wsi, statusLine, MAX_HDR_LENGTH, WSI_TOKEN_HTTP) < 0 || strlen(statusLine) == 0) {
        return HttpDummy(wsi, reason, user, in, len);
    }
    auto vec = Split(statusLine, STATUS_LINE_SEP, STATUS_LINE_ELEM_NUM);
    if (vec.size() >= FUNCTION_PARAM_TWO) {
        client->GetClientContext()->openMessage = vec[1];
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
    if (client->onHeaderReceiveCallback_) {
        client->onHeaderReceiveCallback_(client, responseHeader);
    }
    return HttpDummy(wsi, reason, user, in, len);
}
// LCOV_EXCL_STOP

int LwsCallbackClientEstablished(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    WebSocketClient *client = static_cast<WebSocketClient *>(user);
    if (client->GetClientContext() == nullptr) {
        NETSTACK_LOGE("libwebsockets Callback ClientContext is nullptr");
        return -1;
    }
    NETSTACK_LOGI("ClientId:%{public}d,Callback ClientEstablished", client->GetClientContext()->GetClientId());
    client->GetClientContext()->TriggerWritable();
    client->GetClientContext()->SetLws(wsi);
    OpenResult openResult;
    openResult.status = client->GetClientContext()->openStatus;
    openResult.message = client->GetClientContext()->openMessage.c_str();
    if (client->onOpenCallback_) {
        client->onOpenCallback_(client, openResult);
    }
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackClientClosed(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    WebSocketClient *client = static_cast<WebSocketClient *>(user);
    if (client->GetClientContext() == nullptr) {
        NETSTACK_LOGE("Callback ClientContext is nullptr");
        return -1;
    }
    NETSTACK_LOGI("ClientId:%{public}d,Callback ClientClosed", client->GetClientContext()->GetClientId());
    std::string buf;
    char *data = static_cast<char *>(in);
    buf.assign(data, len);
    CloseResult closeResult;
    auto ctx = client->GetClientContext();
    if (ctx != nullptr && ctx->closeStatus != LWS_CLOSE_STATUS_NOSTATUS) {
        closeResult.code = static_cast<unsigned int>(ctx->closeStatus);
    } else {
        closeResult.code = static_cast<unsigned int>(CLOSE_RESULT_FROM_SERVER_CODE);
    }
    if (ctx != nullptr && !ctx->closeReason.empty()) {
        closeResult.reason = ctx->closeReason.c_str();
    } else {
        closeResult.reason = CLOSE_REASON_FORM_SERVER;
    }
    if (client->onCloseCallback_) {
        client->onCloseCallback_(client, closeResult);
    }
    client->GetClientContext()->SetThreadStop(true);
    if ((client->GetClientContext()->closeReason).empty()) {
        client->GetClientContext()->Close(client->GetClientContext()->closeStatus, LINK_DOWN);
    }
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackWsiDestroy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    WebSocketClient *client = static_cast<WebSocketClient *>(user);
    if (client->GetClientContext() == nullptr) {
        NETSTACK_LOGE("Callback ClientContext is nullptr");
        return -1;
    }
    NETSTACK_LOGI("Lws Callback LwsCallbackWsiDestroy");
    client->GetClientContext()->SetLws(nullptr);
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackProtocolDestroy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGI("Lws Callback ProtocolDestroy");
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackVhostCertAging(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGI("lws callback vhost cert aging. len: %{public}zu", len);
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallback(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    constexpr CallbackDispatcher dispatchers[] = {
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
    auto it = std::find_if(std::begin(dispatchers), std::end(dispatchers),
        [&reason](const CallbackDispatcher &dispatcher) { return dispatcher.reason == reason; });
    if (it != std::end(dispatchers) && user != nullptr) {
        return it->callback(wsi, reason, user, in, len);
    }
    return HttpDummy(wsi, reason, user, in, len);
}

static struct lws_protocols protocols[] = {{"lws-minimal-client1", LwsCallback, 0, 0, 0, NULL, 0},
                                           LWS_PROTOCOL_LIST_TERM};

static void GetWebsocketProxyInfo(ClientContext *context, std::string &host, uint32_t &port,
                                  std::string &exclusions)
{
    if (context->usingWebsocketProxyType == WebsocketProxyType::USE_SYSTEM) {
#ifdef HAS_NETMANAGER_BASE
        using namespace NetManagerStandard;
        HttpProxy websocketProxy;
        NetConnClient::GetInstance().GetDefaultHttpProxy(websocketProxy);
        host = websocketProxy.GetHost();
        port = websocketProxy.GetPort();
        exclusions = CommonUtils::ToString(websocketProxy.GetExclusionList());
#endif
    } else if (context->usingWebsocketProxyType == WebsocketProxyType::USE_SPECIFIED) {
        host = context->websocketProxyHost;
        port = static_cast<uint32_t>(context->websocketProxyPort);
        exclusions = context->websocketProxyExclusions;
    }
}

static void FillContextInfo(ClientContext *context, lws_context_creation_info &info, char *proxyAds, int proxyAdsLen)
{
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.fd_limit_per_thread = FD_LIMIT_PER_THREAD;

    char tempUri[MAX_URI_LENGTH] = {0};
    const char *tempProtocol = nullptr;
    const char *tempAddress = nullptr;
    const char *tempPath = nullptr;
    int32_t tempPort = 0;

    std::string host;
    uint32_t port = 0;
    std::string exclusions;

    if (strcpy_s(tempUri, sizeof tempUri, context->url.c_str()) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return;
    }
    if (lws_parse_uri(tempUri, &tempProtocol, &tempAddress, &tempPort, &tempPath) != 0) {
        NETSTACK_LOGE("get websocket hostname failed");
        return;
    }
    GetWebsocketProxyInfo(context, host, port, exclusions);
    if (!host.empty() && !CommonUtils::IsHostNameExcluded(tempAddress, exclusions, ",")) {
        if (strcpy_s(proxyAds, proxyAdsLen, host.c_str()) != EOK) {
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

static bool FillCaPath(ClientContext *context, lws_context_creation_info &info)
{
    if (!context->caPath.empty()) {
        if (!CheckFilePath(context->caPath)) {
            NETSTACK_LOGE("ca not exist");
            context->errorCode = WebSocketErrorCode::WEBSOCKET_ERROR_FILE_NOT_EXIST;
            return false;
        }
        info.client_ssl_ca_filepath = context->caPath.c_str();
        NETSTACK_LOGD("load customize CA: %{public}s", info.client_ssl_ca_filepath);
    } else {
        info.client_ssl_ca_dirs[0] = WEBSOCKET_SYSTEM_PREPARE_CA_PATH;
#ifdef HAS_NETMANAGER_BASE
        if (NetManagerStandard::NetConnClient::GetInstance().TrustUserCa()) {
            context->SetUserCertPath(BASE_PATH + std::to_string(getuid() / UID_TRANSFORM_DIVISOR));
            info.client_ssl_ca_dirs[1] = context->GetUserCertPath().c_str();
        }
#endif
        NETSTACK_LOGD("load system CA");
    }
    if (!context->clientCert.empty()) {
        char realKeyPath[PATH_MAX] = {0};
        if (!CheckFilePath(context->clientCert) || !realpath(context->clientKey.Data(), realKeyPath)) {
            NETSTACK_LOGE("client cert not exist");
            context->errorCode = WebSocketErrorCode::WEBSOCKET_ERROR_FILE_NOT_EXIST;
            return false;
        }
        context->clientKey = Secure::SecureChar(realKeyPath);
        info.client_ssl_cert_filepath = context->clientCert.c_str();
        info.client_ssl_private_key_filepath = context->clientKey.Data();
        info.client_ssl_private_key_password = context->keyPassword.Data();
    }
    return true;
}

bool ParseUrl(const std::string url, char *prefix, char *address, char *path, int *port)
{
    char uri[MAX_URI_LENGTH] = {0};
    if (strcpy_s(uri, MAX_URI_LENGTH, url.c_str()) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    const char *tempPrefix = nullptr;
    const char *tempAddress = nullptr;
    const char *tempPath = nullptr;
    (void)lws_parse_uri(uri, &tempPrefix, &tempAddress, port, &tempPath);
    if (strcpy_s(prefix, MAX_URI_LENGTH, tempPrefix) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    if (strcpy_s(address, MAX_URI_LENGTH, tempAddress) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    if (strcpy_s(path, MAX_URI_LENGTH, tempPath) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    return true;
}

bool ParseUrlEx(const std::string url, char *prefix, char *address, char *path, int *port)
{
    char uri[MAX_URI_LENGTH] = {0};
    if (strcpy_s(uri, sizeof(uri), url.c_str()) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    const char *tempPrefix = nullptr;
    const char *tempAddress = nullptr;
    const char *tempPath = nullptr;
    (void)lws_parse_uri(uri, &tempPrefix, &tempAddress, port, &tempPath);
    if (strcpy_s(prefix, MAX_URI_LENGTH, tempPrefix) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    if (std::find(WS_PREFIX.begin(), WS_PREFIX.end(), prefix) == WS_PREFIX.end()) {
        NETSTACK_LOGE("protocol failed");
        return false;
    }
    if (strcpy_s(address, MAX_URI_LENGTH, tempAddress) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    if (strcpy_s(path, MAX_URI_LENGTH, tempPath) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    return true;
}

int CreatConnectInfo(const std::string url, lws_context *lwsContext, WebSocketClient *client)
{
    lws_client_connect_info connectInfo = {};
    char prefix[MAX_URI_LENGTH] = {0};
    char address[MAX_URI_LENGTH] = {0};
    char pathWithoutStart[MAX_URI_LENGTH] = {0};
    int port = 0;
    if (!ParseUrl(url, prefix, address, pathWithoutStart, &port)) {
        return WebSocketErrorCode::WEBSOCKET_CONNECTION_PARSEURL_ERROR;
    }
    std::string path = PATH_START + std::string(pathWithoutStart);
    std::string tempHost;
    if ((strcmp(prefix, PREFIX_WS) == 0 && port == WS_DEFAULT_PORT) ||
        (strcmp(prefix, PREFIX_WSS) == 0 && port == WSS_DEFAULT_PORT)) {
        tempHost = std::string(address);
    } else {
        tempHost = std::string(address) + NAME_END + std::to_string(port);
    }
    connectInfo.context = lwsContext;
    connectInfo.address = address;
    connectInfo.port = port;
    if (std::strlen(path.c_str()) != path.length()) {
        NETSTACK_LOGE("c_str() length does not match path length.");
        return -1;
    }
    connectInfo.path = path.c_str();
    connectInfo.host = tempHost.c_str();
    connectInfo.origin = address;

    connectInfo.local_protocol_name = "lws-minimal-client1";
    connectInfo.retry_and_idle_policy = &RETRY;
    if (strcmp(prefix, PREFIX_HTTPS) == 0 || strcmp(prefix, PREFIX_WSS) == 0) {
        connectInfo.ssl_connection =
            LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK | LCCSCF_ALLOW_INSECURE | LCCSCF_ALLOW_SELFSIGNED;
    }
    lws *wsi = nullptr;
    connectInfo.pwsi = &wsi;
    connectInfo.userdata = client;
    if (lws_client_connect_via_info(&connectInfo) == nullptr) {
        NETSTACK_LOGE("Connect lws_context_destroy");
        return WebSocketErrorCode::WEBSOCKET_CONNECTION_TO_SERVER_FAIL;
    }
    return WebSocketErrorCode::WEBSOCKET_NONE_ERR;
}

int WebSocketClient::Connect(std::string url, struct OpenOptions options)
{
    NETSTACK_LOGI("ClientId:%{public}d, Connect start", this->GetClientContext()->GetClientId());
    if (!CommonUtils::HasInternetPermission()) {
        this->GetClientContext()->permissionDenied = true;
        return WebSocketErrorCode::WEBSOCKET_ERROR_PERMISSION_DENIED;
    }
    if (this->GetClientContext()->isAtomicService && !CommonUtils::IsAllowedHostname(this->GetClientContext()->
            bundleName, CommonUtils::DOMAIN_TYPE_WEBSOCKET_REQUEST, this->GetClientContext()->url)) {
        this->GetClientContext()->noAllowedHost = true;
        return WebSocketErrorCode::WEBSOCKET_ERROR_DISALLOW_HOST;
    }
    if (!options.headers.empty()) {
        if (options.headers.size() > MAX_HEADER_LENGTH) {
            return WebSocketErrorCode::WEBSOCKET_ERROR_NO_HEADR_EXCEEDS;
        }
        for (const auto &item : options.headers) {
            const std::string &key = item.first;
            const std::string &value = item.second;
            this->GetClientContext()->header[key] = value;
        }
    }
    lws_context_creation_info info = {};
    char proxyAds[MAX_ADDRESS_LENGTH] = {0};
    FillContextInfo(this->GetClientContext(), info, proxyAds, MAX_ADDRESS_LENGTH);
    FillCaPath(this->GetClientContext(), info);
    lws_context *lwsContext = lws_create_context(&info);
    if (lwsContext == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_CONNECTION_NO_MEMOERY;
    }
    this->GetClientContext()->SetContext(lwsContext);
    int ret = CreatConnectInfo(url, lwsContext, this);
    if (ret != WEBSOCKET_NONE_ERR) {
        NETSTACK_LOGE("websocket CreatConnectInfo error");
        GetClientContext()->SetContext(nullptr);
        lws_context_destroy(lwsContext);
        return ret;
    }
    std::thread serviceThread(RunService, this);
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(WEBSOCKET_CLIENT_THREAD_RUN);
#else
    pthread_setname_np(serviceThread.native_handle(), WEBSOCKET_CLIENT_THREAD_RUN);
#endif
    serviceThread.detach();
    return WebSocketErrorCode::WEBSOCKET_NONE_ERR;
}

int WebSocketClient::Send(char *data, size_t length)
{
    if (data == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_SEND_DATA_NULL;
    }
    if (length == 0) {
        return WebSocketErrorCode::WEBSOCKET_NONE_ERR;
    }
    if (length > MAX_DATA_LENGTH) {
        return WebSocketErrorCode::WEBSOCKET_DATA_LENGTH_EXCEEDS;
    }
    if (this->GetClientContext() == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_ERROR_NO_CLIENTCONTEX;
    }

    lws_write_protocol protocol = (strlen(data) == length) ? LWS_WRITE_TEXT : LWS_WRITE_BINARY;
    auto dataCopy = reinterpret_cast<char *>(malloc(length));
    if (dataCopy == nullptr) {
        NETSTACK_LOGE("webSocketClient malloc error");
        return WEBSOCKET_SEND_NO_MEMOERY_ERROR;
    } else if (memcpy_s(dataCopy, length, data, length) != EOK) {
        free(dataCopy);
        NETSTACK_LOGE("webSocketClient malloc copy error");
        return WEBSOCKET_SEND_NO_MEMOERY_ERROR;
    }
    this->GetClientContext()->Push(dataCopy, length, protocol);
    this->GetClientContext()->TriggerWritable();
    return WebSocketErrorCode::WEBSOCKET_NONE_ERR;
}

int WebSocketClient::Close(CloseOption options)
{
    NETSTACK_LOGI("Close start");
    if (this->GetClientContext() == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_ERROR_NO_CLIENTCONTEX;
    }
    if (this->GetClientContext()->openStatus == 0)
        return WebSocketErrorCode::WEBSOCKET_ERROR_HAVE_NO_CONNECT;

    if (options.reason == nullptr || options.code == 0) {
        options.reason = "";
        options.code = CLOSE_RESULT_FROM_CLIENT_CODE;
    }
    this->GetClientContext()->Close(static_cast<lws_close_status>(options.code), options.reason);
    this->GetClientContext()->TriggerWritable();
    return WebSocketErrorCode::WEBSOCKET_NONE_ERR;
}

int WebSocketClient::Registcallback(OnOpenCallback onOpen, OnMessageCallback onMessage, OnErrorCallback onError,
                                    OnCloseCallback onClose)
{
    onMessageCallback_ = onMessage;
    onCloseCallback_ = onClose;
    onErrorCallback_ = onError;
    onOpenCallback_ = onOpen;
    return WebSocketErrorCode::WEBSOCKET_NONE_ERR;
}

int WebSocketClient::Destroy()
{
    NETSTACK_LOGI("Destroy start");
    if (this->GetClientContext()->GetContext() == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_ERROR_HAVE_NO_CONNECT_CONTEXT;
    }
    this->GetClientContext()->SetContext(nullptr);
    lws_context_destroy(this->GetClientContext()->GetContext());
    return WebSocketErrorCode::WEBSOCKET_NONE_ERR;
}

int CreatConnectInfoEx(const std::string url, lws_context *lwsContext, WebSocketClient *client)
{
    lws_client_connect_info connectInfo = {};
    char prefix[MAX_URI_LENGTH] = {0};
    char address[MAX_URI_LENGTH] = {0};
    char pathWithoutStart[MAX_URI_LENGTH] = {0};
    int port = 0;
    if (!ParseUrlEx(url, prefix, address, pathWithoutStart, &port)) {
        NETSTACK_LOGI("websocket-log| ParseUrl error: %{public}s", url.c_str());
        return WebsocketErrorCodeEx::WEBSOCKET_ERROR_CODE_URL_ERROR;
    }
    std::string path = PATH_START + std::string(pathWithoutStart);
    std::string tempHost;
    // LCOV_EXCL_START
    if ((strcmp(prefix, PREFIX_WS) == 0 && port == WS_DEFAULT_PORT) ||
        (strcmp(prefix, PREFIX_WSS) == 0 && port == WSS_DEFAULT_PORT)) {
        tempHost = std::string(address);
    } else {
        tempHost = std::string(address) + NAME_END + std::to_string(port);
    }
    connectInfo.context = lwsContext;
    connectInfo.address = address;
    connectInfo.port = port;
    if (std::strlen(path.c_str()) != path.length()) {
        NETSTACK_LOGE("c_str() length does not match path length");
        return -1;
    }
    connectInfo.path = path.c_str();
    connectInfo.host = tempHost.c_str();
    connectInfo.origin = address;

    connectInfo.local_protocol_name = "lws-minimal-client1";
    connectInfo.retry_and_idle_policy = &RETRY;
    if (strcmp(prefix, PREFIX_HTTPS) == 0 || strcmp(prefix, PREFIX_WSS) == 0) {
        connectInfo.ssl_connection =
            LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK | LCCSCF_ALLOW_INSECURE | LCCSCF_ALLOW_SELFSIGNED;
    }
    lws *wsi = nullptr;
    connectInfo.pwsi = &wsi;
    connectInfo.userdata = client;
    if (lws_client_connect_via_info(&connectInfo) == nullptr) {
        NETSTACK_LOGE("Connect lws_context_destroy");
        return -1;
    }
    // LCOV_EXCL_STOP
    return WebSocketErrorCode::WEBSOCKET_NONE_ERR;
}

int WebSocketClient::ConnectEx(std::string url, struct OpenOptions options)
{
    NETSTACK_LOGI("ClientId:%{public}d, Connect start", this->GetClientContext()->GetClientId());
    if (!CommonUtils::HasInternetPermission()) {
        this->GetClientContext()->permissionDenied = true;
        return WebSocketErrorCode::WEBSOCKET_ERROR_PERMISSION_DENIED;
    }
    if (this->GetClientContext()->isAtomicService && !CommonUtils::IsAllowedHostname(this->GetClientContext()->
            bundleName, CommonUtils::DOMAIN_TYPE_WEBSOCKET_REQUEST, this->GetClientContext()->url)) {
        this->GetClientContext()->noAllowedHost = true;
        return WebSocketErrorCode::WEBSOCKET_ERROR_DISALLOW_HOST;
    }
    if (!options.headers.empty()) {
        if (options.headers.size() > MAX_HEADER_LENGTH) {
            return WebSocketErrorCode::WEBSOCKET_ERROR_NO_HEADR_EXCEEDS;
        }
        for (const auto &item : options.headers) {
            const std::string &key = item.first;
            const std::string &value = item.second;
            this->GetClientContext()->header[key] = value;
        }
    }
    if (!this->GetClientContext()->GetUserCertPath().empty()) {
        this->GetClientContext()->caPath = this->GetClientContext()->GetUserCertPath();
    }
    
    lws_context_creation_info info = {};
    char proxyAds[MAX_ADDRESS_LENGTH] = {0};
    FillContextInfo(this->GetClientContext(), info, proxyAds, MAX_ADDRESS_LENGTH);
    if (!FillCaPath(this->GetClientContext(), info)) {
        return WebsocketErrorCodeEx::WEBSOCKET_ERROR_CODE_FILE_NOT_EXIST;
    }
    if (this->GetClientContext()->GetContext() != nullptr) {
        NETSTACK_LOGE("Websocket connect already exist");
        return WebsocketErrorCodeEx::WEBSOCKET_ERROR_CODE_CONNECT_ALREADY_EXIST;
    }
    lws_context *lwsContext = lws_create_context(&info);
    if (lwsContext == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_CONNECTION_NO_MEMOERY;
    }
    this->GetClientContext()->SetContext(lwsContext);
    int ret = CreatConnectInfoEx(url, lwsContext, this);
    if (ret != WEBSOCKET_NONE_ERR) {
        NETSTACK_LOGE("websocket CreatConnectInfoEx error");
        GetClientContext()->SetContext(nullptr);
        lws_context_destroy(lwsContext);
        return ret;
    }
    RunLwsThread();
    return WebSocketErrorCode::WEBSOCKET_NONE_ERR;
}

int WebSocketClient::SendEx(char *data, size_t length)
{
    NETSTACK_LOGI("WebSocketClient::SendEx start %{public}s, %{public}zu", data, length);
    if (!CommonUtils::HasInternetPermission()) {
        this->GetClientContext()->permissionDenied = true;
        return WebSocketErrorCode::WEBSOCKET_ERROR_PERMISSION_DENIED;
    }
    if (data == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_SEND_DATA_NULL;
    }
    if (length == 0) {
        return WebSocketErrorCode::WEBSOCKET_NONE_ERR;
    }
    if (length > MAX_DATA_LENGTH) {
        return WebSocketErrorCode::WEBSOCKET_DATA_LENGTH_EXCEEDS;
    }
    if (this->GetClientContext() == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_ERROR_NO_CLIENTCONTEX;
    }
    if (this->GetClientContext()->GetContext() == nullptr) {
        return -1;
    }

    lws_write_protocol protocol = (strlen(data) == length) ? LWS_WRITE_TEXT : LWS_WRITE_BINARY;
    auto dataCopy = reinterpret_cast<char *>(malloc(length));
    if (dataCopy == nullptr) {
        NETSTACK_LOGE("webSocketClient malloc error");
        return WEBSOCKET_SEND_NO_MEMOERY_ERROR;
    } else if (memcpy_s(dataCopy, length, data, length) != EOK) {
        free(dataCopy);
        NETSTACK_LOGE("webSocketClient malloc copy error");
        return WEBSOCKET_SEND_NO_MEMOERY_ERROR;
    }
    this->GetClientContext()->Push(dataCopy, length, protocol);
    this->GetClientContext()->TriggerWritable();
    NETSTACK_LOGI("WebSocketClient::Send end %{public}s, %{public}s, %{public}zu", dataCopy, data, length);
    return WebSocketErrorCode::WEBSOCKET_NONE_ERR;
}

int WebSocketClient::CloseEx(CloseOption options)
{
    if (!CommonUtils::HasInternetPermission()) {
        this->GetClientContext()->permissionDenied = true;
        return WebSocketErrorCode::WEBSOCKET_ERROR_PERMISSION_DENIED;
    }
    if (this->GetClientContext() == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_ERROR_NO_CLIENTCONTEX;
    }
    if (this->GetClientContext()->GetContext() == nullptr) {
        return -1;
    }
    if (options.reason == nullptr || options.code == 0) {
        options.reason = "";
        options.code = CLOSE_RESULT_FROM_CLIENT_CODE;
    }
    this->GetClientContext()->Close(static_cast<lws_close_status>(options.code), options.reason);
    this->GetClientContext()->TriggerWritable();
    return WebSocketErrorCode::WEBSOCKET_NONE_ERR;
}

// LCOV_EXCL_START
void WebSocketClient::RunLwsThread()
{
    std::weak_ptr<WebSocketClient> weak = shared_from_this();
    std::thread serviceThread = std::thread([weak]() {
        auto client = weak.lock();
        if (client == nullptr) {
            NETSTACK_LOGE("WebSocketClient instance has been destroyed");
            return;
        }
        auto* context = client->GetClientContext()->GetContext();
        if (context == nullptr) {
            return;
        }
        int res = 0;
        while (res >= 0 && !client->GetClientContext()->IsThreadStop()) {
            res = lws_service(context, 0);
        }
        lws_context_destroy(context);
        client->GetClientContext()->SetContext(nullptr);
        client = nullptr;
    });
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(WEBSOCKET_CLIENT_THREAD_RUN);
#else
    pthread_setname_np(serviceThread.native_handle(), WEBSOCKET_CLIENT_THREAD_RUN);
#endif
    serviceThread.detach();
}
// LCOV_EXCL_STOP

} // namespace OHOS::NetStack::WebSocketClient