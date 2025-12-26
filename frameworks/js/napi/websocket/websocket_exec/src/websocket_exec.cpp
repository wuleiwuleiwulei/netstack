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

#include "websocket_exec.h"

#include <atomic>
#include <memory>
#include <queue>
#include <thread>
#include <unistd.h>

#include "constant.h"
#include "napi_utils.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "securec.h"
#include "websocket_exec_common.h"
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

static constexpr const int MAX_URI_LENGTH = 2048;

static constexpr const int MAX_HDR_LENGTH = 1024;

static constexpr const int MAX_PROTOCOL_LENGTH = 1024;

static constexpr const int MAX_ADDRESS_LENGTH = 2048;

static constexpr const int FD_LIMIT_PER_THREAD = 1 + 1 + 1;

static constexpr const int COMMON_ERROR_CODE = 200;

static constexpr const char *EVENT_KEY_CODE = "code";

static constexpr const char *EVENT_KEY_STATUS = "status";

static constexpr const char *EVENT_KEY_REASON = "reason";

static constexpr const char *EVENT_KEY_MESSAGE = "message";

static constexpr const char *LINK_DOWN = "The link is down";

static constexpr const int32_t UID_TRANSFORM_DIVISOR = 200000;

static constexpr const char *BASE_PATH = "/data/certificates/user_cacerts/";

static constexpr const char *WEBSOCKET_SYSTEM_PREPARE_CA_PATH = "/etc/security/certificates";

static constexpr const char *WEBSOCKET_CLIENT_THREAD_RUN = "OS_NET_WSJsCli";

static constexpr const int WS_DEFAULT_PORT = 80;

static constexpr const int WSS_DEFAULT_PORT = 443;

namespace OHOS::NetStack::Websocket {

static const lws_protocols LWS_PROTOCOLS[] = {
    {"lws-minimal-client", WebSocketExec::LwsCallback, 0, 0},
    {nullptr, nullptr, 0, 0}, // this line is needed
};

struct CallbackDispatcher {
    lws_callback_reasons reason;
    int (*callback)(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);
};

struct OnOpenClosePara {
    OnOpenClosePara() : status(0) {}
    uint32_t status;
    std::string message;
};

struct WebSocketRecvMessage {
    std::string data;
    bool isBinary;
};

static const std::vector<std::string> WS_PREFIX = {PREFIX_WSS, PREFIX_WS};

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

bool WebSocketExec::ParseUrl(ConnectContext *context, std::string &protocol, std::string &address, std::string &path,
    int &port)
{
    char uri[MAX_URI_LENGTH] = {0};
    if (strcpy_s(uri, MAX_URI_LENGTH, context->url.c_str()) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    const char *tempProt = nullptr;
    const char *tempAddress = nullptr;
    const char *tempPath = nullptr;
    (void)lws_parse_uri(uri, &tempProt, &tempAddress, &port, &tempPath);
    protocol = std::string(tempProt);
    if (std::find(WS_PREFIX.begin(), WS_PREFIX.end(), protocol) == WS_PREFIX.end()) {
        NETSTACK_LOGE("protocol failed");
        return false;
    }
    address = std::string(tempAddress);
    path = std::string(tempPath);
    return true;
}

void WebSocketExec::ParseHost(const std::string &protocol, const std::string &address, int port, std::string &host)
{
    if ((protocol == PREFIX_WS && port == WS_DEFAULT_PORT) ||
        (protocol == PREFIX_WSS && port == WSS_DEFAULT_PORT)) {
        host = address;
    } else {
        host = address + NAME_END + std::to_string(port);
    }
    std::string origin = protocol + NAME_END + PROTOCOL_DELIMITER + host;
    NETSTACK_LOGD("host: %{private}s, Origin = %{private}s", host.c_str(), origin.c_str());
}

void RunService(std::shared_ptr<UserData> userData, std::shared_ptr<EventManager> manager)
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
    NETSTACK_LOGI("websocket run service end");
}

int WebSocketExec::RaiseError(EventManager *manager, uint32_t httpResponse)
{
    OnError(manager, COMMON_ERROR_CODE, httpResponse);
    return -1;
}

uint32_t WebSocketExec::GetHttpResponseFromWsi(lws *wsi)
{
    if (wsi == nullptr) {
        return 0;
    }
    return lws_http_client_http_response(wsi);
}

int WebSocketExec::HttpDummy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    int ret = lws_callback_http_dummy(wsi, reason, user, in, len);
    if (ret < 0) {
        OnError(reinterpret_cast<EventManager *>(user), COMMON_ERROR_CODE, GetHttpResponseFromWsi(wsi));
    }
    return 0;
}

int WebSocketExec::LwsCallbackClientAppendHandshakeHeader(lws *wsi, lws_callback_reasons reason, void *user, void *in,
                                                          size_t len)
{
    NETSTACK_LOGD("lws callback client append handshake header");
    auto manager = reinterpret_cast<EventManager *>(user);
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }

    auto payload = reinterpret_cast<unsigned char **>(in);
    if (payload == nullptr || (*payload) == nullptr || len == 0) {
        NETSTACK_LOGE("header payload is null, do not append header");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    auto payloadEnd = (*payload) + len;
    for (const auto &pair : userData->header) {
        std::string name = pair.first + NAME_END;
        if (lws_add_http_header_by_name(wsi, reinterpret_cast<const unsigned char *>(name.c_str()),
                                        reinterpret_cast<const unsigned char *>(pair.second.c_str()),
                                        static_cast<int>(strlen(pair.second.c_str())), payload, payloadEnd)) {
            NETSTACK_LOGE("add header failed");
            return RaiseError(manager, GetHttpResponseFromWsi(wsi));
        }
    }
    NETSTACK_LOGI("add header OK");
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackWsPeerInitiatedClose(lws *wsi, lws_callback_reasons reason, void *user, void *in,
                                                   size_t len)
{
    NETSTACK_LOGD("lws callback ws peer initiated close");
    auto manager = reinterpret_cast<EventManager *>(user);
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }

    if (in == nullptr || len < sizeof(uint16_t)) {
        NETSTACK_LOGI("No close reason");
        userData->Close(LWS_CLOSE_STATUS_NORMAL, "");
        return HttpDummy(wsi, reason, user, in, len);
    }

    uint16_t closeStatus = ntohs(*reinterpret_cast<uint16_t *>(in));
    std::string closeReason;
    closeReason.append(reinterpret_cast<char *>(in) + sizeof(uint16_t), len - sizeof(uint16_t));
    userData->Close(static_cast<lws_close_status>(closeStatus), closeReason);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackClientWritable(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback client writable");
    auto manager = reinterpret_cast<EventManager *>(user);
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    if (userData->IsClosed()) {
        NETSTACK_LOGI("need to close");
        lws_close_reason(wsi, userData->closeStatus,
                         reinterpret_cast<unsigned char *>(const_cast<char *>(userData->closeReason.c_str())),
                         strlen(userData->closeReason.c_str()));
        // here do not emit error, because we close it
        return -1;
    }
    auto sendData = userData->Pop();
    if (sendData.data == nullptr) {
        return HttpDummy(wsi, reason, user, in, len);
    }
    int sendLength = lws_write(wsi, reinterpret_cast<unsigned char *>(sendData.data) + LWS_SEND_BUFFER_PRE_PADDING,
                               sendData.length, sendData.protocol);
    free(sendData.data);
    NETSTACK_LOGD("lws send data length is %{public}d", sendLength);
    if (!userData->IsEmpty()) {
        userData->TriggerWritable();
    }
    return HttpDummy(wsi, reason, user, in, len);
}

static napi_value CreateConnectError(napi_env env, void *callbackPara)
{
    auto pair = reinterpret_cast<std::pair<int, uint32_t> *>(callbackPara);
    auto deleter = [](std::pair<int, uint32_t> *p) { delete p; };
    std::unique_ptr<std::pair<int, uint32_t>, decltype(deleter)> handler(pair, deleter);
    napi_value err = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, err) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetInt32Property(env, err, EVENT_KEY_CODE, pair->first);
    NapiUtils::SetStringPropertyUtf8(env, err, "data", std::to_string(pair->second));
    return err;
}

void OnConnectError(EventManager *manager, int32_t code, uint32_t httpResponse)
{
    NETSTACK_LOGI("OnError %{public}d", code);
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    if (auto userData = manager->GetWebSocketUserData(); userData != nullptr) {
        NETSTACK_LOGI("OnConnectError SetThreadStop");
        userData->SetThreadStop(true);
    }
    if (!manager->HasEventListener(EventName::EVENT_ERROR)) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_ERROR);
        return;
    }
    auto pair = new std::pair<int, uint32_t>;
    pair->first = code;
    pair->second = httpResponse;
    manager->EmitByUvWithoutCheckShared(EventName::EVENT_ERROR, pair, CallbackTemplate<CreateConnectError>);
}

int WebSocketExec::LwsCallbackClientConnectionError(lws *wsi, lws_callback_reasons reason, void *user, void *in,
                                                    size_t len)
{
    NETSTACK_LOGI("Lws client connection error %{public}s", (in == nullptr) ? "null" : reinterpret_cast<char *>(in));
    // 200 means connect failed
    OnConnectError(reinterpret_cast<EventManager *>(user), COMMON_ERROR_CODE, GetHttpResponseFromWsi(wsi));
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackClientReceive(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback client receive");
    auto manager = reinterpret_cast<EventManager *>(user);
    auto isFinal = lws_is_final_fragment(wsi);
    OnMessage(manager, in, len, lws_frame_is_binary(wsi), isFinal);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackClientFilterPreEstablish(lws *wsi, lws_callback_reasons reason, void *user, void *in,
                                                       size_t len)
{
    NETSTACK_LOGD("lws callback client filter preEstablish");
    auto manager = reinterpret_cast<EventManager *>(user);
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }

    userData->openStatus = GetHttpResponseFromWsi(wsi);
    char statusLine[MAX_HDR_LENGTH] = {0};
    if (lws_hdr_copy(wsi, statusLine, MAX_HDR_LENGTH, WSI_TOKEN_HTTP) < 0 || strlen(statusLine) == 0) {
        return HttpDummy(wsi, reason, user, in, len);
    }

    auto vec = CommonUtils::Split(statusLine, STATUS_LINE_SEP, STATUS_LINE_ELEM_NUM);
    if (vec.size() >= FUNCTION_PARAM_TWO) {
        userData->openMessage = vec[1];
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
    OnHeaderReceive(manager, responseHeader);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackClientEstablished(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback client established");
    auto manager = reinterpret_cast<EventManager *>(user);
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    userData->TriggerWritable();
    userData->SetLws(wsi);
    OnOpen(reinterpret_cast<EventManager *>(user), userData->openStatus, userData->openMessage);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackClientClosed(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback client closed");
    auto manager = reinterpret_cast<EventManager *>(user);
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    userData->SetThreadStop(true);
    if ((userData->closeReason).empty()) {
        userData->Close(userData->closeStatus, LINK_DOWN);
    }
    if (userData->closeStatus == LWS_CLOSE_STATUS_NOSTATUS) {
        NETSTACK_LOGE("The link is down, onError");
        OnError(manager, COMMON_ERROR_CODE, GetHttpResponseFromWsi(wsi));
    }
    OnClose(reinterpret_cast<EventManager *>(user), userData->closeStatus, userData->closeReason);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackWsiDestroy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback wsi destroy");
    auto manager = reinterpret_cast<EventManager *>(user);
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    userData->SetLws(nullptr);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackProtocolDestroy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback protocol destroy");
    return HttpDummy(wsi, reason, user, in, len);
}

// len: he number of days left before it expires
int WebSocketExec::LwsCallbackVhostCertAging(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGI("lws callback vhost cert aging. len: %{public}zu", len);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallback(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
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

void WebSocketExec::FillContextInfo(ConnectContext *context, lws_context_creation_info &info, char *proxyAds)
{
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = LWS_PROTOCOLS;
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
        if (strcpy_s(proxyAds, host.length() + 1, host.c_str()) != EOK) {
            NETSTACK_LOGE("memory copy failed");
        }
        info.http_proxy_address = proxyAds;
        info.http_proxy_port = port;
    }
}

static bool WebSocketConnect(lws_client_connect_info &connectInfo, const std::shared_ptr<EventManager> &manager,
    ConnectContext *context)
{
    if (lws_client_connect_via_info(&connectInfo) == nullptr) {
        NETSTACK_LOGI("ExecConnect websocket connect failed");
        context->SetErrorCode(-1);
        OnConnectError(manager.get(), COMMON_ERROR_CODE, 0);
        return false;
    }
    return true;
}

static void SetRetry(lws_retry_bo_t *retry, ConnectContext *context)
{
    if (context == nullptr) {
        return;
    }
    if (retry == nullptr) {
        return;
    }
    if (context->pingInterval_ < context->minPingInterval || context->pingInterval_ > context->maxPingInterval) {
        NETSTACK_LOGE("PingInterval is invalid: %{public}d", context->pingInterval_);
        context->pingInterval_ = context->defaultPingInterval;
    }
    if (context->pongTimeout_ > context->pingInterval_ && context->pongTimeout_ != context->defaultPingInterval) {
        NETSTACK_LOGE("PongTimeout is invalid: %{public}d", context->pongTimeout_);
        context->pongTimeout_ = context->pingInterval_;
    }
    if (context->pingInterval_ == context->minPingInterval) {
        context->pongTimeout_ = context->pingInterval_;
    }
    NETSTACK_LOGI("PingInterval is %{public}d,  PongTimeout is %{public}d",
        context->pingInterval_, context->pongTimeout_);
    retry->secs_since_valid_ping = context->pingInterval_;
    retry->secs_since_valid_hangup = context->pingInterval_ + context->pongTimeout_;
}

bool WebSocketExec::CreatConnectInfo(ConnectContext *context, lws_context *lwsContext,
    const std::shared_ptr<EventManager> &manager)
{
    lws_client_connect_info connectInfo = {};
    std::string protocol;
    std::string address;
    std::string path;
    char customizedProtocol[MAX_PROTOCOL_LENGTH] = {0};
    int port = 0;
    if (!ParseUrl(context, protocol, address, path, port)) {
        NETSTACK_LOGE("ParseUrl failed");
        context->SetErrorCode(WEBSOCKET_ERROR_CODE_URL_ERROR);
        return false;
    }
    if (lwsContext == nullptr) {
        NETSTACK_LOGE("no memory");
        return false;
    }
    std::string tempHost;
    ParseHost(protocol, address, port, tempHost);
    if (strcpy_s(customizedProtocol, context->GetProtocol().length() + 1, context->GetProtocol().c_str()) != EOK) {
        NETSTACK_LOGE("memory copy failed");
    }

    connectInfo.context = lwsContext;
    connectInfo.port = port;
    connectInfo.address = address.c_str();
    if (std::strlen(path.c_str()) != path.length()) {
        NETSTACK_LOGE("c_str() length does not match path length.");
        return false;
    }
    connectInfo.path = path.c_str();
    connectInfo.host = tempHost.c_str();
    connectInfo.origin = address.c_str();
    connectInfo.protocol = customizedProtocol;

    if (protocol == PREFIX_HTTPS || protocol == PREFIX_WSS) {
        connectInfo.ssl_connection = LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK | LCCSCF_ALLOW_SELFSIGNED;
    }
    if (context->skipServerCertVerification_) {
        NETSTACK_LOGI("ExecConnect skip server cert verify");
        connectInfo.ssl_connection = ((unsigned int)connectInfo.ssl_connection) | LCCSCF_ALLOW_INSECURE |
            LCCSCF_ALLOW_EXPIRED;
    }
    lws *wsi = nullptr;
    connectInfo.pwsi = &wsi;
    connectInfo.retry_and_idle_policy = &manager->GetWebSocketUserData()->retry_policy;
    connectInfo.userdata = manager.get();
    if (!WebSocketConnect(connectInfo, manager, context)) {
        return false;
    }
    return true;
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

bool WebSocketExec::FillCaPath(ConnectContext *context, lws_context_creation_info &info)
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
        context->clientKey_ = Secure::SecureChar(realKeyPath);
        info.client_ssl_cert_filepath = context->clientCert_.c_str();
        info.client_ssl_private_key_filepath = context->clientKey_.Data();
        info.client_ssl_private_key_password = context->keyPassword_.Data();
    }
    return true;
}

bool WebSocketExec::ExecConnect(ConnectContext *context)
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
    if (context->IsAtomicService() &&
        !CommonUtils::IsAllowedHostname(context->GetBundleName(), CommonUtils::DOMAIN_TYPE_WEBSOCKET_REQUEST,
                                        context->url)) {
        context->SetNoAllowedHost(true);
        return false;
    }
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        return false;
    }
    lws_context_creation_info info = {};
    char proxyAds[MAX_ADDRESS_LENGTH] = {0};
    FillContextInfo(context, info, proxyAds);
    if (!FillCaPath(context, info)) {
        return false;
    }
    lws_context *lwsContext = nullptr;
    std::shared_ptr<UserData> userData;
    if (manager->GetWebSocketUserData() == nullptr) {
        lwsContext = lws_create_context(&info);
        userData = std::make_shared<UserData>(lwsContext);
        userData->header = context->header;
        manager->SetWebSocketUserData(userData);
    } else {
        NETSTACK_LOGE("Websocket connect already exist");
        context->SetErrorCode(WEBSOCKET_ERROR_CODE_CONNECT_AlREADY_EXIST);
        return false;
    }
    SetRetry(&userData->retry_policy, context);
    if (!CreatConnectInfo(context, lwsContext, manager)) {
        userData->SetContext(nullptr);
        lws_context_destroy(lwsContext);
        manager->SetWebSocketUserData(nullptr);
        return false;
    }
    std::thread serviceThread(RunService, userData, manager);

#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(WEBSOCKET_CLIENT_THREAD_RUN);
#else
    pthread_setname_np(serviceThread.native_handle(), WEBSOCKET_CLIENT_THREAD_RUN);
#endif
    serviceThread.detach();
    return true;
}

napi_value WebSocketExec::ConnectCallback(ConnectContext *context)
{
    if (context->GetErrorCode() < 0) {
        NETSTACK_LOGI("ConnectCallback connect failed");
        return NapiUtils::GetBoolean(context->GetEnv(), false);
    }
    NETSTACK_LOGI("ConnectCallback connect success");
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}

bool WebSocketExec::ExecSend(SendContext *context)
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
    userData->Push(context->data, context->length, context->protocol);
    userData->TriggerWritable();
    NETSTACK_LOGD("lws ts send success");
    return true;
}

napi_value WebSocketExec::SendCallback(SendContext *context)
{
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}

bool WebSocketExec::ExecClose(CloseContext *context)
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

    auto manager = context->GetSharedManager();
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is nullptr");
        return false;
    }

    if (userData->IsClosed()) {
        NETSTACK_LOGE("connection has been closed");
        return false;
    }
    userData->Close(static_cast<lws_close_status>(context->code), context->reason);
    userData->TriggerWritable();
    NETSTACK_LOGI("ExecClose OK");
    return true;
}

napi_value WebSocketExec::CloseCallback(CloseContext *context)
{
    auto manager = context->GetSharedManager();
    if (manager != nullptr) {
        NETSTACK_LOGD("websocket close, delete js ref");
        manager->DeleteEventReference(context->GetEnv());
    }
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}

static napi_value CreateError(napi_env env, void *callbackPara)
{
    auto pair = reinterpret_cast<std::pair<int, uint32_t> *>(callbackPara);
    auto deleter = [](std::pair<int, uint32_t> *p) { delete p; };
    std::unique_ptr<std::pair<int, uint32_t>, decltype(deleter)> handler(pair, deleter);
    napi_value err = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, err) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetInt32Property(env, err, EVENT_KEY_CODE, pair->first);
    NapiUtils::SetStringPropertyUtf8(env, err, "data", std::to_string(pair->second));
    return err;
}

static napi_value CreateOpenPara(napi_env env, void *callbackPara)
{
    auto para = reinterpret_cast<OnOpenClosePara *>(callbackPara);
    auto deleter = [](const OnOpenClosePara *p) { delete p; };
    std::unique_ptr<OnOpenClosePara, decltype(deleter)> handler(para, deleter);
    napi_value obj = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, obj) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetUint32Property(env, obj, EVENT_KEY_STATUS, para->status);
    NapiUtils::SetStringPropertyUtf8(env, obj, EVENT_KEY_MESSAGE, para->message);
    return obj;
}

static napi_value CreateClosePara(napi_env env, void *callbackPara)
{
    auto para = reinterpret_cast<OnOpenClosePara *>(callbackPara);
    auto deleter = [](const OnOpenClosePara *p) { delete p; };
    std::unique_ptr<OnOpenClosePara, decltype(deleter)> handler(para, deleter);
    napi_value obj = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, obj) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetUint32Property(env, obj, EVENT_KEY_CODE, para->status);
    NapiUtils::SetStringPropertyUtf8(env, obj, EVENT_KEY_REASON, para->message);
    return obj;
}

static napi_value CreateMessagePara(napi_env env, void *callbackPara)
{
    auto manager = reinterpret_cast<EventManager *>(callbackPara);
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        return NapiUtils::GetUndefined(env);
    }
    auto msg = reinterpret_cast<WebSocketRecvMessage *>(manager->GetQueueData());
    if (!msg) {
        NETSTACK_LOGE("msg is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    napi_value result = NapiUtils::GetUndefined(env);
    if (msg->isBinary) {
        void *data = nullptr;
        auto arrayBuffer = NapiUtils::CreateArrayBuffer(env, msg->data.size(), &data);
        if (data != nullptr && NapiUtils::ValueIsArrayBuffer(env, arrayBuffer) &&
            memcpy_s(data, msg->data.size(), msg->data.data(), msg->data.size()) >= 0) {
            result = arrayBuffer;
        }
    } else {
        result = NapiUtils::CreateStringUtf8(env, msg->data);
    }
    delete msg;
    return result;
}

void WebSocketExec::OnError(EventManager *manager, int32_t code, uint32_t httpResponse)
{
    NETSTACK_LOGI("OnError %{public}d", code);
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    if (!manager->HasEventListener(EventName::EVENT_ERROR)) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_ERROR);
        return;
    }
    auto pair = new std::pair<int, uint32_t>;
    pair->first = code;
    pair->second = httpResponse;
    manager->EmitByUvWithoutCheckShared(EventName::EVENT_ERROR, pair, CallbackTemplate<CreateError>);
}

napi_value CreateResponseHeader(napi_env env, void *callbackPara)
{
    auto para = reinterpret_cast<std::map<std::string, std::string> *>(callbackPara);
    if (para == nullptr) {
        return NapiUtils::GetUndefined(env);
    }
    auto deleter = [](const std::map<std::string, std::string> *p) {
        delete p;
        p = nullptr;
    };
    std::unique_ptr<std::map<std::string, std::string>, decltype(deleter)> handler(para, deleter);
    napi_value header = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, header) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    for (const auto &singleHeader : *para) {
        NapiUtils::SetStringPropertyUtf8(env, header, singleHeader.first, singleHeader.second);
    }
    return header;
}

void WebSocketExec::OnOpen(EventManager *manager, uint32_t status, const std::string &message)
{
    NETSTACK_LOGI("OnOpen %{public}u %{public}s", status, message.c_str());
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    if (!manager->HasEventListener(EventName::EVENT_OPEN)) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_OPEN);
        return;
    }
    auto para = new OnOpenClosePara;
    para->status = status;
    para->message = message;
    manager->EmitByUvWithoutCheckShared(EventName::EVENT_OPEN, para, CallbackTemplate<CreateOpenPara>);
}

void WebSocketExec::OnClose(EventManager *manager, lws_close_status closeStatus, const std::string &closeReason)
{
    NETSTACK_LOGI("OnClose %{public}u %{public}s", closeStatus, closeReason.c_str());
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    if (!manager->HasEventListener(EventName::EVENT_CLOSE)) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_CLOSE);
        return;
    }
    auto para = new OnOpenClosePara;
    para->status = closeStatus;
    para->message = closeReason;
    manager->EmitByUvWithoutCheckShared(EventName::EVENT_CLOSE, para, CallbackTemplate<CreateClosePara>);
}

void WebSocketExec::OnMessage(EventManager *manager, void *data, size_t length, bool isBinary, bool isFinal)
{
    NETSTACK_LOGD("OnMessage %{public}d", isBinary);
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    if (!manager->HasEventListener(EventName::EVENT_MESSAGE)) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_MESSAGE);
        return;
    }
    if (length > INT32_MAX) {
        NETSTACK_LOGE("data length too long");
        return;
    }
    HandleRcvMessage(manager, data, length, isBinary, isFinal);
}

void WebSocketExec::HandleRcvMessage(EventManager *manager, void *data, size_t length, bool isBinary, bool isFinal)
{
    if (isBinary) {
        manager->AppendWebSocketBinaryData(data, length);
        if (isFinal) {
            const std::string &msgFromManager = manager->GetWebSocketBinaryData();
            auto msg = new (std::nothrow) WebSocketRecvMessage();
            if (msg == nullptr) {
                return;
            }
            msg->data.append(msgFromManager.data(), msgFromManager.size());
            msg->isBinary = true;
            manager->SetQueueData(msg);
            manager->EmitByUvWithoutCheckShared(EventName::EVENT_MESSAGE, manager,
                                                CallbackTemplate<CreateMessagePara>);
            manager->ClearWebSocketBinaryData();
        }
    } else {
        manager->AppendWebSocketTextData(data, length);
        if (isFinal) {
            const std::string &msgFromManager = manager->GetWebSocketTextData();
            auto msg = new (std::nothrow) WebSocketRecvMessage();
            if (msg == nullptr) {
                return;
            }
            msg->data.append(msgFromManager.data(), msgFromManager.size());
            msg->isBinary = false;
            manager->SetQueueData(msg);
            manager->EmitByUvWithoutCheckShared(EventName::EVENT_MESSAGE, manager,
                                                CallbackTemplate<CreateMessagePara>);
            manager->ClearWebSocketTextData();
        }
    }
}

void WebSocketExec::OnHeaderReceive(EventManager *manager, const std::map<std::string, std::string> &headers)
{
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }

    if (!manager->HasEventListener(EventName::EVENT_HEADER_RECEIVE)) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_HEADER_RECEIVE);
        return;
    }
    auto para = new std::map<std::string, std::string>(headers);
    manager->EmitByUvWithoutCheckShared(EventName::EVENT_HEADER_RECEIVE, para, CallbackTemplate<CreateResponseHeader>);
}

void WebSocketExec::GetWebsocketProxyInfo(ConnectContext *context, std::string &host, uint32_t &port,
                                          std::string &exclusions)
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
} // namespace OHOS::NetStack::Websocket
