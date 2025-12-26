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

#include "server_send_context.h"

#include "constant.h"
#include "netstack_log.h"
#include "napi_utils.h"
#include "securec.h"

static constexpr size_t MAX_LIMIT = 5 * 1024 * 1024;
namespace OHOS::NetStack::Websocket {
ServerSendContext::ServerSendContext(napi_env env, const std::shared_ptr<EventManager> &manager)
    : BaseContext(env, manager), data(nullptr), length(0), protocol(LWS_WRITE_TEXT), connection() {}

ServerSendContext::~ServerSendContext() = default;

void ServerSendContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsType(params, paramsCount)) {
        NETSTACK_LOGE("SendContext Parse Failed");
        if (paramsCount == FUNCTION_PARAM_ONE) {
            if (NapiUtils::GetValueType(GetEnv(), params[0]) == napi_object) {
                SetCallback(params[0]);
            }
            return;
        }

        if (paramsCount == FUNCTION_PARAM_TWO) {
            if (NapiUtils::GetValueType(GetEnv(), params[1]) == napi_object) {
                SetCallback(params[1]);
            }
            return;
        }
        return;
    }

    if (NapiUtils::GetValueType(GetEnv(), params[0]) == napi_string) {
        if (!HandleParseString(params)) {
            NETSTACK_LOGI("HandleParseString fail");
            return;
        }
    } else {
        if (!HandleParseArrayBuffer(params)) {
            NETSTACK_LOGI("HandleParseArrayBuffer fail");
            return;
        }
    }

    if (!HandleParseConnection(GetEnv(), params[1])) {
        return;
    }
    NETSTACK_LOGD("SendContext SetParseOK");
    return SetParseOK(true);
}

bool ServerSendContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == FUNCTION_PARAM_TWO) {
        return (NapiUtils::GetValueType(GetEnv(), params[0]) == napi_string ||
            NapiUtils::ValueIsArrayBuffer(GetEnv(), params[0])) &&
            IsValidWebsocketConnection(GetEnv(), params[1]);
    }
    return false;
}

bool ServerSendContext::IsValidWebsocketConnection(napi_env env, napi_value params)
{
    NETSTACK_LOGI("IsValidWebsocketConnection enter");
    if (NapiUtils::GetValueType(env, params) != napi_object) {
        return false;
    }
    return (NapiUtils::GetValueType(env, NapiUtils::GetNamedProperty(env, params,
        ContextKey::CLIENT_PORT)) == napi_number) && (NapiUtils::GetValueType(env,
        NapiUtils::GetNamedProperty(env, params, ContextKey::CLIENT_IP)) == napi_string);
}

bool ServerSendContext::HandleParseString(napi_value *params)
{
    NETSTACK_LOGI("Server SendContext data is String");
    std::string str = NapiUtils::GetStringFromValueUtf8(GetEnv(), params[0]);
    // must have PRE and POST
    size_t dataLen = LWS_SEND_BUFFER_PRE_PADDING + str.length() + LWS_SEND_BUFFER_POST_PADDING;
    if (dataLen == 0 || dataLen > MAX_LIMIT) {
        NETSTACK_LOGE("ServerSendContext data is exceeded the limit");
        return false;
    }
    data = malloc(dataLen);
    if (data == nullptr) {
        NETSTACK_LOGE("no memory");
        return false;
    }
    if (memcpy_s(reinterpret_cast<void *>(reinterpret_cast<uint8_t *>(data) + LWS_SEND_BUFFER_PRE_PADDING),
        str.length(), str.c_str(), str.length()) < 0) {
        NETSTACK_LOGE("copy failed");
        free(data);
        return false;
    }
    length = str.length();
    protocol = LWS_WRITE_TEXT;
    return true;
}

bool ServerSendContext::HandleParseArrayBuffer(napi_value *params)
{
    NETSTACK_LOGI("ServerSendContext data is ArrayBuffer");
    size_t len = 0;
    void *mem = NapiUtils::GetInfoFromArrayBufferValue(GetEnv(), params[0], &len);
    if (mem == nullptr && len != 0) {
        NETSTACK_LOGE("Get info error");
        return false;
    }
    // must have PRE and POST
    size_t dataLen = LWS_SEND_BUFFER_PRE_PADDING + len + LWS_SEND_BUFFER_POST_PADDING;
    if (dataLen == 0 || dataLen > MAX_LIMIT) {
        NETSTACK_LOGE("ServerSendContext data is exceeded the limit");
        return false;
    }
    data = malloc(dataLen);
    if (data == nullptr) {
        NETSTACK_LOGE("no memory");
        return false;
    }
    if (memcpy_s(reinterpret_cast<void *>(reinterpret_cast<uint8_t *>(data) + LWS_SEND_BUFFER_PRE_PADDING), len, mem,
        len) < 0) {
        NETSTACK_LOGE("copy failed");
        free(data);
        return false;
    }
    length = len;
    protocol = LWS_WRITE_BINARY;
    return true;
}

bool ServerSendContext::HandleParseConnection(napi_env env, napi_value params)
{
    NETSTACK_LOGI("parse websocketconnection enter");
    if (NapiUtils::GetValueType(env, params) == napi_object) {
        uint32_t port = NapiUtils::GetUint32Property(env, params, ContextKey::CLIENT_PORT);
        if (port == 0) {
            NETSTACK_LOGE("parse clientPort error");
        }
        std::string ip = NapiUtils::GetStringPropertyUtf8(env, params, ContextKey::CLIENT_IP);
        if (ip == "") {
            NETSTACK_LOGE("parse clientIP error");
        }
        SetClientWebSocketConn(port, ip);
        return true;
    }
    return false;
}

void ServerSendContext::SetClientWebSocketConn(uint32_t &port, std::string &ip)
{
    connection.clientPort = port;
    connection.clientIP = ip;
}

WebSocketConnection ServerSendContext::GetConnection() const
{
    return connection;
}

int32_t ServerSendContext::GetErrorCode() const
{
    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_CODE;
    }

    auto err = BaseContext::GetErrorCode();
    if (err == PARSE_ERROR_CODE) {
        return PARSE_ERROR_CODE;
    }
    if (WEBSOCKET_ERR_MAP.find(err) != WEBSOCKET_ERR_MAP.end()) {
        return err;
    }
    return WEBSOCKET_CONNECT_FAILED;
}

std::string ServerSendContext::GetErrorMessage() const
{
    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_MSG;
    }

    auto err = BaseContext::GetErrorCode();
    if (err == PARSE_ERROR_CODE) {
        return PARSE_ERROR_MSG;
    }
    auto it = WEBSOCKET_ERR_MAP.find(err);
    if (it != WEBSOCKET_ERR_MAP.end()) {
        return it->second;
    }
    it = WEBSOCKET_ERR_MAP.find(WEBSOCKET_UNKNOWN_OTHER_ERROR);
    if (it != WEBSOCKET_ERR_MAP.end()) {
        return it->second;
    }
    return {};
}
} // namespace OHOS::NetStack::Websocket