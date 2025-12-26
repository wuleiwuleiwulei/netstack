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

#include "net_websocket_send_context.h"

#include "securec.h"
#include "netstack_log.h"

namespace OHOS::NetStack::NetWebSocket {
WebSocketSendContext::WebSocketSendContext(CJWebsocketProxy *websocketProxy)
    : WebSocketBaseContext(websocketProxy), data(nullptr), length(0), protocol(LWS_WRITE_TEXT)
{
}

void WebSocketSendContext::ParseParams(CArrUI8 params, bool stringType)
{
    // set protocol
    protocol = stringType ? LWS_WRITE_TEXT : LWS_WRITE_BINARY;
    size_t len = static_cast<size_t>(params.size);
    if (len == 0) {
        NETSTACK_LOGE("no memory");
        return;
    };
    // set data
    // must have PRE and POST
    size_t dataLen = static_cast<size_t>(LWS_SEND_BUFFER_PRE_PADDING + params.size + LWS_SEND_BUFFER_POST_PADDING);
    if (dataLen == 0 || dataLen > MAX_LIMIT) {
        NETSTACK_LOGE("WebSocketSendContext data is exceeded the limit");
        return;
    }
    data = malloc(dataLen);
    if (data == nullptr) {
        NETSTACK_LOGE("no memory");
        return;
    }
    if (memcpy_s(reinterpret_cast<void *>(reinterpret_cast<uint8_t *>(data) + LWS_SEND_BUFFER_PRE_PADDING),
                 len, params.head, len) < 0) {
        NETSTACK_LOGE("copy failed");
        free(data);
        return;
    }
    // set length
    length = len;
    NETSTACK_LOGD("WebSocketSendContext SetParseOK");
    SetParseOK(true);
}

int32_t WebSocketSendContext::GetErrorCode() const
{
    if (WebSocketBaseContext::IsPermissionDenied()) {
        return WEBSOCKET_PERMISSION_DENIED_CODE;
    }
    auto err = WebSocketBaseContext::GetErrorCode();
    if (WEBSOCKET_ERR_MAP.find(err) != WEBSOCKET_ERR_MAP.end()) {
        return err;
    }
    return WEBSOCKET_CONNECT_FAILED;
}

std::string WebSocketSendContext::GetErrorMessage() const
{
    auto err = WebSocketBaseContext::GetErrorCode();
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
}