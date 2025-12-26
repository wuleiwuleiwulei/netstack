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

#include "net_websocket_close_context.h"

namespace OHOS::NetStack::NetWebSocket {
WebSocketCloseContext::WebSocketCloseContext(CJWebsocketProxy *websocketProxy)
    : WebSocketBaseContext(websocketProxy), code(CLOSE_REASON_NORMAL_CLOSE), reason("CLOSE_NORMAL")
{
}

void WebSocketCloseContext::ParseParams(CWebSocketCloseOptions *opt)
{
    if (opt != nullptr) {
        code = opt->code;
        if (opt->reason != nullptr) {
            reason = std::string{opt->reason};
        }
    }
    SetParseOK(true);
}

int32_t WebSocketCloseContext::GetErrorCode() const
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

std::string WebSocketCloseContext::GetErrorMessage() const
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