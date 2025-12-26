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

#ifndef NET_WEBSOCKET_IMPL_H
#define NET_WEBSOCKET_IMPL_H

#include <functional>
#include <map>
#include <queue>

#include "ffi_remote_data.h"
#include "ffi_structs.h"
#include "net_websocket_connect_context.h"
#include "net_websocket_send_context.h"
#include "net_websocket_close_context.h"
#include "cj_lambda.h"
#include "constant.h"

namespace OHOS::NetStack::NetWebSocket {

class WebSocketContext;

using WebSocketCallback = std::function<void(CWebSocketCallbackData *)>;

class CJWebsocketProxy : public OHOS::FFI::FFIData {
    DECL_TYPE(CJWebsocketProxy, OHOS::FFI::FFIData);
    
public:
    std::shared_ptr<NetWebSocket::WebSocketContext> GetWebSocketContext();
    void SetWebSocketContext(const std::shared_ptr<NetWebSocket::WebSocketContext> &websocketContext);
    void EmitCallBack(CWebSocketCallbackData *data);

    const std::string &GetWebSocketTextData();

    void AppendWebSocketTextData(void *data, size_t length);

    const std::string &GetWebSocketBinaryData();

    void AppendWebSocketBinaryData(void *data, size_t length);

    void SetQueueData(void *data);

    void *GetQueueData();

    void ClearWebSocketTextData();

    void ClearWebSocketBinaryData();

    void AddCallback2Map(int32_t type, WebSocketCallback callback);
    
    void DelCallback(int32_t type);
    
    std::optional<WebSocketCallback> FindCallback(int32_t type);
private:
    std::queue<void *> dataQueue_;
    std::string webSocketTextData_;
    std::string webSocketBinaryData_;
    std::mutex dataQueueMutex_;

    std::map<int32_t, WebSocketCallback> eventMap_;
    std::mutex mutex_;
    std::mutex contextMutex_;
    std::shared_ptr<NetWebSocket::WebSocketContext> webSocketContext_;
};

class CJWebsocketImpl {
public:
    static WebSocketConnectContext* Connect(std::string url, CWebSocketRequestOptions* opt, CJWebsocketProxy *proxy);
    
    static WebSocketSendContext* Send(CArrUI8 data, CJWebsocketProxy *proxy, bool stringType);

    static WebSocketCloseContext* Close(CWebSocketCloseOptions* opt, CJWebsocketProxy *proxy);

    static bool OnWithProxy(int32_t typeId, void (*callback)(CWebSocketCallbackData *data), CJWebsocketProxy *proxy);

    static bool OffWithProxy(int32_t typeId, CJWebsocketProxy *proxy);
};
}
#endif