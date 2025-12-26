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
#ifndef NATIVE_WEBSOCKET_ADAPTER_H
#define NATIVE_WEBSOCKET_ADAPTER_H

#include "net_websocket.h"
#include "websocket_client_innerapi.h"

namespace OHOS::NetStack::WebSocketClient {

extern std::map<WebSocket *, WebSocketClient *> g_clientMap;

WebSocketClient *GetInnerClientAdapter(WebSocket *key);
WebSocket *GetNdkClientAdapter(const WebSocketClient *websocketClient);

int32_t Conv2RequestOptions(struct OpenOptions *openOptions,
                            struct WebSocket_RequestOptions requestOptions);
int32_t Conv2CloseOptions(struct CloseOption *closeOption,
                          struct WebSocket_CloseOption requestOptions);
int32_t Conv2CloseResult(struct CloseResult closeResult,
                         struct WebSocket_CloseResult *webSocketCloseResult);
int32_t Conv2ErrorResult(struct ErrorResult error, struct WebSocket_ErrorResult *webSocketErrorResult);
int32_t Conv2OpenResult(struct OpenResult openResult, struct WebSocket_OpenResult *webSocketOpenResult);

} // namespace OHOS::NetStack::WebSocketClient
#endif /* NATIVE_WEBSOCKET_ADAPTER_H */