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

#ifndef COMMUNICATIONNETSTACK_WEBSOCKET_SERVER_H
#define COMMUNICATIONNETSTACK_WEBSOCKET_SERVER_H

#include <libwebsockets.h>
#include "server_context.h"

namespace OHOS {
namespace NetStack {
namespace WebSocketServer {

class WebSocketServer {
public:
    WebSocketServer();
    ~WebSocketServer();
    typedef void (*OnErrorCallback)(WebSocketServer *server, ErrorResult error);
    typedef void (*OnConnectCallback)(WebSocketServer *server, SocketConnection connection);
    typedef void (*OnCloseCallback)(WebSocketServer *server, CloseResult result, SocketConnection connection);
    typedef void (*OnMessageReceiveCallback)(WebSocketServer *server, const std::string &data,
                                             size_t length, SocketConnection connection);

    int Start(const ServerConfig &config);
    int Stop();
    int Close(const SocketConnection &connection, const CloseOption &option);
    int Send(const char *data, int length, const SocketConnection &connection);
    int ListAllConnections(std::vector<SocketConnection> &connections) const;
    int Destroy();

    ServerContext *GetServerContext() const;

    int Registcallback(OnErrorCallback onError, OnConnectCallback onConnect,
        OnCloseCallback onClose, OnMessageReceiveCallback onMessageReceive);

    OnErrorCallback onErrorCallback_ = nullptr;
    OnConnectCallback onConnectCallback_ = nullptr;
    OnCloseCallback onCloseCallback_ = nullptr;
    OnMessageReceiveCallback onMessageReceiveCallback_ = nullptr;

private:
    ServerContext *serverContext_ = nullptr;
};
} // namespace WebSocketServer
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATIONNETSTACK_WEBSOCKET_SERVER_H