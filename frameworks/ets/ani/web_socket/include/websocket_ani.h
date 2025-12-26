/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef NET_WEB_SOCKET_ANI_H
#define NET_WEB_SOCKET_ANI_H

#include <cstdint>
#include <memory>
#include <string>

#include "cxx.h"
#include "websocket_client_innerapi.h"
#include "websocket_server_innerapi.h"

namespace OHOS {
namespace NetStackAni {

struct AniConnectOptions;
struct AniCloseOption;
struct AniServerConfig;
struct AniServerConfigCert;
struct AniWebSocketConnection;

class WebSocketClientWrapper {
public:
    WebSocketClientWrapper();
    ~WebSocketClientWrapper();
    std::shared_ptr<NetStack::WebSocketClient::WebSocketClient> client = nullptr;
};

std::unique_ptr<WebSocketClientWrapper> CreateWebSocket();
int32_t Connect(WebSocketClientWrapper &client,
                const rust::str url, AniConnectOptions options);

void SetCaPath(WebSocketClientWrapper &client,
               const rust::str caPath);
void SetClientCert(WebSocketClientWrapper &client,
                   const rust::str clientCert, const rust::str clientKey);
void SetCertPassword(WebSocketClientWrapper &client,
                     const rust::str password);

int32_t Send(WebSocketClientWrapper &client,
             const rust::Vec<uint8_t> data, int32_t dataType);
int32_t Close(WebSocketClientWrapper &client,
              AniCloseOption options);

int32_t RegisterOpenCallback(WebSocketClientWrapper &client);
int32_t RegisterMessageCallback(WebSocketClientWrapper &client);
int32_t RegisterCloseCallback(WebSocketClientWrapper &client);
int32_t RegisterErrorCallback(WebSocketClientWrapper &client);
int32_t RegisterDataEndCallback(WebSocketClientWrapper &client);
int32_t RegisterHeaderReceiveCallback(WebSocketClientWrapper &client);

int32_t UnregisterOpenCallback(WebSocketClientWrapper &client);
int32_t UnregisterMessageCallback(WebSocketClientWrapper &client);
int32_t UnregisterCloseCallback(WebSocketClientWrapper &client);
int32_t UnregisterErrorCallback(WebSocketClientWrapper &client);
int32_t UnregisterDataEndCallback(WebSocketClientWrapper &client);
int32_t UnregisterHeaderReceiveCallback(WebSocketClientWrapper &client);

/**
 * @brief server
 */
std::unique_ptr<NetStack::WebSocketServer::WebSocketServer> CreateWebSocketServer();
int32_t StartServer(NetStack::WebSocketServer::WebSocketServer &server,
                    AniServerConfig options);
int32_t StopServer(NetStack::WebSocketServer::WebSocketServer &server);
int32_t SendServerData(NetStack::WebSocketServer::WebSocketServer &server,
                       const rust::Vec<uint8_t> data,
                       const AniWebSocketConnection &connection,
                       int32_t dataType);
int32_t CloseServer(NetStack::WebSocketServer::WebSocketServer &server,
                    const AniWebSocketConnection &connection,
                    AniCloseOption options);
int32_t ListAllConnections(NetStack::WebSocketServer::WebSocketServer &server,
                           rust::Vec<AniWebSocketConnection> &connections);

int32_t RegisterServerErrorCallback(NetStack::WebSocketServer::WebSocketServer &server);
int32_t RegisterServerConnectCallback(NetStack::WebSocketServer::WebSocketServer &server);
int32_t RegisterServerCloseCallback(NetStack::WebSocketServer::WebSocketServer &server);
int32_t RegisterServerMessageReceiveCallback(NetStack::WebSocketServer::WebSocketServer &server);

int32_t UnregisterServerErrorCallback(NetStack::WebSocketServer::WebSocketServer &server);
int32_t UnregisterServerConnectCallback(NetStack::WebSocketServer::WebSocketServer &server);
int32_t UnregisterServerCloseCallback(NetStack::WebSocketServer::WebSocketServer &server);
int32_t UnregisterServerMessageReceiveCallback(NetStack::WebSocketServer::WebSocketServer &server);

} // namespace NetStackAni
} // namespace OHOS

#endif