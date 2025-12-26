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

#include "websocket_ani.h"

#include "secure_char.h"
#include "wrapper.rs.h"
#include <memory>
#include <map>

namespace OHOS {
namespace NetStackAni {

static std::map<NetStack::WebSocketClient::WebSocketClient*, WebSocketClientWrapper*> clientMap;
static constexpr const int COMMON_ERROR_CODE = 200;
static constexpr const int PARSE_ERROR_CODE = 401;
static constexpr const int WEBSOCKET_CONNECTION_ERROR = 1003;
static constexpr const int WEBSOCKET_UNKNOWN_OTHER_ERROR = 2302999;

WebSocketClientWrapper::WebSocketClientWrapper()
{
    client = std::make_shared<NetStack::WebSocketClient::WebSocketClient>();
    clientMap[client.get()] = this;
}

WebSocketClientWrapper::~WebSocketClientWrapper()
{
    clientMap.erase(client.get());
}

std::unique_ptr<WebSocketClientWrapper> CreateWebSocket()
{
    return std::make_unique<WebSocketClientWrapper>();
}

int32_t Connect(WebSocketClientWrapper &client, const rust::str url, AniConnectOptions options)
{
    NetStack::WebSocketClient::OpenOptions openOptions;
    bool isValue = false;
    std::string key;
    std::string value;
    for (const auto &item : options.headers) {
        if (isValue) {
            value = std::string(item);
            openOptions.headers.insert(std::make_pair(key, value));
            isValue = false;
        } else {
            key = std::string(item);
            isValue = true;
        }
    }
    return client.client->ConnectEx(std::string(url), openOptions);
}

void SetCaPath(WebSocketClientWrapper &client, const rust::str caPath)
{
    auto context = client.client->GetClientContext();
    context->SetUserCertPath(std::string(caPath));
}

void SetClientCert(WebSocketClientWrapper &client, const rust::str clientCert,
    const rust::str clientKey)
{
    auto context = client.client->GetClientContext();
    context->clientCert = std::string(clientCert);
    context->clientKey = NetStack::Secure::SecureChar(std::string(clientKey));
}

void SetCertPassword(WebSocketClientWrapper &client, const rust::str password)
{
    auto context = client.client->GetClientContext();
    context->keyPassword = NetStack::Secure::SecureChar(std::string(password));
}

int32_t Send(WebSocketClientWrapper &client, const rust::Vec<uint8_t> data, int32_t dataType)
{
    if ((data.size() == 0 || data.data() == nullptr) && dataType == 1) {
        return PARSE_ERROR_CODE;
    }
    return client.client->SendEx((char*)data.data(), data.size());
}

int32_t Close(WebSocketClientWrapper &client, AniCloseOption options)
{
    NetStack::WebSocketClient::CloseOption closeOption{
        .code = options.code,
        .reason = options.reason.data(),
    };
    int ret = client.client->CloseEx(closeOption);
    if (ret == -1) {
        ret = WEBSOCKET_UNKNOWN_OTHER_ERROR;
    }
    return ret;
}

void OnOpenCallbackC(NetStack::WebSocketClient::WebSocketClient *client,
    NetStack::WebSocketClient::OpenResult openResult)
{
    auto iter = clientMap.find(client);
    if (iter == clientMap.end()) {
        NETSTACK_LOGE("OnOpenCallbackC can not find client");
        return;
    }
    on_open_websocket_client(*(iter->second), std::string(openResult.message), openResult.status);
}

void OnMessageCallbackC(NetStack::WebSocketClient::WebSocketClient *client, const std::string &data, size_t length)
{
    auto iter = clientMap.find(client);
    if (iter == clientMap.end()) {
        NETSTACK_LOGE("OnOpenCallbackC can not find client");
        return;
    }
    on_message_websocket_client(*(iter->second), data, length);
}

void OnCloseCallbackC(NetStack::WebSocketClient::WebSocketClient *client,
    NetStack::WebSocketClient::CloseResult closeResult)
{
    auto iter = clientMap.find(client);
    if (iter == clientMap.end()) {
        NETSTACK_LOGE("OnOpenCallbackC can not find client");
        return;
    }
    on_close_websocket_client(*(iter->second), std::string(closeResult.reason), closeResult.code);
}

void OnErrorCallbackC(NetStack::WebSocketClient::WebSocketClient *client, NetStack::WebSocketClient::ErrorResult error)
{
    auto iter = clientMap.find(client);
    if (iter == clientMap.end()) {
        NETSTACK_LOGE("OnOpenCallbackC can not find client");
        return;
    }
    if (error.errorCode == WEBSOCKET_CONNECTION_ERROR) {
        error.errorCode = COMMON_ERROR_CODE;
    }
    on_error_websocket_client(*(iter->second), std::string(error.errorMessage), error.errorCode);
}

void OnDataEndCallbackC(NetStack::WebSocketClient::WebSocketClient *client)
{
    auto iter = clientMap.find(client);
    if (iter == clientMap.end()) {
        NETSTACK_LOGE("OnOpenCallbackC can not find client");
        return;
    }
    on_data_end_websocket_client(*(iter->second));
}

void OnHeaderReceiveCallbackC(NetStack::WebSocketClient::WebSocketClient *client,
    const std::map<std::string, std::string> &headers)
{
    auto iter = clientMap.find(client);
    if (iter == clientMap.end()) {
        NETSTACK_LOGE("OnOpenCallbackC can not find client");
        return;
    }
    rust::Vec<rust::String> keys;
    rust::Vec<rust::String> values;
    for (const auto &pair : headers) {
        header_push_data(keys, rust::String(pair.first.c_str()));
        header_push_data(values, rust::String(pair.second.c_str()));
    }
    on_header_receive_websocket_client(*(iter->second), keys, values);
}

int32_t RegisterOpenCallback(WebSocketClientWrapper &client)
{
    client.client->onOpenCallback_ = &OnOpenCallbackC;
    return 0;
}

int32_t RegisterMessageCallback(WebSocketClientWrapper &client)
{
    client.client->onMessageCallback_ = &OnMessageCallbackC;
    return 0;
}

int32_t RegisterCloseCallback(WebSocketClientWrapper &client)
{
    client.client->onCloseCallback_ = &OnCloseCallbackC;
    return 0;
}

int32_t RegisterErrorCallback(WebSocketClientWrapper &client)
{
    client.client->onErrorCallback_ = &OnErrorCallbackC;
    return 0;
}

int32_t RegisterDataEndCallback(WebSocketClientWrapper &client)
{
    client.client->onDataEndCallback_ = &OnDataEndCallbackC;
    return 0;
}

int32_t RegisterHeaderReceiveCallback(WebSocketClientWrapper &client)
{
    client.client->onHeaderReceiveCallback_ = &OnHeaderReceiveCallbackC;
    return 0;
}

int32_t UnregisterOpenCallback(WebSocketClientWrapper &client)
{
    client.client->onOpenCallback_ = nullptr;
    return 0;
}

int32_t UnregisterMessageCallback(WebSocketClientWrapper &client)
{
    client.client->onMessageCallback_ = nullptr;
    return 0;
}

int32_t UnregisterCloseCallback(WebSocketClientWrapper &client)
{
    client.client->onCloseCallback_ = nullptr;
    return 0;
}

int32_t UnregisterHeaderReceiveCallback(WebSocketClientWrapper &client)
{
    client.client->onHeaderReceiveCallback_ = nullptr;
    return 0;
}

int32_t UnregisterErrorCallback(WebSocketClientWrapper &client)
{
    client.client->onErrorCallback_ = nullptr;
    return 0;
}

int32_t UnregisterDataEndCallback(WebSocketClientWrapper &client)
{
    client.client->onDataEndCallback_ = nullptr;
    return 0;
}

/* *
 * @brief server
 */
std::unique_ptr<NetStack::WebSocketServer::WebSocketServer> CreateWebSocketServer()
{
    return std::make_unique<NetStack::WebSocketServer::WebSocketServer>();
}

int32_t StartServer(NetStack::WebSocketServer::WebSocketServer &server, AniServerConfig options)
{
    NetStack::WebSocketServer::ServerCert serverCert{
        .certPath = options.serverCert.certPath.c_str(),
        .keyPath = options.serverCert.keyPath.c_str()
    };
    NetStack::WebSocketServer::ServerConfig severCfg{
        .serverIP = options.serverIP.c_str(),
        .serverPort = options.serverPort,
        .serverCert = serverCert,
        .maxConcurrentClientsNumber = options.maxConcurrentClientsNumber,
        .protocol = options.protocol.c_str(),
        .maxConnectionsForOneClient = options.maxConnectionsForOneClient
    };
    return server.Start(severCfg);
}

int32_t StopServer(NetStack::WebSocketServer::WebSocketServer &server)
{
    return server.Stop();
}

int32_t CloseServer(NetStack::WebSocketServer::WebSocketServer &server, const AniWebSocketConnection &connection,
    AniCloseOption options)
{
    std::string strIP(get_web_socket_connection_client_ip(connection).c_str());
    int32_t iPort = get_web_socket_connection_client_port(connection);
    NetStack::WebSocketServer::SocketConnection socketConn{
        .clientIP = strIP,
        .clientPort = static_cast<uint32_t>(iPort),
    };
    NetStack::WebSocketServer::CloseOption closeOpt{
        .code = options.code,
        .reason = options.reason.data(),
    };
    return server.Close(socketConn, closeOpt);
}

int32_t SendServerData(NetStack::WebSocketServer::WebSocketServer &server, const rust::Vec<uint8_t> data,
    const AniWebSocketConnection &connection, int32_t dataType)
{
    if ((data.size() == 0 || data.data() == nullptr) && dataType == 1) {
        return PARSE_ERROR_CODE;
    }
    std::string strIP(get_web_socket_connection_client_ip(connection).c_str());
    int32_t iPort = get_web_socket_connection_client_port(connection);
    NetStack::WebSocketServer::SocketConnection socketConn{
        .clientIP = strIP,
        .clientPort = static_cast<uint32_t>(iPort),
    };
    return server.Send((char*)(data.data()), data.size(), socketConn);
}

int32_t ListAllConnections(NetStack::WebSocketServer::WebSocketServer &server,
    rust::Vec<AniWebSocketConnection> &connections)
{
    int32_t iRet;
    std::vector<NetStack::WebSocketServer::SocketConnection> connectionList;
    iRet = server.ListAllConnections(connectionList);
    if (iRet != 0) {
        return iRet;
    }

    for (size_t i = 0; i < connectionList.size(); ++i) {
        std::string strIP = connectionList[i].clientIP;
        int32_t iPort = static_cast<int32_t>(connectionList[i].clientPort);
        socket_connection_push_data(connections, rust::String(strIP.c_str()), rust::i32(iPort));
    }

    return iRet;
}

void OnErrorCallbackServerC(NetStack::WebSocketServer::WebSocketServer *server,
    NetStack::WebSocketServer::ErrorResult error)
{
    on_error_websocket_server(*server, std::string(error.errorMessage), error.errorCode);
}

void OnConnectCallbackServerC(NetStack::WebSocketServer::WebSocketServer *server,
    NetStack::WebSocketServer::SocketConnection connection)
{
    on_connect_websocket_server(*server, std::string(connection.clientIP), connection.clientPort);
}

void OnCloseCallbackServerC(NetStack::WebSocketServer::WebSocketServer *server,
    NetStack::WebSocketServer::CloseResult result, NetStack::WebSocketServer::SocketConnection connection)
{
    on_close_websocket_server(*server, std::string(result.reason), result.code, std::string(connection.clientIP),
        connection.clientPort);
}

void OnMessageReceiveCallbackServerC(NetStack::WebSocketServer::WebSocketServer *server, const std::string &data,
    size_t length, NetStack::WebSocketServer::SocketConnection connection)
{
    on_message_receive_websocket_server(*server, data, length, std::string(connection.clientIP), connection.clientPort);
}

int32_t RegisterServerErrorCallback(NetStack::WebSocketServer::WebSocketServer &server)
{
    server.onErrorCallback_ = &OnErrorCallbackServerC;
    return 0;
}

int32_t RegisterServerConnectCallback(NetStack::WebSocketServer::WebSocketServer &server)
{
    server.onConnectCallback_ = &OnConnectCallbackServerC;
    return 0;
}

int32_t RegisterServerCloseCallback(NetStack::WebSocketServer::WebSocketServer &server)
{
    server.onCloseCallback_ = &OnCloseCallbackServerC;
    return 0;
}

int32_t RegisterServerMessageReceiveCallback(NetStack::WebSocketServer::WebSocketServer &server)
{
    server.onMessageReceiveCallback_ = &OnMessageReceiveCallbackServerC;
    return 0;
}

int32_t UnregisterServerErrorCallback(NetStack::WebSocketServer::WebSocketServer &server)
{
    server.onErrorCallback_ = nullptr;
    return 0;
}

int32_t UnregisterServerConnectCallback(NetStack::WebSocketServer::WebSocketServer &server)
{
    server.onConnectCallback_ = nullptr;
    return 0;
}

int32_t UnregisterServerCloseCallback(NetStack::WebSocketServer::WebSocketServer &server)
{
    server.onCloseCallback_ = nullptr;
    return 0;
}

int32_t UnregisterServerMessageReceiveCallback(NetStack::WebSocketServer::WebSocketServer &server)
{
    server.onMessageReceiveCallback_ = nullptr;
    return 0;
}
} // namespace NetStackAni
} // namespace OHOS