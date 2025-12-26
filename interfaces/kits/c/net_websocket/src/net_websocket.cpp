/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <cstring>
#include <iostream>

#include "net_websocket.h"
#include "net_websocket_adapter.h"
#include "netstack_log.h"
#include "websocket_client_innerapi.h"

using namespace OHOS::NetStack::WebSocketClient;

const int MAX_CLIENT_SIZE = 100;

void OH_NetStack_OnMessageCallback(WebSocketClient *ptrInner, const std::string &data, size_t length)
{
    NETSTACK_LOGD("websocket CAPI Message Callback");
    WebSocket *OH_client = GetNdkClientAdapter(ptrInner);
    if (OH_client == nullptr) {
        return;
    }
    OH_client->onMessage(OH_client, const_cast<char *>(data.c_str()), length);
}

void OH_NetStack_OnCloseCallback(WebSocketClient *ptrInner, CloseResult closeResult)
{
    NETSTACK_LOGD("websocket CAPI Close Callback");
    struct WebSocket_CloseResult OH_CloseResult;
    Conv2CloseResult(closeResult, &OH_CloseResult);
    WebSocket *OH_client = GetNdkClientAdapter(ptrInner);
    if (OH_client == nullptr) {
        return;
    }
    OH_client->onClose(OH_client, OH_CloseResult);
}

void OH_NetStack_OnErrorCallback(WebSocketClient *ptrInner, ErrorResult error)
{
    NETSTACK_LOGD("websocket CAPI Error Callback");
    struct WebSocket_ErrorResult OH_ErrorResult;
    Conv2ErrorResult(error, &OH_ErrorResult);
    WebSocket *OH_client = GetNdkClientAdapter(ptrInner);
    if (OH_client == nullptr) {
        return;
    }
    OH_client->onError(OH_client, OH_ErrorResult);
}

void OH_NetStack_OnOpenCallback(WebSocketClient *ptrInner, OpenResult openResult)
{
    NETSTACK_LOGD("websocket CAPI Open Callback");
    struct WebSocket_OpenResult OH_OpenResult;
    Conv2OpenResult(openResult, &OH_OpenResult);
    WebSocket *OH_client = GetNdkClientAdapter(ptrInner);
    if (OH_client == nullptr) {
        return;
    }
    OH_client->onOpen(OH_client, OH_OpenResult);
}

struct WebSocket *OH_WebSocketClient_Constructor(WebSocket_OnOpenCallback onOpen, WebSocket_OnMessageCallback onMessage,
                                                 WebSocket_OnErrorCallback onError, WebSocket_OnCloseCallback onclose)
{
    WebSocket *OH_client = new WebSocket;
    WebSocketClient *websocketClient = new WebSocketClient();
    OH_client->onMessage = onMessage;
    OH_client->onClose = onclose;
    OH_client->onError = onError;
    OH_client->onOpen = onOpen;
    websocketClient->Registcallback(OH_NetStack_OnOpenCallback, OH_NetStack_OnMessageCallback,
                                    OH_NetStack_OnErrorCallback, OH_NetStack_OnCloseCallback);
    if (g_clientMap.size() == MAX_CLIENT_SIZE) {
        delete OH_client;
        OH_client = nullptr;
        delete websocketClient;
        websocketClient = nullptr;
        return nullptr;
    }

    OH_client->requestOptions.headers = nullptr;
    g_clientMap[OH_client] = websocketClient;
    return OH_client;
}

int OH_WebSocketClient_AddHeader(struct WebSocket *client, struct WebSocket_Header header)
{
    NETSTACK_LOGD("websocket CAPI AddHeader");
    if (client == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_CLIENT_IS_NULL;
    }
    auto newHeader = std::make_unique<struct WebSocket_Header>();
    if (newHeader == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_CONNECTION_ERROR;
    } else {
        newHeader->fieldName = header.fieldName;
        newHeader->fieldValue = header.fieldValue;
        newHeader->next = NULL;
        struct WebSocket_Header *currentHeader = client->requestOptions.headers;
        if (currentHeader == nullptr) {
            client->requestOptions.headers = newHeader.release();
        } else {
            while (currentHeader->next != NULL) {
                currentHeader = currentHeader->next;
            }
            currentHeader->next = newHeader.release();
        }
        return 0;
    }
}

int OH_WebSocketClient_Send(struct WebSocket *client, char *data, size_t length)
{
    int ret;
    if (client == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_CLIENT_IS_NULL;
    }
    WebSocketClient *websocketClient = GetInnerClientAdapter(client);

    if (websocketClient == NULL) {
        return WebSocketErrorCode::WEBSOCKET_CLIENT_IS_NOT_CREAT;
    }

    ret = websocketClient->Send(data, length);
    return ret;
}

int OH_WebSocketClient_Connect(struct WebSocket *client, const char *url, struct WebSocket_RequestOptions options)
{
    NETSTACK_LOGI("websocket CAPI Connect");
    int ret = 0;
    if (client == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_CLIENT_IS_NULL;
    }

    struct OpenOptions openOptions;
    openOptions.headers = {};

    if (options.headers != nullptr) {
        Conv2RequestOptions(&openOptions, options);
    }

    WebSocketClient *websocketClient = GetInnerClientAdapter(client);

    if (websocketClient == NULL) {
        return WebSocketErrorCode::WEBSOCKET_CLIENT_IS_NOT_CREAT;
    }

    std::string connectUrl = std::string(url);
    ret = websocketClient->Connect(connectUrl, openOptions);
    NETSTACK_LOGD("websocket CAPI Connect,ret=%{public}d", ret);
    return ret;
}

int OH_WebSocketClient_Close(struct WebSocket *client, struct WebSocket_CloseOption options)
{
    int ret = 0;

    if (client == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_CLIENT_IS_NULL;
    }

    WebSocketClient *websocketClient = GetInnerClientAdapter(client);
    if (websocketClient == NULL) {
        return WebSocketErrorCode::WEBSOCKET_CLIENT_IS_NOT_CREAT;
    }

    struct CloseOption closeOption;
    Conv2CloseOptions(&closeOption, options);
    ret = websocketClient->Close(closeOption);
    return ret;
}

void OH_WebSocketClient_FreeHeader(struct WebSocket_Header *header)
{
    if (header == nullptr) {
        return;
    }
    OH_WebSocketClient_FreeHeader(header->next);
    free(header);
}

int OH_WebSocketClient_Destroy(struct WebSocket *client)
{
    NETSTACK_LOGI("websocket CAPI Destroy");
    int ret = 0;
    if (client == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_CLIENT_IS_NULL;
    }
    WebSocketClient *websocketClient = GetInnerClientAdapter(client);
    if (websocketClient == NULL) {
        return WebSocketErrorCode::WEBSOCKET_CLIENT_IS_NOT_CREAT;
    }
    ret = websocketClient->Destroy();

    OH_WebSocketClient_FreeHeader(client->requestOptions.headers);

    g_clientMap.erase(client);
    return ret;
}