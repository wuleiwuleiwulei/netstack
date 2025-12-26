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

#ifndef NET_WEBSOCKET_EXEC_H
#define NET_WEBSOCKET_EXEC_H

#include "net_websocket_connect_context.h"
#include "net_websocket_send_context.h"
#include "net_websocket_close_context.h"
#include "libwebsockets.h"

namespace OHOS::NetStack::NetWebSocket {
class NetWebSocketExec final {
public:
    static bool CreatConnectInfo(WebSocketConnectContext *context, lws_context *lwsContext,
                                 CJWebsocketProxy *websocketProxy);
    /* async work execute */
    static bool ExecConnect(WebSocketConnectContext *context);

    static bool ExecSend(WebSocketSendContext *context);

    static bool ExecClose(WebSocketCloseContext *context);

    static int LwsCallback(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

private:
    static bool ParseUrl(WebSocketConnectContext *context, char *prefix,
                         size_t prefixLen, char *address, size_t addressLen,
                         char *path, size_t pathLen, int *port);

    static int RaiseError(CJWebsocketProxy *websocketProxy, uint32_t httpResponse);

    static int HttpDummy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackClientAppendHandshakeHeader(lws *wsi, lws_callback_reasons reason, void *user, void *in,
                                                      size_t len);

    static int LwsCallbackWsPeerInitiatedClose(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackClientWritable(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackClientConnectionError(lws *wsi, lws_callback_reasons reason, void *user, void *in,
                                                size_t len);

    static int LwsCallbackClientReceive(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackClientFilterPreEstablish(lws *wsi, lws_callback_reasons reason, void *user, void *in,
                                                   size_t len);

    static int LwsCallbackClientEstablished(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackClientClosed(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackWsiDestroy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackProtocolDestroy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackVhostCertAging(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static void OnOpen(CJWebsocketProxy *websocketProxy, uint32_t status, const std::string &message);

    static void OnError(CJWebsocketProxy *websocketProxy, int32_t code, uint32_t httpResponse);

    static uint32_t GetHttpResponseFromWsi(lws *wsi);

    static void OnMessage(CJWebsocketProxy *websocketProxy, void *data, size_t length, bool isBinary, bool isFinal);

    static void OnClose(CJWebsocketProxy *websocketProxy, lws_close_status closeStatus, const std::string &closeReason);

    static void OnDataEnd(CJWebsocketProxy *websocketProxy);

    static void OnHeaderReceive(CJWebsocketProxy *websocketProxy, const std::map<std::string, std::string> &headers);

    static void FillContextInfo(WebSocketConnectContext *context, lws_context_creation_info &info, char *proxyAds);

    static bool FillCaPath(WebSocketConnectContext *context, lws_context_creation_info &info);

    static void GetWebsocketProxyInfo(WebSocketConnectContext *context, std::string &host,
                                      uint32_t &port, std::string &exclusions);
    static void HandleRcvMessage(CJWebsocketProxy *websocketProxy, void *data,
                                 size_t length, bool isBinary, bool isFinal);
};
} // namespace OHOS::NetStack::NetWebSocket
#endif /* NET_WEBSOCKET_EXEC_H */
