/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_WEBSOCKET_EXEC_H
#define COMMUNICATIONNETSTACK_WEBSOCKET_EXEC_H

#include "close_context.h"
#include "connect_context.h"
#include "send_context.h"

namespace OHOS::NetStack::Websocket {

class WebSocketExec final {
public:
    static bool CreatConnectInfo(ConnectContext *context, lws_context *lwsContext,
                                 const std::shared_ptr<EventManager> &manager);
    /* async work execute */
    static bool ExecConnect(ConnectContext *context);

    static bool ExecSend(SendContext *context);

    static bool ExecClose(CloseContext *context);

    /* async work callback */
    static napi_value ConnectCallback(ConnectContext *context);

    static napi_value SendCallback(SendContext *context);

    static napi_value CloseCallback(CloseContext *context);

    static int LwsCallback(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

private:
    static bool ParseUrl(ConnectContext *context, std::string &protocol, std::string &address, std::string &path,
        int &port);

    static void ParseHost(const std::string &protocol, const std::string &address, int port, std::string &host);

    static int RaiseError(EventManager *manager, uint32_t httpResponse);

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

    static void OnOpen(EventManager *manager, uint32_t status, const std::string &message);

    static void OnError(EventManager *manager, int32_t code, uint32_t httpResponse);

    static uint32_t GetHttpResponseFromWsi(lws *wsi);

    static void OnMessage(EventManager *manager, void *data, size_t length, bool isBinary, bool isFinal);

    static void OnClose(EventManager *manager, lws_close_status closeStatus, const std::string &closeReason);

    static void OnHeaderReceive(EventManager *manager, const std::map<std::string, std::string> &headers);

    static void FillContextInfo(ConnectContext *context, lws_context_creation_info &info, char *proxyAds);

    static bool FillCaPath(ConnectContext *context, lws_context_creation_info &info);

    static void GetWebsocketProxyInfo(ConnectContext *context, std::string &host, uint32_t &port,
                                      std::string &exclusions);
    static void HandleRcvMessage(EventManager *manager, void *data, size_t length, bool isBinary, bool isFinal);
};
} // namespace OHOS::NetStack::Websocket
#endif /* COMMUNICATIONNETSTACK_WEBSOCKET_EXEC_H */
