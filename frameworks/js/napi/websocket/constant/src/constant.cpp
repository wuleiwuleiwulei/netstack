/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "constant.h"

namespace OHOS::NetStack::Websocket {
const char *ContextKey::HEADER = "header";

const char *ContextKey::CAPATH = "caPath";
const char *ContextKey::CLIENT_CERT = "clientCert";
const char *ContextKey::CERT_PATH = "certPath";
const char *ContextKey::KEY_PATH = "keyPath";
const char *ContextKey::KEY_PASSWD = "keyPassword";
const char *ContextKey::KEY_SKIP_SERVER_CERT_VERIFY = "skipServerCertVerification";
/* WebSocketConnection */
const char *ContextKey::CLIENT_PORT = "clientPort";
const char *ContextKey::CLIENT_IP = "clientIP";

/* WebSocketServerConfig */
const char *ContextKey::SERVER_PORT = "serverPort";
const char *ContextKey::MAX_CLIENT_NUMBER = "maxConcurrentClientsNumber";
const char *ContextKey::MAX_CONNECTIONS_FOR_ONE_CLIENT = "maxConnectionsForOneClient";
const char *ContextKey::SERVER_IP = "serverIP";
const char *ContextKey::SERVER_CERT = "serverCert";
const char *ContextKey::PROTOCOL = "protocol";
const char *ContextKey::PING_INTERVAL = "pingInterval";
const char *ContextKey::PONG_TIMEOUT = "pongTimeout";

const char *ContextKey::PROXY = "proxy";
const char *ContextKey::PROTCOL = "protocol";
const char *ContextKey::USE_SYSTEM_PROXY = "system";
const char *ContextKey::NOT_USE_PROXY = "no-proxy";

const char *ContextKey::WEBSOCKET_PROXY_HOST = "host";
const char *ContextKey::WEBSOCKET_PROXY_PORT = "port";
const char *ContextKey::WEBSOCKET_PROXY_EXCLUSION_LIST = "exclusionList";
const char *ContextKey::WEBSOCKET_PROXY_EXCLUSIONS_SEPARATOR = ",";

const char *ContextKey::CODE = "code";
const char *ContextKey::REASON = "reason";

const char *EventName::EVENT_OPEN = "open";
const char *EventName::EVENT_MESSAGE = "message";
const char *EventName::EVENT_CLOSE = "close";
const char *EventName::EVENT_ERROR = "error";
const char *EventName::EVENT_DATA_END = "dataEnd";
const char *EventName::EVENT_HEADER_RECEIVE = "headerReceive";
/* websocketServer */
const char *EventName::EVENT_SERVER_ERROR = "error";
const char *EventName::EVENT_SERVER_CONNECT = "connect";
const char *EventName::EVENT_SERVER_MESSAGE_RECEIVE = "messageReceive";
const char *EventName::EVENT_SERVER_CLOSE = "close";
} // namespace OHOS::NetStack::Websocket