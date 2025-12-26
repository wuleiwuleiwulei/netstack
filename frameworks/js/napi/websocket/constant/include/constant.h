/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_CONSTANT_H
#define COMMUNICATIONNETSTACK_CONSTANT_H

#include <map>
#include <string>

namespace OHOS::NetStack::Websocket {
enum {
    FUNCTION_PARAM_ZERO = 0,
    FUNCTION_PARAM_ONE = 1,
    FUNCTION_PARAM_TWO = 2,
    FUNCTION_PARAM_THREE = 3,
};

enum WebsocketErrorCode {
    WEBSOCKET_CONNECT_FAILED = -1,
    WEBSOCKET_ERROR_CODE_BASE = 2302000,
    WEBSOCKET_ERROR_CODE_URL_ERROR = WEBSOCKET_ERROR_CODE_BASE + 1,
    WEBSOCKET_ERROR_CODE_FILE_NOT_EXIST = WEBSOCKET_ERROR_CODE_BASE + 2,
    WEBSOCKET_ERROR_CODE_CONNECT_AlREADY_EXIST = WEBSOCKET_ERROR_CODE_BASE + 3,
    WEBSOCKET_ERROR_CODE_INVALID_NIC = WEBSOCKET_ERROR_CODE_BASE + 4,
    WEBSOCKET_ERROR_CODE_INVALID_PORT = WEBSOCKET_ERROR_CODE_BASE + 5,
    WEBSOCKET_ERROR_CODE_CONNECTION_NOT_EXIST = WEBSOCKET_ERROR_CODE_BASE + 6,
    WEBSOCKET_ERROR_CODE_PORT_ALREADY_OCCUPIED = WEBSOCKET_ERROR_CODE_BASE + 7,
    WEBSOCKET_NOT_ALLOWED_HOST = 2302998,
    WEBSOCKET_UNKNOWN_OTHER_ERROR = 2302999
};

static const std::map<int32_t, std::string> WEBSOCKET_ERR_MAP = {
    {WEBSOCKET_CONNECT_FAILED, "Websocket connect failed"},
    {WEBSOCKET_ERROR_CODE_URL_ERROR, "Websocket url error"},
    {WEBSOCKET_ERROR_CODE_FILE_NOT_EXIST, "Websocket file not exist"},
    {WEBSOCKET_ERROR_CODE_CONNECT_AlREADY_EXIST, "Websocket connection exist"},
    {WEBSOCKET_ERROR_CODE_INVALID_NIC, "Can't listen to the given NIC"},
    {WEBSOCKET_ERROR_CODE_INVALID_PORT, "Can't listen to the given Port"},
    {WEBSOCKET_ERROR_CODE_CONNECTION_NOT_EXIST, "websocket connection does not exist"},
    {WEBSOCKET_ERROR_CODE_PORT_ALREADY_OCCUPIED, "Websocket port already occupied"},
    {WEBSOCKET_NOT_ALLOWED_HOST, "It is not allowed to access this domain"},
    {WEBSOCKET_UNKNOWN_OTHER_ERROR, "Websocket Unknown Other Error"}};

enum {
    CLOSE_REASON_NORMAL_CLOSE [[maybe_unused]] = 1000,
    CLOSE_REASON_SERVER_CLOSED [[maybe_unused]] = 1001,
    CLOSE_REASON_PROTOCOL_ERROR [[maybe_unused]] = 1002,
    CLOSE_REASON_UNSUPPORT_DATA_TYPE [[maybe_unused]] = 1003,
    CLOSE_REASON_RESERVED1 [[maybe_unused]],
    CLOSE_REASON_RESERVED2 [[maybe_unused]],
    CLOSE_REASON_RESERVED3 [[maybe_unused]],
    CLOSE_REASON_RESERVED4 [[maybe_unused]],
    CLOSE_REASON_RESERVED5 [[maybe_unused]],
    CLOSE_REASON_RESERVED6 [[maybe_unused]],
    CLOSE_REASON_RESERVED7 [[maybe_unused]],
    CLOSE_REASON_RESERVED8 [[maybe_unused]],
    CLOSE_REASON_RESERVED9 [[maybe_unused]],
    CLOSE_REASON_RESERVED10 [[maybe_unused]],
    CLOSE_REASON_RESERVED11 [[maybe_unused]],
    CLOSE_REASON_RESERVED12 [[maybe_unused]],
};

enum class WebsocketProxyType {
    NOT_USE,
    USE_SYSTEM,
    USE_SPECIFIED,
};

class ContextKey final {
public:
    static const char *HEADER;

    static const char *CAPATH;
    static const char *CLIENT_CERT;
    static const char *CERT_PATH;
    static const char *KEY_PATH;
    static const char *KEY_PASSWD;
    static const char *KEY_SKIP_SERVER_CERT_VERIFY;

    static const char *PROXY;
    static const char *PROTCOL;
    static const char *USE_SYSTEM_PROXY;
    static const char *NOT_USE_PROXY;

    static const char *WEBSOCKET_PROXY_HOST;
    static const char *WEBSOCKET_PROXY_PORT;
    static const char *WEBSOCKET_PROXY_EXCLUSION_LIST;
    static const char *WEBSOCKET_PROXY_EXCLUSIONS_SEPARATOR;

    static const char *CODE;
    static const char *REASON;
/* WebSocketConnection */
    static const char *CLIENT_PORT;
    static const char *CLIENT_IP;

/* WebSocketServerConfig */
    static const char *SERVER_PORT;
    static const char *MAX_CLIENT_NUMBER;
    static const char *MAX_CONNECTIONS_FOR_ONE_CLIENT;
    static const char *SERVER_IP;
    static const char *SERVER_CERT;
    static const char *PROTOCOL;
    static const char *PING_INTERVAL;
    static const char *PONG_TIMEOUT;
};

class EventName final {
public:
    static const char *EVENT_OPEN;
    static const char *EVENT_MESSAGE;
    static const char *EVENT_CLOSE;
    static const char *EVENT_ERROR;
    static const char *EVENT_DATA_END;
    static const char *EVENT_HEADER_RECEIVE;

/* websocketServer */
    static const char *EVENT_SERVER_ERROR;
    static const char *EVENT_SERVER_CONNECT;
    static const char *EVENT_SERVER_MESSAGE_RECEIVE;
    static const char *EVENT_SERVER_CLOSE;
};
} // namespace OHOS::NetStack::Websocket
#endif /* COMMUNICATIONNETSTACK_CONSTANT_H */
