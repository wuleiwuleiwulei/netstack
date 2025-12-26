/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WEBSOCKET_CONSTANT_H
#define WEBSOCKET_CONSTANT_H

#include <map>
#include <string>

constexpr const char *WEBSOCKET_PROXY_EXCLUSIONS_SEPARATOR = ",";
constexpr const int32_t ERR_OK = 0;
constexpr const size_t MAP_TUPLE_SIZE = 2;
constexpr const uint32_t MAX_LIMIT = 100 * 1024 * 1024;

namespace OHOS::NetStack::NetWebSocket {
enum WebSocketErrorCode {
    WEBSOCKET_CONNECT_FAILED = -1,
    WEBSOCKET_PERMISSION_DENIED_CODE = 201,
    WEBSOCKET_PARSE_ERROR_CODE = 401,
    WEBSOCKET_ERROR_CODE_BASE = 2302000,
    WEBSOCKET_ERROR_CODE_URL_ERROR = WEBSOCKET_ERROR_CODE_BASE + 1,
    WEBSOCKET_ERROR_CODE_FILE_NOT_EXIST = WEBSOCKET_ERROR_CODE_BASE + 2,
    WEBSOCKET_ERROR_CODE_CONNECT_AlREADY_EXIST = WEBSOCKET_ERROR_CODE_BASE + 3,
    WEBSOCKET_NOT_ALLOWED_HOST = 2302998,
    WEBSOCKET_UNKNOWN_OTHER_ERROR = 2302999
};

static const std::map<int32_t, std::string> WEBSOCKET_ERR_MAP = {
    {WEBSOCKET_CONNECT_FAILED, "Websocket connect failed"},
    {WEBSOCKET_PERMISSION_DENIED_CODE, "Permission denied"},
    {WEBSOCKET_PARSE_ERROR_CODE, "Parameter error"},
    {WEBSOCKET_ERROR_CODE_URL_ERROR, "Websocket url error"},
    {WEBSOCKET_ERROR_CODE_FILE_NOT_EXIST, "Websocket file not exist"},
    {WEBSOCKET_ERROR_CODE_CONNECT_AlREADY_EXIST, "Websocket connection exist"},
    {WEBSOCKET_NOT_ALLOWED_HOST, "It is not allowed to access this domain"},
    {WEBSOCKET_UNKNOWN_OTHER_ERROR, "Websocket Unknown Other Error"}};

enum class WebsocketProxyType {
    NOT_USE,
    USE_SYSTEM,
    USE_SPECIFIED,
};

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

enum OnOffType {
    EVENT_OPEN = 1,
    EVENT_MESSAGE = 2,
    EVENT_CLOSE = 3,
    EVENT_ERROR = 4,
    EVENT_DATA_END = 5,
    EVENT_HEADER_RECEIVE = 6
};

enum ReceiveResponseType {
    MAP = 0,
    ARRAY_STRING = 1,
    UNDEFINED = 2
};

enum MessageResponseType {
    STRING = 0,
    ARRAY_BUFFER = 1
};
}
#endif