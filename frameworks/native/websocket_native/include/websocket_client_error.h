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

#ifndef COMMUNICATIONNETSTACK_WEBSOCKET_CLIENT_ERROR_H
#define COMMUNICATIONNETSTACK_WEBSOCKET_CLIENT_ERROR_H

#include <map>
#include <string>

namespace OHOS {
namespace NetStack {
namespace WebSocketClient {

enum WebSocketErrorCode {
    WEBSOCKET_NONE_ERR = 0,
    WEBSOCKET_COMMON_ERROR_CODE = 200,
    WEBSOCKET_ERROR_CODE_BASE = 1000,
    WEBSOCKET_CLIENT_IS_NULL = 1001,
    WEBSOCKET_CLIENT_IS_NOT_CREAT = 1002,
    WEBSOCKET_CONNECTION_ERROR = 1003,
    WEBSOCKET_CONNECTION_PARSEURL_ERROR = 1004,
    WEBSOCKET_CONNECTION_NO_MEMOERY = 1005,
    WEBSOCKET_CONNECTION_TO_SERVER_FAIL = 1006,
    WEBSOCKET_PEER_INITIATED_CLOSE = 1007,
    WEBSOCKET_DESTROY = 1008,
    WEBSOCKET_PROTOCOL_ERROR = 1009,
    WEBSOCKET_SEND_NO_MEMOERY_ERROR = 1010,
    WEBSOCKET_SEND_DATA_NULL = 1011,
    WEBSOCKET_DATA_LENGTH_EXCEEDS = 1012,
    WEBSOCKET_QUEUE_LENGTH_EXCEEDS = 1013,
    WEBSOCKET_ERROR_NO_CLIENTCONTEX = 1014,
    WEBSOCKET_ERROR_NO_HEADR_CONTEXT = 1015,
    WEBSOCKET_ERROR_NO_HEADR_EXCEEDS = 1016,
    WEBSOCKET_ERROR_HAVE_NO_CONNECT = 1017,
    WEBSOCKET_ERROR_HAVE_NO_CONNECT_CONTEXT = 1018,
    WEBSOCKET_ERROR_FILE_NOT_EXIST = 1019,
    WEBSOCKET_ERROR_PERMISSION_DENIED = 1020,
    WEBSOCKET_ERROR_DISALLOW_HOST = 1021,
    WEBSOCKET_UNKNOWN_OTHER_ERROR = 9999
};

} // namespace WebSocketClient
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATIONNETSTACK_WEBSOCKET_CLIENT_ERROR_H