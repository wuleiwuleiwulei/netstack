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

#ifndef COMMUNICATIONNETSTACK_SERVER_SEND_CONTEXT_H
#define COMMUNICATIONNETSTACK_SERVER_SEND_CONTEXT_H

#include <string>
#include "base_context.h"
#include "websocket_exec_common.h"
#include "nocopyable.h"

namespace OHOS::NetStack::Websocket {
class ServerSendContext final : public BaseContext {
public:
    DISALLOW_COPY_AND_MOVE(ServerSendContext);

    ServerSendContext() = delete;

    ServerSendContext(napi_env env, const std::shared_ptr<EventManager> &manager);

    ~ServerSendContext() override;

    void ParseParams(napi_value *params, size_t paramsCount) override;

    bool HandleParseString(napi_value *params);

    bool HandleParseArrayBuffer(napi_value *params);

    bool HandleParseConnection(napi_env env, napi_value params);

    void SetClientWebSocketConn(uint32_t &port, std::string &ip);

    [[nodiscard]] int32_t GetErrorCode() const override;

    [[nodiscard]] std::string GetErrorMessage() const override;

    [[nodiscard]] OHOS::NetStack::Websocket::WebSocketConnection GetConnection() const;

    void *data;

    size_t length;

    lws_write_protocol protocol;

    OHOS::NetStack::Websocket::WebSocketConnection connection;

private:
    bool CheckParamsType(napi_value *params, size_t paramsCount);

    bool IsValidWebsocketConnection(napi_env env, napi_value params);
};
} // namespace OHOS::NetStack::Websocket

#endif