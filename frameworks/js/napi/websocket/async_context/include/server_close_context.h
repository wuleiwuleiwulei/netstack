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

#ifndef COMMUNICATIONNETSTACK_SERVER_CLOSE_CONTEXT_H
#define COMMUNICATIONNETSTACK_SERVER_CLOSE_CONTEXT_H

#include <string>
#include "base_context.h"
#include "websocket_exec_common.h"
#include "nocopyable.h"

namespace OHOS::NetStack::Websocket {
class ServerCloseContext final : public BaseContext {
public:
    DISALLOW_COPY_AND_MOVE(ServerCloseContext);

    ServerCloseContext() = delete;

    ServerCloseContext(napi_env env, const std::shared_ptr<EventManager> &manager);

    ~ServerCloseContext() override;

    void ParseParams(napi_value *params, size_t paramsCount) override;

    bool HandleParseConnection(napi_env env, napi_value params);

    bool HandleParseCloseOption(napi_env env, napi_value params);

    [[nodiscard]] OHOS::NetStack::Websocket::WebSocketConnection GetConnection() const;

    [[nodiscard]] int32_t GetErrorCode() const override;

    [[nodiscard]] std::string GetErrorMessage() const override;

    uint32_t code;

    std::string reason;

    WebSocketConnection connection;

private:
    bool CheckParamsType(napi_value *params, size_t paramsCount);

    bool IsValidWebsocketConnection(napi_env env, napi_value params);

    bool IsValidCloseOptions(napi_env env, napi_value params);
};
} // namespace OHOS::NetStack::Websocket

#endif /* COMMUNICATIONNETSTACK_SERVER_CLOSE_CONTEXT_H */