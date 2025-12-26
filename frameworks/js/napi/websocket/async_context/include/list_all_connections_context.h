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

#ifndef COMMUNICATIONNETSTACK_LISTALLCONNECTIONS_CONTEXT_H
#define COMMUNICATIONNETSTACK_LISTALLCONNECTIONS_CONTEXT_H

#include "base_context.h"
#include "websocket_exec_common.h"
#include "nocopyable.h"

namespace OHOS::NetStack::Websocket {
class ListAllConnectionsContext final : public BaseContext {
public:
    DISALLOW_COPY_AND_MOVE(ListAllConnectionsContext);

    ListAllConnectionsContext() = delete;

    ListAllConnectionsContext(napi_env env, const std::shared_ptr<EventManager> &sharedManager);

    ~ListAllConnectionsContext() override;

    void ParseParams(napi_value *params, size_t paramsCount) override;

    void SetAllConnections(std::vector<OHOS::NetStack::Websocket::WebSocketConnection> &connections);

    [[nodiscard]] std::vector<OHOS::NetStack::Websocket::WebSocketConnection> GetAllConnections() const;

    [[nodiscard]] int32_t GetErrorCode() const override;

    [[nodiscard]] std::string GetErrorMessage() const override;

private:
    bool CheckParamsType(napi_value *params, size_t paramsCount);

    std::vector<OHOS::NetStack::Websocket::WebSocketConnection> webSocketConnections_;
};
} // namespace OHOS::NetStack::Websocket

#endif /* COMMUNICATIONNETSTACK_LISTALLCONNECTIONS_CONTEXT_H */