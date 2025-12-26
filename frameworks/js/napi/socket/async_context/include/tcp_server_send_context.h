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

#ifndef COMMUNICATIONNETSTACK_TCP_SERVER_SEND_CONTEXT_H
#define COMMUNICATIONNETSTACK_TCP_SERVER_SEND_CONTEXT_H

#include <cstddef>

#include "base_context.h"
#include "napi/native_api.h"
#include "nocopyable.h"
#include "tcp_send_options.h"

namespace OHOS::NetStack::Socket {
class TcpServerSendContext final : public BaseContext {
public:
    DISALLOW_COPY_AND_MOVE(TcpServerSendContext);

    TcpServerSendContext() = delete;

    explicit TcpServerSendContext(napi_env env, const std::shared_ptr<EventManager> &manager);

    void ParseParams(napi_value *params, size_t paramsCount) override;

    [[nodiscard]] int GetSocketFd() const;

    [[nodiscard]] int32_t GetErrorCode() const override;

    [[nodiscard]] std::string GetErrorMessage() const override;

    TCPSendOptions options;
    int32_t clientId_ = 0;

private:
    bool CheckParamsType(napi_value *params, size_t paramsCount);

    bool GetData(napi_value udpSendOptions);
};
} // namespace OHOS::NetStack::Socket

#endif /* COMMUNICATIONNETSTACK_TCP_SERVER_SEND_CONTEXT_H */
