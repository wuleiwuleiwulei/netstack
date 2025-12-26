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

#ifndef MULTICAST_SET_LOOPBACK_CONTEXT_H
#define MULTICAST_SET_LOOPBACK_CONTEXT_H

#include <cstddef>

#include "base_context.h"
#include "napi/native_api.h"
#include "nocopyable.h"

namespace OHOS::NetStack::Socket {
class MulticastSetLoopbackContext final : public BaseContext {
public:
    DISALLOW_COPY_AND_MOVE(MulticastSetLoopbackContext);

    MulticastSetLoopbackContext() = delete;

    MulticastSetLoopbackContext(napi_env env, const std::shared_ptr<EventManager> &manager);

    void ParseParams(napi_value *params, size_t paramsCount) override;

    [[nodiscard]] int GetSocketFd() const;

    [[nodiscard]] int32_t GetErrorCode() const override;

    [[nodiscard]] std::string GetErrorMessage() const override;

    void SetLoopbackMode(bool mode);

    bool GetLoopbackMode() const;

private:
    bool CheckParamsType(napi_value *params, size_t paramsCount);

    bool isLoopback_ = false;
};
} // namespace OHOS::NetStack::Socket

#endif /* MULTICAST_SET_LOOPBACK_CONTEXT_H */
