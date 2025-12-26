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

#ifndef MULTICAST_SET_TTL_CONTEXT_H
#define MULTICAST_SET_TTL_CONTEXT_H

#include <cstddef>

#include "base_context.h"
#include "napi/native_api.h"
#include "nocopyable.h"

namespace OHOS::NetStack::Socket {
class MulticastSetTTLContext final : public BaseContext {
public:
    DISALLOW_COPY_AND_MOVE(MulticastSetTTLContext);

    MulticastSetTTLContext() = delete;

    MulticastSetTTLContext(napi_env env, const std::shared_ptr<EventManager> &manager);

    void ParseParams(napi_value *params, size_t paramsCount) override;

    [[nodiscard]] int GetSocketFd() const;

    [[nodiscard]] int32_t GetErrorCode() const override;

    [[nodiscard]] std::string GetErrorMessage() const override;

    void SetMulticastTTL(int ttl);

    int GetMulticastTTL() const;

private:
    bool CheckParamsType(napi_value *params, size_t paramsCount);

    int ttl_ = 0;
};
} // namespace OHOS::NetStack::Socket

#endif /* MULTICAST_SET_TTL_CONTEXT_H */
