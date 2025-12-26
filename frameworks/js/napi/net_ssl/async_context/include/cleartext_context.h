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

#ifndef COMMUNICATIONNETSTACK_CLEARTEXT_CONTEXT_H
#define COMMUNICATIONNETSTACK_CLEARTEXT_CONTEXT_H

#include "base_context.h"
#include "net_ssl.h"

#define PARAM_NONE 0
#define PARAM_JUST_OPTIONS 1

namespace OHOS::NetStack::Ssl {
static constexpr const size_t MAX_ERR_NUM = 256;

class CleartextContext final : public BaseContext {
public:
    CleartextContext() = delete;
    explicit CleartextContext(napi_env env, const std::shared_ptr<EventManager> &manager);
    void ParseParams(napi_value *params, size_t paramsCount) override;
    [[nodiscard]] std::string GetErrorMessage() const override;

public:
    bool isCleartextPermitted_ = true;
};

class CleartextForHostContext final : public BaseContext {
public:
    CleartextForHostContext() = delete;
    explicit CleartextForHostContext(napi_env env, const std::shared_ptr<EventManager> &manager);
    void ParseParams(napi_value *params, size_t paramsCount) override;
    [[nodiscard]] std::string GetErrorMessage() const override;

public:
    std::string hostname_ = "";
    bool isCleartextPermitted_ = true;

private:
    bool CheckParamsType(napi_value *params, size_t paramsCount);
};

} // namespace OHOS::NetStack::Ssl
#endif // COMMUNICATIONNETSTACK_CLEARTEXT_CONTEXT_H
