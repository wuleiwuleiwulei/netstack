/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef TLS_INIT_CONTEXT_H
#define TLS_INIT_CONTEXT_H

#include <cstddef>
#include <cstdint>

#include <napi/native_api.h>

#include "base_context.h"
#include "event_manager.h"

namespace OHOS::NetStack::TlsSocket {
class TLSInitContext final : public BaseContext {
public:
    TLSInitContext() = delete;
    explicit TLSInitContext(napi_env env, const std::shared_ptr<EventManager> &manager);

public:
    void ParseParams(napi_value *params, size_t paramsCount) override;

public:
    std::shared_ptr<EventManager> extManager_ = nullptr;

private:
    bool CheckParamsType(napi_value *params, size_t paramsCount);
};
} // namespace OHOS::NetStack::TlsSocket
#endif // TLS_INIT_CONTEXT_H
