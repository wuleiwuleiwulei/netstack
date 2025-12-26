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

#include "tls_init_context.h"

#include <string_view>

#include "context_key.h"
#include "event_manager.h"
#include "netstack_log.h"
#include "napi_utils.h"

namespace OHOS::NetStack::TlsSocket {
static constexpr std::string_view PARSE_ERROR = "Parameter error";
static constexpr const char *INTERFACE_TCP_SOCKET = "TCPSocket";

TLSInitContext::TLSInitContext(napi_env env, const std::shared_ptr<EventManager> &manager)
    : BaseContext(env, manager) {}

void TLSInitContext::ParseParams(napi_value *params, size_t paramsCount)
{
    bool valid = CheckParamsType(params, paramsCount);
    if (!valid) {
        return;
    }
    std::shared_ptr<EventManager> *sharedManager = nullptr;
    auto napiRet = napi_unwrap(GetEnv(), params[0], reinterpret_cast<void **>(&sharedManager));
    if (napiRet != napi_ok) {
        NETSTACK_LOGE("get event manager in napi_unwrap failed, napiRet is %{public}d", napiRet);
        return;
    }
    if (sharedManager != nullptr) {
        extManager_ = *sharedManager;
    }
    SetParseOK(true);
}

bool TLSInitContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_JUST_OPTIONS) {
        if (!NapiUtils::IsInstanceOf(GetEnv(), params[0], INTERFACE_TCP_SOCKET)) {
            NETSTACK_LOGE("param is not TCPSocket");
            SetNeedThrowException(true);
            SetError(PARSE_ERROR_CODE, PARSE_ERROR.data());
            return false;
        }
        return true;
    }

    NETSTACK_LOGE("invalid param number");
    SetNeedThrowException(true);
    SetError(PARSE_ERROR_CODE, PARSE_ERROR.data());
    return false;
}
} // namespace OHOS::NetStack::TlsSocket
