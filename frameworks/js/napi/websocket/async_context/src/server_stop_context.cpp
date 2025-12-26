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

#include "server_stop_context.h"

#include "constant.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "napi_utils.h"

namespace OHOS::NetStack::Websocket {
ServerStopContext::ServerStopContext(napi_env env, const std::shared_ptr<EventManager> &sharedManager)
    : BaseContext(env, sharedManager) {}

ServerStopContext::~ServerStopContext() = default;

void ServerStopContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsType(params, paramsCount)) {
        return;
    }
    if (paramsCount != FUNCTION_PARAM_ZERO) {
        SetParseOK(SetCallback(params[0]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

bool ServerStopContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == FUNCTION_PARAM_ZERO) {
        return true;
    }
    return false;
}

int32_t ServerStopContext::GetErrorCode() const
{
    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_CODE;
    }
    return WEBSOCKET_UNKNOWN_OTHER_ERROR;
}

std::string ServerStopContext::GetErrorMessage() const
{
    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_MSG;
    }
    auto it = WEBSOCKET_ERR_MAP.find(WEBSOCKET_UNKNOWN_OTHER_ERROR);
    if (it != WEBSOCKET_ERR_MAP.end()) {
        return it->second;
    }
    return {};
}
} // namespace OHOS::NetStack::Websocket