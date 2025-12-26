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

#include "multicast_get_loopback_context.h"

#include "context_key.h"
#include "event_manager.h"
#include "napi_utils.h"
#include "netstack_log.h"
#include "socket_constant.h"

namespace OHOS::NetStack::Socket {
MulticastGetLoopbackContext::MulticastGetLoopbackContext(
    napi_env env, const std::shared_ptr<EventManager> &manager)
    : BaseContext(env, manager)
{
}

void MulticastGetLoopbackContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsType(params, paramsCount)) {
        return;
    }

    if (paramsCount != PARAM_NONE) {
        SetParseOK(SetCallback(params[0]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

bool MulticastGetLoopbackContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_NONE) {
        return true;
    }

    if (paramsCount == PARAM_JUST_CALLBACK) {
        if (NapiUtils::GetValueType(GetEnv(), params[0]) == napi_function) {
            return true;
        } else {
            NETSTACK_LOGE("first param is not callback");
            SetNeedThrowException(true);
            SetError(PARSE_ERROR_CODE, PARSE_ERROR_MSG);
        }
    }
    return false;
}

void MulticastGetLoopbackContext::SetLoopbackMode(bool mode)
{
    isLoopback_ = mode;
}

bool MulticastGetLoopbackContext::GetLoopbackMode() const
{
    return isLoopback_;
}

int MulticastGetLoopbackContext::GetSocketFd() const
{
    return sharedManager_->GetData() ? static_cast<int>(reinterpret_cast<uint64_t>(sharedManager_->GetData())) : -1;
}

int32_t MulticastGetLoopbackContext::GetErrorCode() const
{
    auto err = BaseContext::GetErrorCode();
    if (err == PARSE_ERROR_CODE) {
        return PARSE_ERROR_CODE;
    }

    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_CODE;
    }

#if defined(IOS_PLATFORM)
    err = ErrCodePlatformAdapter::GetOHOSErrCode(err);
#endif
    return err + SOCKET_ERROR_CODE_BASE;
}

std::string MulticastGetLoopbackContext::GetErrorMessage() const
{
    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_MSG;
    }

    auto errCode = BaseContext::GetErrorCode();
    if (errCode == PARSE_ERROR_CODE) {
        return PARSE_ERROR_MSG;
    }
#if defined(IOS_PLATFORM)
    std::string errMessage;
    ErrCodePlatformAdapter::GetOHOSErrMessage(errCode, errMessage);
    return errMessage;
#else
    char err[MAX_ERR_NUM] = {0};
    (void)strerror_r(errCode, err, MAX_ERR_NUM);
    return err;
#endif
}
} // namespace OHOS::NetStack::Socket
