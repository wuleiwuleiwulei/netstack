/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "common_context.h"

#include "context_key.h"
#include "socket_constant.h"
#include "event_manager.h"
#include "napi_utils.h"

namespace OHOS::NetStack::Socket {
CommonContext::CommonContext(napi_env env, const std::shared_ptr<EventManager> &manager)
    : BaseContext(env, manager) {}

void CommonContext::ParseParams(napi_value *params, size_t paramsCount)
{
    bool valid = CheckParamsType(params, paramsCount);
    if (!valid) {
        if (paramsCount == PARAM_JUST_CALLBACK) {
            if (NapiUtils::GetValueType(GetEnv(), params[0]) == napi_function) {
                SetCallback(params[0]);
            }
            return;
        }
        return;
    }

    if (paramsCount != PARAM_NONE) {
        SetParseOK(SetCallback(params[0]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

int CommonContext::GetSocketFd() const
{
    if (sharedManager_ == nullptr) {
        return -1;
    }
    return sharedManager_->GetData() ? static_cast<int>(reinterpret_cast<uint64_t>(sharedManager_->GetData())) : -1;
}

bool CommonContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_NONE) {
        return true;
    }

    if (paramsCount == PARAM_JUST_CALLBACK) {
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_function;
    }
    return false;
}

CloseContext::CloseContext(napi_env env, const std::shared_ptr<EventManager> &manager)
    : CommonContext(env, manager) {}

void CloseContext::SetSocketFd(int sock)
{
    sharedManager_->SetData(reinterpret_cast<void *>(sock));
}

int32_t CommonContext::GetErrorCode() const
{
    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_CODE;
    }

    auto err = BaseContext::GetErrorCode();
    if (err == PARSE_ERROR_CODE) {
        return PARSE_ERROR_CODE;
    }
#if defined(IOS_PLATFORM)
    err = ErrCodePlatformAdapter::GetOHOSErrCode(err);
#endif
    return err + SOCKET_ERROR_CODE_BASE;
}

std::string CommonContext::GetErrorMessage() const
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
    if (errCode == -1) {
        return "Unknown Other Error";
    }
    char err[MAX_ERR_NUM] = {0};
    (void)strerror_r(errCode, err, MAX_ERR_NUM);
    return err;
#endif
}
} // namespace OHOS::NetStack::Socket
