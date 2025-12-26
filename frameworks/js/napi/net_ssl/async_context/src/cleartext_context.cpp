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

#include "cleartext_context.h"
#include "netstack_log.h"
#include "napi_utils.h"
#if HAS_NETMANAGER_BASE
#include "net_conn_client.h"
#endif // HAS_NETMANAGER_BASE

namespace OHOS::NetStack::Ssl {
CleartextContext::CleartextContext(napi_env env, const std::shared_ptr<EventManager> &manager)
    : BaseContext(env, manager) {}

void CleartextContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (paramsCount != PARAM_NONE) {
        NETSTACK_LOGE("check params type failed");
        SetNeedThrowException(true);
        SetErrorCode(PARSE_ERROR_CODE);
        return;
    }
    SetParseOK(true);
}

std::string CleartextContext::GetErrorMessage() const
{
    auto errCode = BaseContext::GetErrorCode();
    if (errCode == PARSE_ERROR_CODE) {
        return PARSE_ERROR_MSG;
    }
    if (errCode == PERMISSION_DENIED_CODE) {
        return PERMISSION_DENIED_MSG;
    }
    char err[MAX_ERR_NUM] = {0};
    (void)strerror_r(errCode, err, MAX_ERR_NUM);
    return err;
}

CleartextForHostContext::CleartextForHostContext(napi_env env, const std::shared_ptr<EventManager> &manager)
    : BaseContext(env, manager) {}


void CleartextForHostContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsType(params, paramsCount)) {
        NETSTACK_LOGE("check params type failed");
        SetNeedThrowException(true);
        SetErrorCode(PARSE_ERROR_CODE);
        return;
    }
    hostname_ = NapiUtils::GetStringFromValueUtf8(GetEnv(), params[0]);
    SetParseOK(true);
}

bool CleartextForHostContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_JUST_OPTIONS) {
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_string;
    }
    return false;
}

std::string CleartextForHostContext::GetErrorMessage() const
{
    auto errCode = BaseContext::GetErrorCode();
    if (errCode == PARSE_ERROR_CODE) {
        return PARSE_ERROR_MSG;
    }
    if (errCode == PERMISSION_DENIED_CODE) {
        return PERMISSION_DENIED_MSG;
    }
    char err[MAX_ERR_NUM] = {0};
    (void)strerror_r(errCode, err, MAX_ERR_NUM);
    return err;
}

} // namespace OHOS::NetManagerStandard
