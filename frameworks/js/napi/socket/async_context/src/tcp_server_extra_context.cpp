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

#include "tcp_server_extra_context.h"

#include "context_key.h"
#include "event_manager.h"
#include "napi_utils.h"
#include "netstack_log.h"
#include "socket_constant.h"

namespace OHOS::NetStack::Socket {
TcpServerSetExtraOptionsContext::TcpServerSetExtraOptionsContext(
    napi_env env, const std::shared_ptr<EventManager> &manager)
    : BaseContext(env, manager)
{
}

void TcpServerSetExtraOptionsContext::ParseContextKey(napi_value *params)
{
    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_RECEIVE_BUFFER_SIZE)) {
        options_.SetReceiveBufferSize(NapiUtils::GetUint32Property(GetEnv(), params[0], KEY_RECEIVE_BUFFER_SIZE));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_SEND_BUFFER_SIZE)) {
        options_.SetSendBufferSize(NapiUtils::GetUint32Property(GetEnv(), params[0], KEY_SEND_BUFFER_SIZE));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_REUSE_ADDRESS)) {
        options_.SetReuseAddress(NapiUtils::GetBooleanProperty(GetEnv(), params[0], KEY_REUSE_ADDRESS));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_SOCKET_TIMEOUT)) {
        options_.SetSocketTimeout(NapiUtils::GetUint32Property(GetEnv(), params[0], KEY_SOCKET_TIMEOUT));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_KEEP_ALIVE)) {
        options_.SetKeepAlive(NapiUtils::GetBooleanProperty(GetEnv(), params[0], KEY_KEEP_ALIVE));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_OOB_INLINE)) {
        options_.SetOOBInline(NapiUtils::GetBooleanProperty(GetEnv(), params[0], KEY_OOB_INLINE));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_TCP_NO_DELAY)) {
        options_.SetTCPNoDelay(NapiUtils::GetBooleanProperty(GetEnv(), params[0], KEY_TCP_NO_DELAY));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_SOCKET_LINGER)) {
        napi_value socketLinger = NapiUtils::GetNamedProperty(GetEnv(), params[0], KEY_SOCKET_LINGER);
        if (NapiUtils::GetValueType(GetEnv(), params[0]) == napi_object) {
            if (NapiUtils::HasNamedProperty(GetEnv(), socketLinger, KEY_SOCKET_LINGER_ON)) {
                options_.socketLinger.SetOn(
                    NapiUtils::GetBooleanProperty(GetEnv(), socketLinger, KEY_SOCKET_LINGER_ON));
            }
            if (NapiUtils::HasNamedProperty(GetEnv(), socketLinger, KEY_SOCKET_LINGER_LINGER)) {
                options_.socketLinger.SetLinger(
                    NapiUtils::GetUint32Property(GetEnv(), socketLinger, KEY_SOCKET_LINGER_LINGER));
            }
        }
    }
}

void TcpServerSetExtraOptionsContext::ParseParams(napi_value *params, size_t paramsCount)
{
    bool valid = CheckParamsType(params, paramsCount);
    if (!valid) {
        if (paramsCount == PARAM_JUST_CALLBACK) {
            if (NapiUtils::GetValueType(GetEnv(), params[0]) == napi_function) {
                SetCallback(params[0]);
            }
            return;
        }
        if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
            if (NapiUtils::GetValueType(GetEnv(), params[1]) == napi_function) {
                SetCallback(params[1]);
            }
            return;
        }
        return;
    }

    ParseContextKey(params);

    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        SetParseOK(SetCallback(params[1]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

int TcpServerSetExtraOptionsContext::GetSocketFd() const
{
    return sharedManager_->GetData() ? static_cast<int>(reinterpret_cast<uint64_t>(sharedManager_->GetData())) : -1;
}

bool TcpServerSetExtraOptionsContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_JUST_OPTIONS) {
        if (NapiUtils::GetValueType(GetEnv(), params[0]) != napi_object) {
            NETSTACK_LOGE("invalid parameter");
            SetNeedThrowException(true);
            SetError(PARSE_ERROR_CODE, PARSE_ERROR_MSG);
            return false;
        }
        return true;
    }

    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        if (NapiUtils::GetValueType(GetEnv(), params[0]) != napi_object ||
            NapiUtils::GetValueType(GetEnv(), params[1]) != napi_function) {
            NETSTACK_LOGE("invalid parameter");
            SetNeedThrowException(true);
            SetError(PARSE_ERROR_CODE, PARSE_ERROR_MSG);
            return false;
        }
        return true;
    }
    return false;
}

int32_t TcpServerSetExtraOptionsContext::GetErrorCode() const
{
    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_CODE;
    }

    auto err = BaseContext::GetErrorCode();
    if (err == PARSE_ERROR_CODE) {
        return PARSE_ERROR_CODE;
    }
    return err + SOCKET_SERVER_ERROR_CODE_BASE;
}

std::string TcpServerSetExtraOptionsContext::GetErrorMessage() const
{
    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_MSG;
    }

    auto errCode = BaseContext::GetErrorCode();
    if (errCode == PARSE_ERROR_CODE) {
        return PARSE_ERROR_MSG;
    }
    char err[MAX_ERR_NUM] = {0};
    (void)strerror_r(errCode, err, MAX_ERR_NUM);
    return err;
}
} // namespace OHOS::NetStack::Socket
