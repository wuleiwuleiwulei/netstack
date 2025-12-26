/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "local_socket_context.h"

#include "context_key.h"
#include "event_manager.h"
#include "napi_utils.h"
#include "netstack_log.h"
#include "socket_constant.h"

namespace OHOS::NetStack::Socket {

constexpr int SYSTEM_INTERNAL_ERROR = -998;
constexpr const char *SYSTEM_INTERNAL_ERROR_MSG = "System internal error";

int LocalSocketBaseContext::GetSocketFd() const
{
    if (sharedManager_ == nullptr) {
        return -1;
    }
    LocalSocketManager *pMgr = reinterpret_cast<LocalSocketManager *>(sharedManager_->GetData());
    return (pMgr != nullptr) ? pMgr->sockfd_ : -1;
}

void LocalSocketBaseContext::SetSocketFd(int sock)
{
    if (sharedManager_ == nullptr) {
        return;
    }
    if (auto pMgr = reinterpret_cast<LocalSocketManager *>(sharedManager_->GetData()); pMgr != nullptr) {
        pMgr->sockfd_ = sock;
    }
}

int32_t LocalSocketBaseContext::GetErrorCode() const
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

std::string LocalSocketBaseContext::GetErrorMessage() const
{
    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_MSG;
    }

    auto errCode = BaseContext::GetErrorCode();
    if (errCode == PARSE_ERROR_CODE) {
        return PARSE_ERROR_MSG;
    }
    if (errCode == SYSTEM_INTERNAL_ERROR) {
        return SYSTEM_INTERNAL_ERROR_MSG;
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

bool LocalSocketBaseContext::CheckParamsWithOptions(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_JUST_OPTIONS) {
        if (NapiUtils::GetValueType(GetEnv(), params[0]) != napi_object) {
            NETSTACK_LOGE("first param is not object");
            SetNeedThrowException(true);
            SetError(PARSE_ERROR_CODE, PARSE_ERROR_MSG);
            return false;
        }
    } else if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        if (NapiUtils::GetValueType(GetEnv(), params[0]) != napi_object) {
            NETSTACK_LOGE("first param is not object");
            SetNeedThrowException(true);
            SetError(PARSE_ERROR_CODE, PARSE_ERROR_MSG);
            return false;
        }
        if (NapiUtils::GetValueType(GetEnv(), params[1]) != napi_function) {
            NETSTACK_LOGE("second param is not function");
            return false;
        }
    } else {
        NETSTACK_LOGE("invalid param count");
        return false;
    }
    return true;
}

bool LocalSocketBaseContext::CheckParamsWithoutOptions(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_NONE) {
        return true;
    }
    if (paramsCount == PARAM_JUST_CALLBACK) {
        if (NapiUtils::GetValueType(GetEnv(), params[0]) == napi_function) {
            return true;
        } else {
            NETSTACK_LOGE("only one param and it is not callback");
            SetNeedThrowException(true);
            SetError(PARSE_ERROR_CODE, PARSE_ERROR_MSG);
        }
    }
    return false;
}

void LocalSocketBindContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsWithOptions(params, paramsCount)) {
        return;
    }
    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_ADDRESS)) {
        socketPath_ = NapiUtils::GetStringPropertyUtf8(GetEnv(), params[0], KEY_ADDRESS);
        NETSTACK_LOGD("LocalSocketBindContext parse, path: %{public}s", socketPath_.c_str());
    } else {
        NETSTACK_LOGE("params do not contain socket path");
    }
    if (socketPath_.empty()) {
        NETSTACK_LOGE("socket path is empty");
    }
    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        SetParseOK(SetCallback(params[1]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

const std::string &LocalSocketBindContext::GetSocketPath() const
{
    return socketPath_;
}

void LocalSocketConnectContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsWithOptions(params, paramsCount)) {
        return;
    }
    if (!NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_ADDRESS)) {
        NETSTACK_LOGE("no property named address");
    }
    napi_value netAddress = NapiUtils::GetNamedProperty(GetEnv(), params[0], KEY_ADDRESS);
    if (!NapiUtils::HasNamedProperty(GetEnv(), netAddress, KEY_ADDRESS)) {
        NETSTACK_LOGE("address is empty");
    }
    socketPath_ = NapiUtils::GetStringPropertyUtf8(GetEnv(), netAddress, KEY_ADDRESS);
    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_TIMEOUT)) {
        timeout_ = NapiUtils::GetInt32Property(GetEnv(), params[0], KEY_TIMEOUT);
    }
    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        SetParseOK(SetCallback(params[1]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

const std::string &LocalSocketConnectContext::GetSocketPath() const
{
    return socketPath_;
}

int LocalSocketConnectContext::GetTimeoutMs() const
{
    return timeout_;
}

bool LocalSocketSendContext::GetData(napi_value sendOptions)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), sendOptions, KEY_DATA)) {
        return false;
    }
    napi_value jsData = NapiUtils::GetNamedProperty(GetEnv(), sendOptions, KEY_DATA);
    if (NapiUtils::GetValueType(GetEnv(), jsData) == napi_string) {
        std::string data = NapiUtils::GetStringFromValueUtf8(GetEnv(), jsData);
        if (data.empty()) {
            NETSTACK_LOGE("string data is empty");
            return true;
        }
        options_.SetBuffer(data);
        return true;
    }

    if (NapiUtils::ValueIsArrayBuffer(GetEnv(), jsData)) {
        size_t length = 0;
        void *data = NapiUtils::GetInfoFromArrayBufferValue(GetEnv(), jsData, &length);
        if (data == nullptr || length == 0) {
            NETSTACK_LOGE("arraybuffer data is empty");
            return true;
        }
        options_.SetBuffer(data, length);
        return true;
    }
    return false;
}

void LocalSocketSendContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsWithOptions(params, paramsCount)) {
        return;
    }
    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_ENCODING)) {
        std::string encoding = NapiUtils::GetStringPropertyUtf8(GetEnv(), params[0], KEY_ENCODING);
        options_.SetEncoding(encoding);
    }
    if (!GetData(params[0])) {
        return;
    }
    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        SetParseOK(SetCallback(params[1]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

LocalSocketOptions &LocalSocketSendContext::GetOptionsRef()
{
    return options_;
}

void LocalSocketCloseContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsWithoutOptions(params, paramsCount)) {
        return;
    }
    if (paramsCount != PARAM_NONE) {
        SetParseOK(SetCallback(params[0]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

void LocalSocketGetStateContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsWithoutOptions(params, paramsCount)) {
        return;
    }
    if (paramsCount != PARAM_NONE) {
        SetParseOK(SetCallback(params[0]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

SocketStateBase &LocalSocketGetStateContext::GetStateRef()
{
    return state_;
}

void LocalSocketGetSocketFdContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsWithoutOptions(params, paramsCount)) {
        return;
    }
    if (paramsCount != PARAM_NONE) {
        SetParseOK(SetCallback(params[0]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

void LocalSocketSetExtraOptionsContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsWithOptions(params, paramsCount)) {
        return;
    }
    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_RECEIVE_BUFFER_SIZE)) {
        options_.SetReceiveBufferSize(NapiUtils::GetUint32Property(GetEnv(), params[0], KEY_RECEIVE_BUFFER_SIZE));
        options_.SetRecvBufSizeFlag(true);
    }
    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_SEND_BUFFER_SIZE)) {
        options_.SetSendBufferSize(NapiUtils::GetUint32Property(GetEnv(), params[0], KEY_SEND_BUFFER_SIZE));
        options_.SetSendBufSizeFlag(true);
    }
    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_SOCKET_TIMEOUT)) {
        options_.SetSocketTimeout(NapiUtils::GetUint32Property(GetEnv(), params[0], KEY_SOCKET_TIMEOUT));
        options_.SetTimeoutFlag(true);
    }
    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        SetParseOK(SetCallback(params[1]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

LocalExtraOptions &LocalSocketSetExtraOptionsContext::GetOptionsRef()
{
    return options_;
}

void LocalSocketGetExtraOptionsContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsWithoutOptions(params, paramsCount)) {
        return;
    }
    if (paramsCount != PARAM_NONE) {
        SetParseOK(SetCallback(params[0]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

LocalExtraOptions &LocalSocketGetExtraOptionsContext::GetOptionsRef()
{
    return options_;
}

void LocalSocketGetLocalAddressContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (paramsCount != PARAM_NONE) {
        NETSTACK_LOGE("get local address param error");
        SetNeedThrowException(true);
        SetError(PARSE_ERROR_CODE, PARSE_ERROR_MSG);
        return;
    }
    SetParseOK(true);
}

void LocalSocketGetLocalAddressContext::SetSocketPath(const std::string socketPath)
{
    socketPath_ = socketPath;
}

std::string LocalSocketGetLocalAddressContext::GetSocketPath()
{
    return socketPath_;
}
} // namespace OHOS::NetStack::Socket
