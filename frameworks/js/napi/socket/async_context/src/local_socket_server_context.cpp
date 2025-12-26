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

#include "local_socket_server_context.h"

#include "context_key.h"
#include "event_manager.h"
#include "napi_utils.h"
#include "netstack_log.h"
#include "socket_constant.h"

namespace OHOS::NetStack::Socket {
int LocalSocketServerBaseContext::GetSocketFd() const
{
    if (sharedManager_ == nullptr) {
        return -1;
    }
    LocalSocketServerManager *pManagerInfo = reinterpret_cast<LocalSocketServerManager *>(sharedManager_->GetData());
    return (pManagerInfo != nullptr) ? pManagerInfo->sockfd_ : -1;
}

void LocalSocketServerBaseContext::SetSocketFd(int sock)
{
    if (sharedManager_ == nullptr) {
        return;
    }
    LocalSocketServerManager *pManagerInfo = reinterpret_cast<LocalSocketServerManager *>(sharedManager_->GetData());
    if (pManagerInfo != nullptr) {
        pManagerInfo->sockfd_ = sock;
    }
}

void LocalSocketServerListenContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsWithOptions(params, paramsCount)) {
        return;
    }
    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_ADDRESS)) {
        socketPath_ = NapiUtils::GetStringPropertyUtf8(GetEnv(), params[0], KEY_ADDRESS);
    }
    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        SetParseOK(SetCallback(params[PARAM_OPTIONS_AND_CALLBACK - 1]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

const std::string &LocalSocketServerListenContext::GetSocketPath() const
{
    return socketPath_;
}

void LocalSocketServerEndContext::ParseParams(napi_value *params, size_t paramsCount)
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

void LocalSocketServerGetStateContext::ParseParams(napi_value *params, size_t paramsCount)
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

SocketStateBase &LocalSocketServerGetStateContext::GetStateRef()
{
    return state_;
}

void LocalSocketServerSetExtraOptionsContext::ParseParams(napi_value *params, size_t paramsCount)
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
        SetParseOK(SetCallback(params[PARAM_OPTIONS_AND_CALLBACK - 1]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

LocalExtraOptions &LocalSocketServerSetExtraOptionsContext::GetOptionsRef()
{
    return options_;
}

void LocalSocketServerGetExtraOptionsContext::ParseParams(napi_value *params, size_t paramsCount)
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

LocalExtraOptions &LocalSocketServerGetExtraOptionsContext::GetOptionsRef()
{
    return options_;
}

bool LocalSocketServerSendContext::GetData(napi_value sendOptions)
{
    if (NapiUtils::HasNamedProperty(GetEnv(), sendOptions, KEY_TIMEOUT)) {
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

void LocalSocketServerSendContext::ParseParams(napi_value *params, size_t paramsCount)
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

int LocalSocketServerSendContext::GetAcceptFd()
{
    if (sharedManager_ == nullptr) {
        return -1;
    }
    LocalSocketServerManager *pManagerInfo = reinterpret_cast<LocalSocketServerManager *>(sharedManager_->GetData());
    return (pManagerInfo != nullptr) ? pManagerInfo->GetAcceptFd(clientId_) : -1;
}

LocalSocketOptions &LocalSocketServerSendContext::GetOptionsRef()
{
    return options_;
}

int LocalSocketServerSendContext::GetClientId() const
{
    return clientId_;
}

void LocalSocketServerSendContext::SetClientId(int clientId)
{
    clientId_ = clientId;
}

void LocalSocketServerCloseContext::ParseParams(napi_value *params, size_t paramsCount)
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

int LocalSocketServerCloseContext::GetClientId() const
{
    return clientId_;
}

void LocalSocketServerCloseContext::SetClientId(int clientId)
{
    clientId_ = clientId;
}

void LocalSocketServerGetSocketFdContext::ParseParams(napi_value *params, size_t paramsCount)
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

int LocalSocketServerGetSocketFdContext::GetClientId() const
{
    return clientId_;
}

void LocalSocketServerGetSocketFdContext::SetClientId(int clientId)
{
    clientId_ = clientId;
}

int LocalSocketServerGetSocketFdContext::GetConnectionSocketFd() const
{
    return socketFd_;
}

void LocalSocketServerGetSocketFdContext::SetConnectionSocketFd(int socketFd)
{
    socketFd_ = socketFd;
}

void LocalSocketServerGetLocalAddressContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (paramsCount != PARAM_NONE) {
        NETSTACK_LOGE("get local address param error");
        SetNeedThrowException(true);
        SetError(PARSE_ERROR_CODE, PARSE_ERROR_MSG);
        return;
    }
    SetParseOK(true);
}

void LocalSocketServerGetLocalAddressContext::SetSocketPath(const std::string socketPath)
{
    socketPath_ = socketPath;
}

std::string LocalSocketServerGetLocalAddressContext::GetSocketPath()
{
    return socketPath_;
}

int LocalSocketServerGetLocalAddressContext::GetClientId() const
{
    return clientId_;
}

void LocalSocketServerGetLocalAddressContext::SetClientId(int clientId)
{
    clientId_ = clientId;
}

} // namespace OHOS::NetStack::Socket
