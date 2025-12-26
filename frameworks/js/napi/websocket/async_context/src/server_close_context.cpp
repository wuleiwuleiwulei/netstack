/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "server_close_context.h"
#include "constant.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "napi_utils.h"

namespace OHOS::NetStack::Websocket {
ServerCloseContext::ServerCloseContext(napi_env env, const std::shared_ptr<EventManager> &manager)
    : BaseContext(env, manager), code(CLOSE_REASON_NORMAL_CLOSE), reason("CLOSE_NORMAL"), connection() {}

ServerCloseContext::~ServerCloseContext() = default;

void ServerCloseContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsType(params, paramsCount)) {
        NETSTACK_LOGE("ServerCloseContext Parse Failed");
        if (paramsCount == FUNCTION_PARAM_ONE) {
            if (NapiUtils::GetValueType(GetEnv(), params[0]) == napi_function) {
                SetCallback(params[0]);
            }
            return;
        }

        if (paramsCount == FUNCTION_PARAM_TWO) {
            if (NapiUtils::GetValueType(GetEnv(), params[1]) == napi_function) {
                SetCallback(params[1]);
            }
            return;
        }
        return;
    }

    if (paramsCount == FUNCTION_PARAM_ONE) {
        NETSTACK_LOGI("paramsCount is one");
        if (!HandleParseConnection(GetEnv(), params[0])) {
            return;
        }
    }

    if (paramsCount == FUNCTION_PARAM_TWO) {
        NETSTACK_LOGI("paramsCount is two");
        if (!HandleParseConnection(GetEnv(), params[0])) {
            return;
        }
        if (!HandleParseCloseOption(GetEnv(), params[1])) {
            return;
        }
    }
    NETSTACK_LOGI("ServerCloseContext Parse OK");
    return SetParseOK(true);
}

bool ServerCloseContext::HandleParseConnection(napi_env env, napi_value params)
{
    NETSTACK_LOGI("HandleParseConnection enter");
    if (NapiUtils::GetValueType(env, params) == napi_object) {
        connection.clientPort = NapiUtils::GetUint32Property(env, params, ContextKey::CLIENT_PORT);
        if (connection.clientPort == 0) {
            NETSTACK_LOGE("parse clientPort failed");
        }
        connection.clientIP = NapiUtils::GetStringPropertyUtf8(env, params, ContextKey::CLIENT_IP);
        if (connection.clientIP == "") {
            NETSTACK_LOGE("parse clientIP failed");
        }
        return true;
    }
    return false;
}

bool ServerCloseContext::HandleParseCloseOption(napi_env env, napi_value params)
{
    if (NapiUtils::GetValueType(env, params) == napi_object) {
        uint32_t closeCode = NapiUtils::GetUint32Property(env, params, ContextKey::CODE);
        if (closeCode >= CLOSE_REASON_NORMAL_CLOSE && closeCode <= CLOSE_REASON_RESERVED12) {
            code = closeCode;
        }
        std::string tempReason = NapiUtils::GetStringPropertyUtf8(env, params, ContextKey::REASON);
        if (!tempReason.empty()) {
            reason = tempReason;
        }
        return true;
    }
    return false;
}

bool ServerCloseContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == FUNCTION_PARAM_ONE) {
        NETSTACK_LOGI("paramsCount one");
        return IsValidWebsocketConnection(GetEnv(), params[0]);
    }

    if (paramsCount == FUNCTION_PARAM_TWO) {
        NETSTACK_LOGI("paramsCount two");
        return IsValidWebsocketConnection(GetEnv(), params[0]) &&
            IsValidCloseOptions(GetEnv(), params[1]);
    }
    return false;
}

bool ServerCloseContext::IsValidWebsocketConnection(napi_env env, napi_value params)
{
    if (NapiUtils::GetValueType(env, params) != napi_object) {
        return false;
    }
    return (NapiUtils::GetValueType(env, NapiUtils::GetNamedProperty(env, params,
        ContextKey::CLIENT_PORT)) == napi_number) && (NapiUtils::GetValueType(env,
        NapiUtils::GetNamedProperty(env, params, ContextKey::CLIENT_IP)) == napi_string);
}

bool ServerCloseContext::IsValidCloseOptions(napi_env env, napi_value params)
{
    if (NapiUtils::GetValueType(env, params) != napi_object) {
        return false;
    }
    return NapiUtils::GetValueType(env, NapiUtils::GetNamedProperty(env, params,
        ContextKey::CODE)) == napi_number && NapiUtils::GetValueType(env,
        NapiUtils::GetNamedProperty(env, params, ContextKey::REASON)) == napi_string;
}

WebSocketConnection ServerCloseContext::GetConnection() const
{
    return connection;
}

int32_t ServerCloseContext::GetErrorCode() const
{
    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_CODE;
    }

    auto err = BaseContext::GetErrorCode();
    if (err == PARSE_ERROR_CODE) {
        return PARSE_ERROR_CODE;
    }
    if (WEBSOCKET_ERR_MAP.find(err) != WEBSOCKET_ERR_MAP.end()) {
        return err;
    }
    return WEBSOCKET_UNKNOWN_OTHER_ERROR;
}

std::string ServerCloseContext::GetErrorMessage() const
{
    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_MSG;
    }

    auto err = BaseContext::GetErrorCode();
    if (err == PARSE_ERROR_CODE) {
        return PARSE_ERROR_MSG;
    }
    auto it = WEBSOCKET_ERR_MAP.find(err);
    if (it != WEBSOCKET_ERR_MAP.end()) {
        return it->second;
    }
    it = WEBSOCKET_ERR_MAP.find(WEBSOCKET_UNKNOWN_OTHER_ERROR);
    if (it != WEBSOCKET_ERR_MAP.end()) {
        return it->second;
    }
    return {};
}
} // namespace OHOS::NetStack::Websocket