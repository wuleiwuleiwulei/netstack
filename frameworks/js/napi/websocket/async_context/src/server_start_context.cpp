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

#include "server_start_context.h"
#include "constant.h"
#include "netstack_log.h"
#include "napi_utils.h"

namespace OHOS::NetStack::Websocket {
ServerStartContext::ServerStartContext(napi_env env, const std::shared_ptr<EventManager> &sharedManager)
    : BaseContext(env, sharedManager) {}

ServerStartContext::~ServerStartContext() = default;

void ServerStartContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsType(params, paramsCount)) {
        ParseCallback(params, paramsCount);
        return;
    }

    if (paramsCount == FUNCTION_PARAM_ONE) {
        napi_env env = GetEnv();
        if (ParseRequiredParams(env, params[0])) {
            ParseOptionalParams(env, params[0]);
            SetParseOK(true);
            return;
        }
        SetParseOK(false);
        return;
    }

    if (paramsCount == FUNCTION_PARAM_TWO) {
        napi_env env = GetEnv();
        if (!ParseRequiredParams(env, params[0])) {
            SetParseOK(false);
            return;
        }
        ParseOptionalParams(env, params[0]);
        ParseNewBoolParam(params[1]);
        SetParseOK(true);
        return;
    }
    SetParseOK(false);
}

void ServerStartContext::ParseNewBoolParam(napi_value boolParam)
{
    if (boolParam == nullptr) {
        NETSTACK_LOGE("new bool param is null, use default: false");
        ServerStartContext::SetNeedNewErrorCode(false);
        return;
    }

    napi_env env = GetEnv();
    napi_valuetype type = NapiUtils::GetValueType(env, boolParam);
    if (type == napi_boolean) {
        bool value = false;
        napi_get_value_bool(env, boolParam, &value);
        ServerStartContext::SetNeedNewErrorCode(value);
        NETSTACK_LOGD("parse new bool param success: %d", value);
    }
    return;
}

bool ServerStartContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == FUNCTION_PARAM_ZERO) {
        return true;
    }

    if (paramsCount == FUNCTION_PARAM_ONE) {
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_object;
    }

    if (paramsCount == FUNCTION_PARAM_TWO) {
        bool param_1 = NapiUtils::GetValueType(GetEnv(), params[0]) == napi_object;
        bool param_2 = NapiUtils::GetValueType(GetEnv(), params[1]) == napi_boolean;
        return param_1 && param_2;
    }

    return false;
}

void ServerStartContext::ParseCallback(napi_value const *params, size_t paramsCount)
{
    if (paramsCount == FUNCTION_PARAM_ZERO) {
        return;
    }
    if (paramsCount == FUNCTION_PARAM_ONE) {
        if (NapiUtils::GetValueType(GetEnv(), params[FUNCTION_PARAM_ONE - 1]) == napi_object) {
            SetCallback(params[FUNCTION_PARAM_ONE - 1]);
        }
        return;
    }
}

bool ServerStartContext::ParseRequiredParams(napi_env env, napi_value params)
{
    if (NapiUtils::GetValueType(env, params) != napi_object) {
        NETSTACK_LOGE("js type error");
        return false;
    }
    uint32_t serverPort = NapiUtils::GetUint32Property(env, params, ContextKey::SERVER_PORT);
    if (serverPort == 0) {
        NETSTACK_LOGE("%{public}s not found", ContextKey::SERVER_PORT);
    }
    SetServerPort(serverPort);
    uint32_t maxClientCnt = NapiUtils::GetUint32Property(env, params, ContextKey::MAX_CLIENT_NUMBER);
    if (maxClientCnt == 0) {
        NETSTACK_LOGE("max concurrent clients number is %{public}d", maxClientCnt);
    }
    SetMaxConcurrentClientsNumber(maxClientCnt);
    uint32_t maxConn = NapiUtils::GetUint32Property(env, params, ContextKey::MAX_CONNECTIONS_FOR_ONE_CLIENT);
    if (maxConn == 0) {
        NETSTACK_LOGE("max connections for one clients:%{public}d", maxConn);
    }
    SetMaxConnectionsForOneClient(maxConn);
    return true;
}

void ServerStartContext::ParseOptionalParams(napi_env env, napi_value params)
{
    if (NapiUtils::GetValueType(env, params) != napi_object) {
        NETSTACK_LOGE("js type error");
        return;
    }
    NETSTACK_LOGE("SERVER_IP:%{public}s", ContextKey::SERVER_IP);
    std::string ip = NapiUtils::GetStringPropertyUtf8(env, params, ContextKey::SERVER_IP);
    if (ip != "") {
        SetServerIP(ip);
    } else {
        NETSTACK_LOGE("ip is null");
        std::string ipTmp = "0.0.0.0";
        SetServerIP(ipTmp);
    }
    std::string protocol = NapiUtils::GetStringPropertyUtf8(env, params, ContextKey::PROTOCOL);
    if (protocol != "") {
        SetServerProtocol(protocol);
    } else {
        NETSTACK_LOGE("protocol is null");
        std::string ipTmp = "lws_server";
        SetServerProtocol(ipTmp);
    }
    napi_value jsServerCert = NapiUtils::GetNamedProperty(env, params, ContextKey::SERVER_CERT);
    if (NapiUtils::GetValueType(env, jsServerCert) != napi_object) {
        NETSTACK_LOGE("jsServerCert type error");
        return;
    }
    ParseServerCert(env, jsServerCert);
}

void ServerStartContext::ParseServerCert(napi_env env, napi_value params)
{
    if (NapiUtils::GetValueType(env, params) != napi_object) {
        NETSTACK_LOGE("js type error");
        return;
    }
    std::string certPath = NapiUtils::GetStringPropertyUtf8(env, params, ContextKey::CERT_PATH);
    std::string keyPath = NapiUtils::GetStringPropertyUtf8(env, params, ContextKey::KEY_PATH);
    SetServerCert(certPath, keyPath);
}

void ServerStartContext::SetNeedNewErrorCode(bool needNewErrorCode)
{
    needNewErrorCode_ = needNewErrorCode;
}

void ServerStartContext::SetServerIP(std::string &ip)
{
    serverIp_ = ip;
}

void ServerStartContext::SetServerPort(uint32_t &serverPort)
{
    serverPort_ = serverPort;
}

void ServerStartContext::SetServerCert(std::string &certPath, std::string &keyPath)
{
    certPath_ = certPath;
    keyPath_ = keyPath;
}

void ServerStartContext::SetMaxConcurrentClientsNumber(uint32_t &clientsNumber)
{
    maxClientsNumber_ = clientsNumber;
}

void ServerStartContext::SetServerProtocol(std::string &protocol)
{
    websocketServerProtocol_ = protocol;
}

void ServerStartContext::SetMaxConnectionsForOneClient(uint32_t &count)
{
    maxCountForOneClient_ = count;
}

std::string ServerStartContext::GetServerIP() const
{
    return serverIp_;
}

bool ServerStartContext::GetNeedNewErrorCode() const
{
    return needNewErrorCode_;
}

uint32_t ServerStartContext::GetServerPort() const
{
    return serverPort_;
}

void ServerStartContext::GetServerCert(std::string &certPath, std::string &keyPath) const
{
    certPath = certPath_;
    keyPath = keyPath_;
}

uint32_t ServerStartContext::GetMaxConcurrentClientsNumber() const
{
    return maxClientsNumber_;
}

std::string ServerStartContext::GetServerProtocol() const
{
    return websocketServerProtocol_;
}

uint32_t ServerStartContext::GetMaxConnectionsForOneClient() const
{
    return maxCountForOneClient_;
}

int32_t ServerStartContext::GetErrorCode() const
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

std::string ServerStartContext::GetErrorMessage() const
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