/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "connect_context.h"
#include "constant.h"
#include "napi_utils.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "securec.h"
#include <utility>

namespace OHOS::NetStack::Websocket {
ConnectContext::ConnectContext(napi_env env, const std::shared_ptr<EventManager> &manager)
    : BaseContext(env, manager)
{
}

ConnectContext::~ConnectContext() = default;

static void AddSlashBeforeQuery(std::string &url)
{
    if (url.empty()) {
        return;
    }
    std::string delimiter = "://";
    size_t posStart = url.find(delimiter);
    if (posStart != std::string::npos) {
        posStart += delimiter.length();
    } else {
        posStart = 0;
    }
    size_t notSlash = url.find_first_not_of('/', posStart);
    if (notSlash != std::string::npos) {
        posStart = notSlash;
    }
    auto queryPos = url.find('?', posStart);
    if (queryPos == std::string::npos) {
        return;
    }
    auto posSlash = url.find('/', posStart);
    if (posSlash == std::string::npos || posSlash > queryPos) {
        url.insert(queryPos, 1, '/');
    }
}

void ConnectContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsType(params, paramsCount)) {
        ParseCallback(params, paramsCount);
        return;
    }

    if (paramsCount == FUNCTION_PARAM_ONE) {
        if (NapiUtils::GetValueType(GetEnv(), params[0]) == napi_string) {
            url = NapiUtils::GetStringFromValueUtf8(GetEnv(), params[0]);
            AddSlashBeforeQuery(url);
            SetParseOK(true);
        }
        return;
    }
    if (paramsCount == FUNCTION_PARAM_TWO) {
        if (NapiUtils::GetValueType(GetEnv(), params[0]) == napi_string) {
            url = NapiUtils::GetStringFromValueUtf8(GetEnv(), params[0]);
            AddSlashBeforeQuery(url);
        }
        if (NapiUtils::GetValueType(GetEnv(), params[1]) == napi_function) {
            return SetParseOK(SetCallback(params[1]) == napi_ok);
        }
        if (NapiUtils::GetValueType(GetEnv(), params[1]) == napi_object) {
            ParseHeader(params[1]);
            ParseCaPath(params[1]);
            ParseClientCert(params[1]);
            ParseSkipServerCertVerify(params[1]);
            ParsePingInterval(params[1]);
            ParsePongTimeout(params[1]);
            if (!ParseProxy(params[1]) || !ParseProtocol(params[1])) {
                return;
            }
            return SetParseOK(true);
        }
    }
    if (paramsCount == FUNCTION_PARAM_THREE) {
        ParseParamsCountThree(params);
    }
}

void ConnectContext::ParseCallback(napi_value const *params, size_t paramsCount)
{
    if (paramsCount == FUNCTION_PARAM_ONE) {
        if (NapiUtils::GetValueType(GetEnv(), params[FUNCTION_PARAM_ONE - 1]) == napi_function) {
            SetCallback(params[FUNCTION_PARAM_ONE - 1]);
        }
        return;
    }

    if (paramsCount == FUNCTION_PARAM_TWO) {
        if (NapiUtils::GetValueType(GetEnv(), params[FUNCTION_PARAM_TWO - 1]) == napi_function) {
            SetCallback(params[FUNCTION_PARAM_TWO - 1]);
        }
        return;
    }

    if (paramsCount == FUNCTION_PARAM_THREE) {
        if (NapiUtils::GetValueType(GetEnv(), params[FUNCTION_PARAM_THREE - 1]) == napi_function) {
            SetCallback(params[FUNCTION_PARAM_THREE - 1]);
        }
        return;
    }
}

void ConnectContext::ParseParamsCountThree(napi_value const *params)
{
    if (NapiUtils::GetValueType(GetEnv(), params[0]) == napi_string) {
        url = NapiUtils::GetStringFromValueUtf8(GetEnv(), params[0]);
        AddSlashBeforeQuery(url);
    }
    if (NapiUtils::GetValueType(GetEnv(), params[1]) == napi_object) {
        ParseHeader(params[1]);
        ParseCaPath(params[1]);
        ParseClientCert(params[1]);
        ParseSkipServerCertVerify(params[1]);
        ParsePingInterval(params[1]);
        ParsePongTimeout(params[1]);
        if (!ParseProxy(params[1]) || !ParseProtocol(params[1])) {
            if (NapiUtils::GetValueType(GetEnv(), params[FUNCTION_PARAM_THREE - 1]) == napi_function) {
                SetCallback(params[FUNCTION_PARAM_THREE - 1]);
                return;
            }
            return;
        }
    }
    if (NapiUtils::GetValueType(GetEnv(), params[FUNCTION_PARAM_THREE - 1]) == napi_function) {
        return SetParseOK(SetCallback(params[FUNCTION_PARAM_THREE - 1]) == napi_ok);
    }
}

void ConnectContext::ParseHeader(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, ContextKey::HEADER)) {
        return;
    }
    napi_value jsHeader = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, ContextKey::HEADER);
    if (NapiUtils::GetValueType(GetEnv(), jsHeader) != napi_object) {
        return;
    }
    auto names = NapiUtils::GetPropertyNames(GetEnv(), jsHeader);
    std::for_each(names.begin(), names.end(), [jsHeader, this](const std::string &name) {
        auto value = NapiUtils::GetStringPropertyUtf8(GetEnv(), jsHeader, name);
        if (!value.empty()) {
            // header key ignores key but value not
            header[CommonUtils::ToLower(name)] = value;
        }
    });
}

void ConnectContext::ParseCaPath(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, ContextKey::CAPATH)) {
        NETSTACK_LOGI("ConnectContext CAPATH not found");
        return;
    }
    napi_value jsCaPath = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, ContextKey::CAPATH);
    if (NapiUtils::GetValueType(GetEnv(), jsCaPath) != napi_string) {
        return;
    }
    caPath_ = NapiUtils::GetStringPropertyUtf8(GetEnv(), optionsValue, ContextKey::CAPATH);
}

void ConnectContext::GetClientCert(std::string &cert, Secure::SecureChar &key, Secure::SecureChar &keyPassword)
{
    cert = clientCert_;
    key = clientKey_;
    keyPassword = keyPassword_;
}

void ConnectContext::SetClientCert(std::string &cert, Secure::SecureChar &key, Secure::SecureChar &keyPassword)
{
    clientCert_ = cert;
    clientKey_ = key;
    keyPassword_ = keyPassword;
}

void ConnectContext::ParseClientCert(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, ContextKey::CLIENT_CERT)) {
        NETSTACK_LOGI("ConnectContext CLIENT_CERT not found");
        return;
    }
    napi_value jsCert = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, ContextKey::CLIENT_CERT);
    napi_valuetype type = NapiUtils::GetValueType(GetEnv(), jsCert);
    if (type != napi_object || type == napi_undefined) {
        return;
    }
    std::string certPath = NapiUtils::GetStringPropertyUtf8(GetEnv(), jsCert, ContextKey::CERT_PATH);
    Secure::SecureChar keyPath =
        Secure::SecureChar(NapiUtils::GetStringPropertyUtf8(GetEnv(), jsCert, ContextKey::KEY_PATH));
    Secure::SecureChar keyPassword =
        Secure::SecureChar(NapiUtils::GetStringPropertyUtf8(GetEnv(), jsCert, ContextKey::KEY_PASSWD));
    SetClientCert(certPath, keyPath, keyPassword);
}

void ConnectContext::ParseSkipServerCertVerify(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, ContextKey::KEY_SKIP_SERVER_CERT_VERIFY)) {
        return;
    }
    napi_value jsVal = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, ContextKey::KEY_SKIP_SERVER_CERT_VERIFY);
    if (NapiUtils::GetValueType(GetEnv(), jsVal) != napi_boolean) {
        return;
    }
    skipServerCertVerification_ = NapiUtils::GetBooleanProperty(GetEnv(), optionsValue,
        ContextKey::KEY_SKIP_SERVER_CERT_VERIFY);
}

bool ConnectContext::ParseProxy(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, ContextKey::PROXY)) {
        SetWebsocketProxyType(WebsocketProxyType::USE_SYSTEM);
        NETSTACK_LOGD("websocket connect proxy not found, use system proxy");
        return true;
    }
    napi_value websocketProxyValue = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, ContextKey::PROXY);
    napi_valuetype type = NapiUtils::GetValueType(GetEnv(), websocketProxyValue);
    if (type == napi_string) {
        std::string proxyStr = NapiUtils::GetStringFromValueUtf8(GetEnv(), websocketProxyValue);
        if (proxyStr == ContextKey::NOT_USE_PROXY) {
            SetWebsocketProxyType(WebsocketProxyType::NOT_USE);
            return true;
        } else if (proxyStr == ContextKey::USE_SYSTEM_PROXY) {
            SetWebsocketProxyType(WebsocketProxyType::USE_SYSTEM);
            return true;
        } else {
            NETSTACK_LOGE("websocket proxy param parse failed!");
            return false;
        }
    }
    if (type != napi_object) {
        NETSTACK_LOGE("websocket proxy param parse failed!");
        return false;
    }

    std::string exclusionList;
    std::string host =
        NapiUtils::GetStringPropertyUtf8(GetEnv(), websocketProxyValue, ContextKey::WEBSOCKET_PROXY_HOST);
    int32_t port = NapiUtils::GetInt32Property(GetEnv(), websocketProxyValue, ContextKey::WEBSOCKET_PROXY_PORT);
    if (NapiUtils::HasNamedProperty(GetEnv(), websocketProxyValue, ContextKey::WEBSOCKET_PROXY_EXCLUSION_LIST)) {
        napi_value exclusionListValue =
            NapiUtils::GetNamedProperty(GetEnv(), websocketProxyValue, ContextKey::WEBSOCKET_PROXY_EXCLUSION_LIST);
        uint32_t listLength = NapiUtils::GetArrayLength(GetEnv(), exclusionListValue);
        for (uint32_t index = 0; index < listLength; ++index) {
            napi_value exclusionValue = NapiUtils::GetArrayElement(GetEnv(), exclusionListValue, index);
            std::string exclusion = NapiUtils::GetStringFromValueUtf8(GetEnv(), exclusionValue);
            if (index != 0) {
                exclusionList.append(ContextKey::WEBSOCKET_PROXY_EXCLUSIONS_SEPARATOR);
            }
            exclusionList += exclusion;
        }
    }
    SetSpecifiedWebsocketProxy(host, port, exclusionList);
    SetWebsocketProxyType(WebsocketProxyType::USE_SPECIFIED);
    return true;
}

bool ConnectContext::ParseProtocol(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, ContextKey::PROTCOL)) {
        NETSTACK_LOGD("websocket connect protocol not found");
        return true;
    }
    napi_value jsProtocol = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, ContextKey::PROTCOL);
    if (NapiUtils::GetValueType(GetEnv(), jsProtocol) == napi_string) {
        SetProtocol(NapiUtils::GetStringPropertyUtf8(GetEnv(), optionsValue, ContextKey::PROTCOL));
        return true;
    }
    NETSTACK_LOGE("websocket connect protocol param parse failed");
    return false;
}

void ConnectContext::ParsePingInterval(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, ContextKey::PING_INTERVAL)) {
        NETSTACK_LOGI("ConnectContext PING_INTERVAL not found");
        return;
    }
    napi_value jsPingInterval = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, ContextKey::PING_INTERVAL);
    if (NapiUtils::GetValueType(GetEnv(), jsPingInterval) != napi_number) {
        NETSTACK_LOGI("ConnectContext PING_INTERVAL is not napi_number");
        return;
    }
    pingInterval_ = NapiUtils::GetUint32FromValue(GetEnv(), jsPingInterval);
}
 
void ConnectContext::ParsePongTimeout(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, ContextKey::PONG_TIMEOUT)) {
        NETSTACK_LOGI("ConnectContext PONG_TIMEOUT not found");
        return;
    }
    napi_value jsPongTimeout = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, ContextKey::PONG_TIMEOUT);
    if (NapiUtils::GetValueType(GetEnv(), jsPongTimeout) != napi_number) {
        NETSTACK_LOGI("ConnectContext PONG_TIMEOUT is not napi_number");
        return;
    }
    pongTimeout_ = NapiUtils::GetUint32FromValue(GetEnv(), jsPongTimeout);
}

bool ConnectContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == FUNCTION_PARAM_ONE) {
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_string;
    }
    if (paramsCount == FUNCTION_PARAM_TWO) {
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_string &&
               (NapiUtils::GetValueType(GetEnv(), params[1]) == napi_function ||
                NapiUtils::GetValueType(GetEnv(), params[1]) == napi_object);
    }
    if (paramsCount == FUNCTION_PARAM_THREE) {
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_string &&
               NapiUtils::GetValueType(GetEnv(), params[1]) == napi_object &&
               NapiUtils::GetValueType(GetEnv(), params[FUNCTION_PARAM_THREE - 1]) == napi_function;
    }
    return false;
}

void ConnectContext::SetProtocol(std::string protocol)
{
    websocketProtocol_ = std::move(protocol);
}

std::string ConnectContext::GetProtocol() const
{
    return websocketProtocol_;
}

void ConnectContext::SetWebsocketProxyType(WebsocketProxyType type)
{
    usingWebsocketProxyType_ = type;
}

WebsocketProxyType ConnectContext::GetUsingWebsocketProxyType() const
{
    return usingWebsocketProxyType_;
}

void ConnectContext::SetSpecifiedWebsocketProxy(const std::string &host, int32_t port, const std::string &exclusionList)
{
    websocketProxyHost_ = host;
    websocketProxyPort_ = port;
    websocketProxyExclusions_ = exclusionList;
}

void ConnectContext::GetSpecifiedWebsocketProxy(std::string &host, uint32_t &port, std::string &exclusionList) const
{
    host = websocketProxyHost_;
    port = websocketProxyPort_;
    exclusionList = websocketProxyExclusions_;
}

int32_t ConnectContext::GetErrorCode() const
{
    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_CODE;
    }
    if (BaseContext::IsNoAllowedHost()) {
        return WEBSOCKET_NOT_ALLOWED_HOST;
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

std::string ConnectContext::GetErrorMessage() const
{
    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_MSG;
    }
    if (BaseContext::IsNoAllowedHost()) {
        return WEBSOCKET_ERR_MAP.at(WEBSOCKET_NOT_ALLOWED_HOST);
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

bool ConnectContext::IsAtomicService() const
{
    return isAtomicService_;
}

void ConnectContext::SetAtomicService(bool isAtomicService)
{
    isAtomicService_ = isAtomicService;
}

void ConnectContext::SetBundleName(const std::string &bundleName)
{
    bundleName_ = bundleName;
}

std::string ConnectContext::GetBundleName() const
{
    return bundleName_;
}
} // namespace OHOS::NetStack::Websocket
