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

#include "net_websocket_connect_context.h"

#include "net_websocket_utils.h"

namespace OHOS::NetStack::NetWebSocket {
WebSocketConnectContext::WebSocketConnectContext(CJWebsocketProxy* websocketProxy)
    : WebSocketBaseContext(websocketProxy)
{
}

WebSocketConnectContext::~WebSocketConnectContext() = default;

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
    if (url.find('/', posStart) > queryPos) {
        url.insert(queryPos, 1, '/');
    }
}

void WebSocketConnectContext::ParseParams(std::string url, CWebSocketRequestOptions *opt)
{
    this->url = url;
    AddSlashBeforeQuery(url);
    if (opt != nullptr) {
        ParseHeader(opt->header);
        if (opt->caPath != nullptr) {
            caPath_ = std::string{opt->caPath};
        }
        if (opt->clientCert != nullptr) {
            std::string certPath{opt->clientCert->certPath};
            SecureChar keySecure;
            if (opt->clientCert->keyPath != nullptr) {
                keySecure = SecureChar(opt->clientCert->keyPath);
            } else {
                keySecure = SecureChar("");
            }
            SecureChar keyPasswd;
            if (opt->clientCert->keyPassword != nullptr) {
                keyPasswd = SecureChar(opt->clientCert->keyPassword);
            } else {
                keyPasswd = SecureChar("");
            }
            SetClientCert(certPath, keySecure, keyPasswd);
        }
        if (opt->protocol != nullptr) {
            SetProtocol(std::string{opt->protocol});
        }
        ParseProxy(opt->httpProxy, opt->usingSystemProxy);
    }
    SetParseOK(true);
}

void WebSocketConnectContext::SetClientCert(std::string &cert, SecureChar &key, SecureChar &keyPassword)
{
    clientCert_ = cert;
    clientKey_ = key;
    keyPassword_ = keyPassword;
}

void WebSocketConnectContext::GetClientCert(std::string &cert, SecureChar &key, SecureChar &keyPassword)
{
    cert = clientCert_;
    key = clientKey_;
    keyPassword = keyPassword_;
}

void WebSocketConnectContext::SetProtocol(std::string protocol)
{
    websocketProtocol_ = std::move(protocol);
}

std::string WebSocketConnectContext::GetProtocol() const
{
    return websocketProtocol_;
}

void WebSocketConnectContext::SetWebsocketProxyType(WebsocketProxyType type)
{
    usingWebsocketProxyType_ = type;
}

WebsocketProxyType WebSocketConnectContext::GetUsingWebsocketProxyType() const
{
    return usingWebsocketProxyType_;
}

void WebSocketConnectContext::SetSpecifiedWebsocketProxy(const std::string &host,
    int32_t port, const std::string &exclusionList)
{
    websocketProxyHost_ = host;
    websocketProxyPort_ = port;
    websocketProxyExclusions_ = exclusionList;
}

void WebSocketConnectContext::GetSpecifiedWebsocketProxy(std::string &host, uint32_t &port,
    std::string &exclusionList) const
{
    host = websocketProxyHost_;
    port = websocketProxyPort_;
    exclusionList = websocketProxyExclusions_;
}

int32_t WebSocketConnectContext::GetErrorCode() const
{
    if (WebSocketBaseContext::IsPermissionDenied()) {
        return WEBSOCKET_PERMISSION_DENIED_CODE;
    }
    auto err = WebSocketBaseContext::GetErrorCode();
    if (WEBSOCKET_ERR_MAP.find(err) != WEBSOCKET_ERR_MAP.end()) {
        return err;
    }
    return WEBSOCKET_UNKNOWN_OTHER_ERROR;
}

std::string WebSocketConnectContext::GetErrorMessage() const
{
    auto err = WebSocketBaseContext::GetErrorCode();
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

void WebSocketConnectContext::ParseHeader(CArrString header)
{
    if (header.head == nullptr || header.size == 0) {
        return;
    }
    for (int i = 0; i < header.size; i += MAP_TUPLE_SIZE) {
        std::string key{header.head[i]};
        std::string value{header.head[i + 1]};
        this->header[key] = value;
    }
}

void WebSocketConnectContext::ParseProxy(CHttpProxy* proxy, bool useDefault)
{
    if (proxy != nullptr) {
        SetWebsocketProxyType(WebsocketProxyType::USE_SPECIFIED);
        std::string host{proxy->host};
        std::string exclusionList;
        for (int i = 0; i < proxy->exclusionListSize; i++) {
            if (i != 0) {
                exclusionList = exclusionList + WEBSOCKET_PROXY_EXCLUSIONS_SEPARATOR;
            }
            exclusionList += std::string{proxy->exclusionList[i]};
        }
        SetSpecifiedWebsocketProxy(host, proxy->port, exclusionList);
    } else {
        SetWebsocketProxyType(useDefault ? WebsocketProxyType::USE_SYSTEM : WebsocketProxyType::NOT_USE);
    }
}
}
