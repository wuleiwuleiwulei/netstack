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

#ifndef NET_WEBSOCKET_CONNECT_CONTEXT_H
#define NET_WEBSOCKET_CONNECT_CONTEXT_H

#include <map>
#include <string>

#include "constant.h"
#include "secure_char.h"
#include "ffi_structs.h"
#include "net_websocket_utils.h"
#include "net_websocket_base_context.h"

namespace OHOS::NetStack::NetWebSocket {
    
class CJWebsocketProxy;

class WebSocketConnectContext : public WebSocketBaseContext {
public:
    friend class NetWebSocketExec;
    WebSocketConnectContext() = delete;

    WebSocketConnectContext(CJWebsocketProxy* websocketProxy);

    virtual ~WebSocketConnectContext();

    void ParseParams(std::string url, CWebSocketRequestOptions *opt);

    void SetClientCert(std::string &cert, SecureChar &key, SecureChar &keyPassword);

    void GetClientCert(std::string &cert, SecureChar &key, SecureChar &keyPassword);

    void SetProtocol(std::string protocol);

    [[nodiscard]] std::string GetProtocol() const;

    void SetWebsocketProxyType(WebsocketProxyType type);

    [[nodiscard]] WebsocketProxyType GetUsingWebsocketProxyType() const;

    void SetSpecifiedWebsocketProxy(const std::string &host, int32_t port, const std::string &exclusionList);

    void GetSpecifiedWebsocketProxy(std::string &host, uint32_t &port, std::string &exclusionList) const;

    std::string url;

    std::map<std::string, std::string> header;

    std::string caPath_;

    std::string clientCert_;

    SecureChar clientKey_;

    SecureChar keyPassword_;

    std::string websocketProtocol_;

    WebsocketProxyType usingWebsocketProxyType_ = WebsocketProxyType::USE_SYSTEM;

    std::string websocketProxyHost_;

    int32_t websocketProxyPort_ = 0;

    std::string websocketProxyExclusions_;

    [[nodiscard]] int32_t GetErrorCode() const override;

    [[nodiscard]] std::string GetErrorMessage() const override;
private:
    std::string userCertPath_;
    
    void ParseHeader(CArrString header);

    void ParseProxy(CHttpProxy* proxy, bool useDefault);
};
}
#endif