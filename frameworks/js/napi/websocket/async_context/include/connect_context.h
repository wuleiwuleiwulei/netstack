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

#ifndef COMMUNICATIONNETSTACK_CONNECT_CONTEXT_H
#define COMMUNICATIONNETSTACK_CONNECT_CONTEXT_H

#include <map>
#include <string>

#include "base_context.h"
#include "constant.h"
#include "nocopyable.h"
#include "libwebsockets.h"
#include "secure_char.h"

namespace OHOS::NetStack::Websocket {
class ConnectContext final : public BaseContext {
public:
    friend class WebSocketExec;
    DISALLOW_COPY_AND_MOVE(ConnectContext);

    ConnectContext() = delete;

    ConnectContext(napi_env env, const std::shared_ptr<EventManager> &manager);

    ~ConnectContext() override;

    void ParseParams(napi_value *params, size_t paramsCount) override;

    void SetClientCert(std::string &cert, Secure::SecureChar &key, Secure::SecureChar &keyPassword);

    void GetClientCert(std::string &cert, Secure::SecureChar &key, Secure::SecureChar &keyPassword);

    void SetProtocol(std::string protocol);

    [[nodiscard]] std::string GetProtocol() const;

    void SetWebsocketProxyType(WebsocketProxyType type);

    [[nodiscard]] WebsocketProxyType GetUsingWebsocketProxyType() const;

    void SetSpecifiedWebsocketProxy(const std::string &host, int32_t port, const std::string &exclusionList);

    void GetSpecifiedWebsocketProxy(std::string &host, uint32_t &port, std::string &exclusionList) const;

    [[nodiscard]] int32_t GetErrorCode() const override;

    [[nodiscard]] std::string GetErrorMessage() const override;

    void SetAtomicService(bool isAtomicService);

    [[nodiscard]] bool IsAtomicService() const;

    void SetBundleName(const std::string &bundleName);

    [[nodiscard]] std::string GetBundleName() const;

    std::string url;

    std::map<std::string, std::string> header;

    std::string caPath_;

    std::string clientCert_;

    bool skipServerCertVerification_ = false;

    Secure::SecureChar clientKey_;

    Secure::SecureChar keyPassword_;

    std::string websocketProtocol_;

    WebsocketProxyType usingWebsocketProxyType_ = WebsocketProxyType::USE_SYSTEM;

    std::string websocketProxyHost_;

    int32_t websocketProxyPort_ = 0;

    std::string websocketProxyExclusions_;

    bool isAtomicService_ = false;

    std::string bundleName_;

    constexpr static std::uint32_t defaultPingInterval = 30;
 
    constexpr static std::uint32_t minPingInterval = 0;
 
    constexpr static std::uint32_t maxPingInterval = 30000;
 
    std::uint32_t pingInterval_ = defaultPingInterval;
 
    std::uint32_t pongTimeout_ = defaultPingInterval;

private:
    std::string userCertPath_;

    void ParseHeader(napi_value optionsValue);

    void ParseCaPath(napi_value optionsValue);

    void ParseSkipServerCertVerify(napi_value optionsValue);

    void ParseClientCert(napi_value optionsValue);

    bool ParseProxy(napi_value optionsValue);

    bool ParseProtocol(napi_value optionsValue);

    void ParsePingInterval(napi_value optionsValue);
 
    void ParsePongTimeout(napi_value optionsValue);

    bool CheckParamsType(napi_value *params, size_t paramsCount);

    void ParseCallback(napi_value const *params, size_t paramsCount);

    void ParseParamsCountThree(napi_value const *params);
};
} // namespace OHOS::NetStack::Websocket

#endif /* COMMUNICATIONNETSTACK_CONNECT_CONTEXT_H */
