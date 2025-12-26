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

#ifndef COMMUNICATIONNETSTACK_SERVER_START_CONTEXT_H
#define COMMUNICATIONNETSTACK_SERVER_START_CONTEXT_H

#include <string>

#include "base_context.h"
#include "libwebsockets.h"
#include "nocopyable.h"

namespace OHOS::NetStack::Websocket {
class ServerStartContext final : public BaseContext {
public:
    DISALLOW_COPY_AND_MOVE(ServerStartContext);

    ServerStartContext() = delete;

    ServerStartContext(napi_env env, const std::shared_ptr<EventManager> &sharedManager);

    ~ServerStartContext() override;

    void ParseParams(napi_value *params, size_t paramsCount) override;

    void SetServerIP(std::string &ip);

    [[nodiscard]] std::string GetServerIP() const;

    void SetServerPort(uint32_t &serverPort);

    [[nodiscard]] uint32_t GetServerPort() const;

    void SetServerCert(std::string &certPath, std::string &keyPath);

    void GetServerCert(std::string &certPath, std::string &keyPath) const;

    void SetMaxConcurrentClientsNumber(uint32_t &clientsNumber);

    [[nodiscard]] uint32_t GetMaxConcurrentClientsNumber() const;

    void SetServerProtocol(std::string &protocol);

    [[nodiscard]] std::string GetServerProtocol() const;

    void SetMaxConnectionsForOneClient(uint32_t &count);

    [[nodiscard]] uint32_t GetMaxConnectionsForOneClient() const;

    [[nodiscard]] int32_t GetErrorCode() const override;

    [[nodiscard]] std::string GetErrorMessage() const override;

    void SetNeedNewErrorCode(bool needNewErrorCode);

    [[nodiscard]] bool GetNeedNewErrorCode() const;
    
    void ParseNewBoolParam(napi_value boolParam);

    std::string serverIp_;

    uint32_t serverPort_ = 0;

    std::string certPath_;

    std::string keyPath_;

    uint32_t maxClientsNumber_ = 0;

    std::string websocketServerProtocol_;

    uint32_t maxCountForOneClient_ = 0;

    bool needNewErrorCode_ = false;

private:
    bool CheckParamsType(napi_value *params, size_t paramsCount);

    void ParseCallback(napi_value const *params, size_t paramsCount);

    bool ParseRequiredParams(napi_env env, napi_value params);

    void ParseOptionalParams(napi_env env, napi_value params);

    void ParseServerCert(napi_env env, napi_value params);
};
} // namespace OHOS::NetStack::Websocket
#endif /* COMMUNICATIONNETSTACK_SERVER_START_CONTEXT_H */