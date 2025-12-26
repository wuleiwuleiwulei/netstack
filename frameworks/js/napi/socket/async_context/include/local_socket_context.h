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

#ifndef LOCAL_SOCKET_CONTEXT_H
#define LOCAL_SOCKET_CONTEXT_H

#include <condition_variable>
#include <cstddef>

#include "base_context.h"
#include "local_socket_options.h"
#include "napi/native_api.h"
#include "nocopyable.h"
#include "socket_state_base.h"

namespace OHOS::NetStack::Socket {
struct SocketBaseManager {
    explicit SocketBaseManager(int sockfd) : sockfd_(sockfd) {}
    int sockfd_ = 0;
};

struct LocalSocketManager : public SocketBaseManager {
    explicit LocalSocketManager(int sockfd) : SocketBaseManager(sockfd) {}
    bool isConnected_ = false;
    std::atomic_bool isSockClosed;

    void SetSocketCloseStatus(bool flag)
    {
        isSockClosed.store(flag, std::memory_order_relaxed);
    }
    bool GetSocketCloseStatus()
    {
        return isSockClosed.load(std::memory_order_relaxed);
    }
}__attribute__((packed));

class LocalSocketBaseContext : public BaseContext {
public:
    DISALLOW_COPY_AND_MOVE(LocalSocketBaseContext);
    virtual ~LocalSocketBaseContext() {}
    LocalSocketBaseContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : BaseContext(env, manager) {}
    [[nodiscard]] virtual int GetSocketFd() const;
    virtual void SetSocketFd(int sock);
    [[nodiscard]] int32_t GetErrorCode() const override;
    [[nodiscard]] std::string GetErrorMessage() const override;

protected:
    bool CheckParamsWithOptions(napi_value *params, size_t paramsCount);
    bool CheckParamsWithoutOptions(napi_value *params, size_t paramsCount);
};

class LocalSocketBindContext final : public LocalSocketBaseContext {
public:
    LocalSocketBindContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketBaseContext(env, manager) {}
    void ParseParams(napi_value *params, size_t paramsCount) override;
    const std::string &GetSocketPath() const;

private:
    std::string socketPath_;
};

class LocalSocketGetLocalAddressContext final : public LocalSocketBaseContext {
public:
    LocalSocketGetLocalAddressContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketBaseContext(env, manager) {}
    void ParseParams(napi_value *params, size_t paramsCount) override;
    void SetSocketPath(const std::string socketPath);
    std::string GetSocketPath();

private:
    std::string socketPath_;
};

class LocalSocketConnectContext final : public LocalSocketBaseContext {
public:
    LocalSocketConnectContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketBaseContext(env, manager) {}
    void ParseParams(napi_value *params, size_t paramsCount) override;
    const std::string &GetSocketPath() const;
    int GetTimeoutMs() const;

private:
    std::string socketPath_;
    int timeout_ = 0;
};

class LocalSocketSendContext final : public LocalSocketBaseContext {
public:
    LocalSocketSendContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketBaseContext(env, manager) {}
    void ParseParams(napi_value *params, size_t paramsCount) override;
    LocalSocketOptions &GetOptionsRef();

private:
    bool GetData(napi_value sendOptions);
    LocalSocketOptions options_;
};

class LocalSocketCloseContext final : public LocalSocketBaseContext {
public:
    LocalSocketCloseContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketBaseContext(env, manager) {}
    void ParseParams(napi_value *params, size_t paramsCount) override;
};

class LocalSocketGetStateContext final : public LocalSocketBaseContext {
public:
    LocalSocketGetStateContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketBaseContext(env, manager) {}
    void ParseParams(napi_value *params, size_t paramsCount) override;
    SocketStateBase &GetStateRef();

private:
    SocketStateBase state_;
};

class LocalSocketGetSocketFdContext final : public LocalSocketBaseContext {
public:
    LocalSocketGetSocketFdContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketBaseContext(env, manager) {}
    void ParseParams(napi_value *params, size_t paramsCount) override;
};

class LocalSocketSetExtraOptionsContext final : public LocalSocketBaseContext {
public:
    LocalSocketSetExtraOptionsContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketBaseContext(env, manager) {}
    void ParseParams(napi_value *params, size_t paramsCount) override;
    LocalExtraOptions &GetOptionsRef();

private:
    LocalExtraOptions options_;
};

class LocalSocketGetExtraOptionsContext final : public LocalSocketBaseContext {
public:
    LocalSocketGetExtraOptionsContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketBaseContext(env, manager) {}
    void ParseParams(napi_value *params, size_t paramsCount) override;
    LocalExtraOptions &GetOptionsRef();

private:
    LocalExtraOptions options_;
};
} // namespace OHOS::NetStack::Socket
#endif /* LOCAL_SOCKET_CONTEXT_H */
