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

#ifndef LOCAL_SOCKET_SERVER_CONTEXT_H
#define LOCAL_SOCKET_SERVER_CONTEXT_H

#include <cstddef>
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
#include <unistd.h>
#endif
#include <map>
#if !defined(MAC_PLATFORM) && !defined(IOS_PLATFORM)
#include <sys/epoll.h>
#endif
#include <unistd.h>

#include "base_context.h"
#include "event_list.h"
#include "local_socket_context.h"
#include "napi/native_api.h"
#include "nocopyable.h"
#include "socket_state_base.h"

namespace OHOS::NetStack::Socket {
struct LocalSocketServerManager : public SocketBaseManager {
    static constexpr int MAX_EVENTS = 10;
    static constexpr int EPOLL_TIMEOUT_MS = 500;
    int clientId_ = 0;
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    int threadCounts_ = 0;
#endif
    LocalExtraOptions extraOptions_;
    bool alreadySetExtraOptions_ = false;
    std::atomic_bool isServerDestruct_;
    bool isLoopFinished_ = false;
    int epollFd_ = 0;
#if !defined(MAC_PLATFORM) && !defined(IOS_PLATFORM)
    epoll_event events_[MAX_EVENTS] = {};
#endif
    std::mutex finishMutex_;
    std::condition_variable finishCond_;
    std::mutex clientMutex_;
    std::condition_variable cond_;
    std::map<int, int> acceptFds_;                      // id & fd
    std::map<int, std::shared_ptr<EventManager>> clientEventManagers_; // id & EventManager*
    explicit LocalSocketServerManager(int sockfd) : SocketBaseManager(sockfd) {}

    void SetServerDestructStatus(bool flag)
    {
        isServerDestruct_.store(flag, std::memory_order_relaxed);
    }
    bool GetServerDestructStatus()
    {
        return isServerDestruct_.load(std::memory_order_relaxed);
    }
#if !defined(MAC_PLATFORM) && !defined(IOS_PLATFORM)
    int StartEpoll()
    {
        epollFd_ = epoll_create1(0);
        return epollFd_;
    }
    int EpollWait()
    {
        return epoll_wait(epollFd_, events_, MAX_EVENTS - 1, EPOLL_TIMEOUT_MS);
    }
    int RegisterEpollEvent(int sockfd, int events)
    {
        epoll_event event;
        event.events = events;
        event.data.fd = sockfd;
        return epoll_ctl(epollFd_, EPOLL_CTL_ADD, sockfd, &event);
    }
    void WaitRegisteringEvent(int id)
    {
        std::unique_lock<std::mutex> lock(clientMutex_);
        cond_.wait(lock, [&id, this]() {
            if (auto iter = clientEventManagers_.find(id); iter != clientEventManagers_.end()) {
                if (iter->second->HasEventListener(EVENT_MESSAGE)) {
                    return true;
                }
            }
            return false;
        });
    }
    int GetClientId(int fd)
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        for (const auto &[clientId, connectFd] : acceptFds_) {
            if (fd == connectFd) {
                return clientId;
            }
        }
        return -1;
    }
    std::shared_ptr<EventManager> GetSharedManager(int id)
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        if (auto ite = clientEventManagers_.find(id); ite != clientEventManagers_.end()) {
            return ite->second;
        }
        return nullptr;
    }
#endif
    int AddAccept(int accpetFd)
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        auto res = acceptFds_.emplace(++clientId_, accpetFd);
        return res.second ? clientId_ : -1;
    }
    void RemoveAllAccept()
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        for (const auto &[id, fd] : acceptFds_) {
            if (fd > 0) {
                close(fd);
            }
        }
        acceptFds_.clear();
    }
    void RemoveAccept(int clientId)
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        if (auto ite = acceptFds_.find(clientId); ite != acceptFds_.end()) {
#if !defined(MAC_PLATFORM) && !defined(IOS_PLATFORM)
            epoll_ctl(epollFd_, EPOLL_CTL_DEL, ite->second, nullptr);
#endif
            close(ite->second);
            acceptFds_.erase(ite);
        }
    }
    int GetAcceptFd(int clientId)
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        if (auto ite = acceptFds_.find(clientId); ite != acceptFds_.end()) {
            return ite->second;
        }
        return -1;
    }
    size_t GetClientCounts()
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        return acceptFds_.size();
    }
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    std::shared_ptr<EventManager> WaitForSharedManager(int clientId)
    {
        std::shared_ptr<EventManager> manager = nullptr;
        std::unique_lock<std::mutex> lock(clientMutex_);
        cond_.wait(lock, [&manager, &clientId, this]() {
            if (auto iter = clientEventManagers_.find(clientId); iter != clientEventManagers_.end()) {
                manager = iter->second;
                if (manager->HasEventListener(EVENT_MESSAGE)) {
                    return true;
                }
            }
            return false;
        });
        return manager;
    }
#endif
    void NotifyRegisterEvent()
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        cond_.notify_one();
    }
    void AddEventManager(int clientId, std::shared_ptr<EventManager> &manager)
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        clientEventManagers_.insert(std::make_pair(clientId, manager));
        cond_.notify_one();
    }
    void RemoveEventManager(int clientId)
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        if (auto ite = clientEventManagers_.find(clientId); ite != clientEventManagers_.end()) {
            clientEventManagers_.erase(ite);
        }
    }
    void RemoveAllEventManager()
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        clientEventManagers_.clear();
    }
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    void IncreaseThreadCounts()
    {
        std::lock_guard<std::mutex> lock(finishMutex_);
        ++threadCounts_;
    }
#endif
    void NotifyLoopFinished()
    {
        std::lock_guard<std::mutex> lock(finishMutex_);
        isLoopFinished_ = true;
        finishCond_.notify_one();
    }
    void WaitForEndingLoop()
    {
        std::unique_lock<std::mutex> lock(finishMutex_);
        finishCond_.wait(lock, [this]() {
            return isLoopFinished_;
        });
    }
};

class LocalSocketServerBaseContext : public LocalSocketBaseContext {
public:
    LocalSocketServerBaseContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketBaseContext(env, manager) {}
    [[nodiscard]] int GetSocketFd() const override;
    void SetSocketFd(int sock) override;
};

class LocalSocketServerListenContext final : public LocalSocketServerBaseContext {
public:
    LocalSocketServerListenContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketServerBaseContext(env, manager) {}
    void ParseParams(napi_value *params, size_t paramsCount) override;
    const std::string &GetSocketPath() const;

private:
    std::string socketPath_;
};

class LocalSocketServerEndContext final : public LocalSocketServerBaseContext {
public:
    LocalSocketServerEndContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketServerBaseContext(env, manager) {}
    void ParseParams(napi_value *params, size_t paramsCount) override;
};

class LocalSocketServerGetStateContext final : public LocalSocketServerBaseContext {
public:
    LocalSocketServerGetStateContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketServerBaseContext(env, manager)
    {
    }
    void ParseParams(napi_value *params, size_t paramsCount) override;
    SocketStateBase &GetStateRef();

private:
    SocketStateBase state_;
};

class LocalSocketServerGetLocalAddressContext final : public LocalSocketServerBaseContext {
public:
    LocalSocketServerGetLocalAddressContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketServerBaseContext(env, manager) {}
    void ParseParams(napi_value *params, size_t paramsCount) override;
    void SetSocketPath(const std::string socketPath);
    std::string GetSocketPath();
    int GetClientId() const;
    void SetClientId(int clientId);

private:
    std::string socketPath_;
    int clientId_ = 0;
};

class LocalSocketServerSetExtraOptionsContext final : public LocalSocketServerBaseContext {
public:
    LocalSocketServerSetExtraOptionsContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketServerBaseContext(env, manager)
    {
    }
    void ParseParams(napi_value *params, size_t paramsCount) override;
    LocalExtraOptions &GetOptionsRef();

private:
    LocalExtraOptions options_;
};

class LocalSocketServerGetExtraOptionsContext final : public LocalSocketServerBaseContext {
public:
    LocalSocketServerGetExtraOptionsContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketServerBaseContext(env, manager)
    {
    }
    void ParseParams(napi_value *params, size_t paramsCount) override;
    LocalExtraOptions &GetOptionsRef();

private:
    LocalExtraOptions options_;
};

class LocalSocketServerSendContext final : public LocalSocketServerBaseContext {
public:
    LocalSocketServerSendContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketServerBaseContext(env, manager) {}
    void ParseParams(napi_value *params, size_t paramsCount) override;
    int GetAcceptFd();
    LocalSocketOptions &GetOptionsRef();
    int GetClientId() const;
    void SetClientId(int clientId);

private:
    bool GetData(napi_value sendOptions);
    LocalSocketOptions options_;
    int clientId_ = 0;
};

class LocalSocketServerCloseContext final : public LocalSocketServerBaseContext {
public:
    LocalSocketServerCloseContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketServerBaseContext(env, manager) {}
    void ParseParams(napi_value *params, size_t paramsCount) override;
    int GetClientId() const;
    void SetClientId(int clientId);

private:
    int clientId_ = 0;
};

class LocalSocketServerGetSocketFdContext final : public LocalSocketServerBaseContext {
public:
    LocalSocketServerGetSocketFdContext(napi_env env, const std::shared_ptr<EventManager> &manager)
        : LocalSocketServerBaseContext(env, manager) {}
    void ParseParams(napi_value *params, size_t paramsCount) override;
    int GetClientId() const;
    void SetClientId(int clientId);
    int GetConnectionSocketFd() const;
    void SetConnectionSocketFd(int socketFd);
private:
    int clientId_ = 0;
    int socketFd_ = -1;
};
} // namespace OHOS::NetStack::Socket
#endif
