/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SERVER_CONTEXT_H
#define SERVER_CONTEXT_H

#include <atomic>
#include <iostream>
#include <memory>
#include <shared_mutex>
#include <queue>
#include <signal.h>
#include <string.h>
#include <string>
#include <thread>
#include <unordered_map>
#include <map>
#include "netstack_log.h"
#include "secure_char.h"

namespace OHOS {
namespace NetStack {
namespace WebSocketServer {
struct ClientInfo {
    int32_t cnt;
    uint64_t lastConnectionTime;
};

struct ServerCert {
    std::string certPath;
    std::string keyPath;
};

struct ServerConfig {
    std::string serverIP;
    int serverPort = 0;
    ServerCert serverCert;
    int maxConcurrentClientsNumber = 0;
    std::string protocol;
    int maxConnectionsForOneClient = 0;
};

struct SocketConnection {
    std::string clientIP;
    uint32_t clientPort;
};

struct CloseOption {
    unsigned int code;
    const char *reason;
};

struct ErrorResult {
    unsigned int errorCode;
    const char *errorMessage;
};

struct CloseResult {
    unsigned int code;
    const char *reason;
};

class UserData {
public:
    struct SendData {
        SendData(void *paraData, size_t paraLength, lws_write_protocol paraProtocol)
            : data(paraData), length(paraLength), protocol(paraProtocol)
        {}

        SendData() = delete;

        ~SendData() = default;

        void *data;
        size_t length;
        lws_write_protocol protocol;
    };

    explicit UserData(lws_context *context)
        : closeStatus(LWS_CLOSE_STATUS_NOSTATUS), openStatus(0), closed_(false), threadStop_(false), context_(context)
    {}

    bool IsClosed()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return closed_;
    }

    bool IsThreadStop()
    {
        return threadStop_.load();
    }

    void SetThreadStop(bool threadStop)
    {
        threadStop_.store(threadStop);
    }

    void Close(lws_close_status status, const std::string &reason)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        closeStatus = status;
        closeReason = reason;
        closed_ = true;
    }

    void Push(void *data, size_t length, lws_write_protocol protocol)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        dataQueue_.emplace(data, length, protocol);
    }

    SendData Pop()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (dataQueue_.empty()) {
            return { nullptr, 0, LWS_WRITE_TEXT };
        }
        SendData data = dataQueue_.front();
        dataQueue_.pop();
        return data;
    }

    void SetContext(lws_context *context)
    {
        context_ = context;
    }

    lws_context *GetContext()
    {
        return context_;
    }

    bool IsEmpty()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (dataQueue_.empty()) {
            return true;
        }
        return false;
    }

    void SetLws(lws *wsi)
    {
        std::lock_guard<std::mutex> lock(mutexForLws_);
        if (wsi == nullptr) {
            NETSTACK_LOGD("set wsi nullptr");
        }
        wsi_ = wsi;
    }

    void TriggerWritable()
    {
        std::lock_guard<std::mutex> lock(mutexForLws_);
        if (wsi_ == nullptr) {
            NETSTACK_LOGE("wsi is nullptr, can not trigger");
            return;
        }
        lws_callback_on_writable(wsi_);
    }

    std::map<std::string, std::string> header;

    lws_close_status closeStatus;

    std::string closeReason;

    uint32_t openStatus;

    std::string openMessage;

private:
    volatile bool closed_;

    std::atomic_bool threadStop_;

    std::mutex mutex_;

    std::mutex mutexForLws_;

    lws_context *context_;

    std::queue<SendData> dataQueue_;

    lws *wsi_ = nullptr;
};

class ServerContext {
public:
    ServerContext() {}
    ~ServerContext() = default;
    uint64_t GetCurrentSecond()
    {
        return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    }
    bool IsClosed()
    {
        std::lock_guard<std::mutex> lock(closeMutex_);
        return closed_;
    }
    void Close(lws_close_status status, const std::string &reason)
    {
        std::lock_guard<std::mutex> lock(closeMutex_);
        closeStatus_ = status;
        closeReason_ = reason;
        closed_ = true;
    }
    bool IsThreadStop()
    {
        return threadStop_.load();
    }
    void SetThreadStop(bool threadStop)
    {
        threadStop_.store(threadStop);
    }
    void SetContext(lws_context *context)
    {
        context_ = context;
    }
    lws_context *GetContext()
    {
        return context_;
    }
    void AddClientUserData(void *wsi, std::shared_ptr<UserData> &data)
    {
        std::lock_guard<std::mutex> lock(mapUserDataMutex_);
        userDataMap_[wsi] = data;
    }
    void RemoveClientUserData(void *wsi)
    {
        std::lock_guard<std::mutex> lock(mapUserDataMutex_);
        auto it = userDataMap_.find(wsi);
        if (it != userDataMap_.end()) {
            userDataMap_.erase(it);
        }
    }
    void AddConnections(const std::string &id, lws *wsi, SocketConnection &conn)
    {
        if (IsClosed() || IsThreadStop()) {
            NETSTACK_LOGE("AddConnections failed: session %s", IsClosed() ? "closed" : "thread stopped");
            return;
        }
        std::unique_lock<std::shared_mutex> lock(wsMutex_);
        webSocketConnection_[id].first = wsi;
        webSocketConnection_[id].second = conn;
    }
    std::string GetClientIdFromConnectionByWsi(lws *wsi)
    {
        std::shared_lock<std::shared_mutex> lock(wsMutex_);
        for (const auto &pair : webSocketConnection_) {
            if (pair.second.first == wsi) {
                return pair.first;
            }
        }
        return "";
    }
    SocketConnection GetConnectionFromWsi(lws *wsi)
    {
        std::shared_lock<std::shared_mutex> lock(wsMutex_);
        for (const auto &pair : webSocketConnection_) {
            if (pair.second.first == wsi) {
                return pair.second.second;
            }
        }
        return {};
    }
    void RemoveConnections(const std::string &id)
    {
        if (webSocketConnection_.empty()) {
            return;
        }
        {
            std::unique_lock<std::shared_mutex> lock(wsMutex_);
            if (webSocketConnection_.find(id) == webSocketConnection_.end()) {
                return;
            }
            webSocketConnection_.erase(id);
        }
    }
    void ListAllConnections(std::vector<SocketConnection> &connections)
    {
        std::shared_lock<std::shared_mutex> lock(wsMutex_);
        connections.clear();
        for (const auto &pair : webSocketConnection_) {
            connections.push_back(pair.second.second);
        }
    }
    lws *GetClientWsi(const std::string &clientId)
    {
        std::shared_lock<std::shared_mutex> lock(wsMutex_);
        if (webSocketConnection_.empty()) {
            return nullptr;
        }
        auto it = webSocketConnection_.find(clientId);
        if (it != webSocketConnection_.end()) {
            return it->second.first;
        }
        return nullptr;
    }
    const std::unordered_map<std::string, std::pair<lws *, SocketConnection>> &GetWebSocketConnection()
    {
        std::shared_lock<std::shared_mutex> lock(wsMutex_);
        return webSocketConnection_;
    }
    void AddBanList(const std::string &ip)
    {
        std::shared_lock<std::shared_mutex> lock(banListMutex_);
        banList_[ip] = GetCurrentSecond() + ONE_MINUTE_IN_SEC;
    }

    bool IsIpInBanList(const std::string &ip)
    {
        std::shared_lock<std::shared_mutex> lock(banListMutex_);
        auto it = banList_.find(ip);
        if (it != banList_.end()) {
            auto now = GetCurrentSecond();
            if (now < it->second) {
                return true;
            } else {
                banList_.erase(it);
            }
        }
        return false;
    }
    void UpdateClientList(const std::string &ip)
    {
        std::shared_lock<std::shared_mutex> lock(connListMutex_);
        auto it = clientList_.find(ip);
        if (it == clientList_.end()) {
            NETSTACK_LOGI("add clientid to clientlist");
            clientList_[ip] = {1, GetCurrentSecond()};
        } else {
            auto now = GetCurrentSecond() - it->second.lastConnectionTime;
            if (now > ONE_MINUTE_IN_SEC) {
                NETSTACK_LOGI("reset clientid connections cnt");
                it->second = { 1, GetCurrentSecond() };
            } else {
                it->second.cnt++;
            }
        }
    }
    bool IsHighFreqConnection(const std::string &ip)
    {
        std::shared_lock<std::shared_mutex> lock(connListMutex_);
        auto it = clientList_.find(ip);
        if (it != clientList_.end()) {
            auto duration = GetCurrentSecond() - it->second.lastConnectionTime;
            if (duration <= ONE_MINUTE_IN_SEC) {
                return it->second.cnt > MAX_CONNECTIONS_PER_MINUTE;
            }
        }
        return false;
    }
    bool IsAllowConnection(const std::string &ip)
    {
        if (IsIpInBanList(ip)) {
            NETSTACK_LOGE("client is in banlist");
            return false;
        }
        if (IsHighFreqConnection(ip)) {
            NETSTACK_LOGE("client reach high frequency connection");
            AddBanList(ip);
            return false;
        }
        UpdateClientList(ip);
        return true;
    }
    const std::string &GetWsServerBinaryData(void *wsi)
    {
        return wsServerBinaryData_[wsi];
    }

    const std::string &GetWsServerTextData(void *wsi)
    {
        return wsServerTextData_[wsi];
    }

    void AppendWsServerBinaryData(void *wsi, void *data, size_t length)
    {
        wsServerBinaryData_[wsi].append(reinterpret_cast<char *>(data), length);
    }

    void AppendWsServerTextData(void *wsi, void *data, size_t length)
    {
        wsServerTextData_[wsi].append(reinterpret_cast<char *>(data), length);
    }

    void ClearWsServerBinaryData(void *wsi)
    {
        wsServerBinaryData_[wsi].clear();
    }

    void ClearWsServerTextData(void *wsi)
    {
        wsServerTextData_[wsi].clear();
    }
    void SetPermissionDenied(bool denied)
    {
        permissionDenied = denied;
    }

public:
    lws_close_status closeStatus_ = LWS_CLOSE_STATUS_NOSTATUS;
    std::string closeReason_;
    ServerConfig startServerConfig_;

private:
    bool permissionDenied = false;
    lws_context *context_ = nullptr;
    std::atomic_bool threadStop_ = false;
    std::mutex closeMutex_;
    volatile bool closed_ = false;
    std::shared_mutex wsMutex_;
    std::unordered_map<std::string, std::pair<lws *, SocketConnection>> webSocketConnection_;
    std::shared_mutex connListMutex_;
    std::unordered_map<std::string, ClientInfo> clientList_;
    std::shared_mutex banListMutex_;
    std::unordered_map<std::string, uint64_t> banList_;
    std::mutex mapUserDataMutex_;
    std::unordered_map<void *, std::shared_ptr<UserData>> userDataMap_;
    std::unordered_map<void *, std::string> wsServerBinaryData_;
    std::unordered_map<void *, std::string> wsServerTextData_;
    static constexpr const uint64_t ONE_MINUTE_IN_SEC = 60;
    static constexpr const int32_t MAX_CONNECTIONS_PER_MINUTE = 50;
};
}; // namespace WebSocketServer
} // namespace NetStack
} // namespace OHOS
#endif
