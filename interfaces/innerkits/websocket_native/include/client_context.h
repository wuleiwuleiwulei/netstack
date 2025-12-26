/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef CLIENT_CONTEXT_H
#define CLIENT_CONTEXT_H

#include <atomic>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <signal.h>
#include <string.h>
#include <string>
#include <thread>
#include "netstack_log.h"
#include "secure_char.h"

namespace OHOS {
namespace NetStack {
namespace WebSocketClient {

struct SendData {
    SendData(char *paraData, size_t paraLength, lws_write_protocol paraProtocol)
        : data(paraData), length(paraLength), protocol(paraProtocol)
    {
    }

    SendData() = delete;

    ~SendData() = default;

    char *data;
    size_t length;
    lws_write_protocol protocol;
};

enum class WebsocketProxyType {
    NOT_USE,
    USE_SYSTEM,
    USE_SPECIFIED,
};

class ClientContext {
public:
    ClientContext() : closeStatus(LWS_CLOSE_STATUS_NOSTATUS), openStatus(0), errorCode(0), closed_(false),
                      threadStop_(false), context_(nullptr), clientId(0) {}

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
        NETSTACK_LOGD("ClientContext  Close");
        std::lock_guard<std::mutex> lock(mutex_);
        closeStatus = status;
        closeReason = reason;
        closed_ = true;
    }

    void Push(char *data, size_t length, lws_write_protocol protocol)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        dataQueue_.push(SendData(data, length, protocol));
    }

    SendData Pop()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (dataQueue_.empty()) {
            return {nullptr, 0, LWS_WRITE_TEXT};
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

    void SetClientId(int id)
    {
        clientId = id;
    }

    int GetClientId()
    {
        return clientId;
    }

    void SetUserCertPath(std::string path)
    {
        userCertPath_ = path;
    }

    std::string GetUserCertPath()
    {
        return userCertPath_;
    }

    std::map<std::string, std::string> header;

    std::string caPath;

    std::string clientCert;

    Secure::SecureChar clientKey;

    Secure::SecureChar keyPassword;

    bool permissionDenied = false;

    bool isAtomicService = false;

    bool noAllowedHost = false;

    std::string bundleName;

    std::string url;

    WebsocketProxyType usingWebsocketProxyType = WebsocketProxyType::USE_SYSTEM;

    std::string websocketProxyHost;

    int32_t websocketProxyPort = 0;

    std::string websocketProxyExclusions;

    lws_close_status closeStatus;

    std::string closeReason;

    uint32_t openStatus = 0;

    uint32_t errorCode = 0;

    std::string openMessage;

private:
    bool closed_ = false;

    std::string userCertPath_;

    std::atomic_bool threadStop_;

    std::mutex mutex_;

    lws_context *context_;

    std::queue<SendData> dataQueue_;

    std::mutex mutexForLws_;

    lws *wsi_ = nullptr;

    int clientId = 0;
};
}; // namespace WebSocketClient
} // namespace NetStack
} // namespace OHOS
#endif
