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

#ifndef COMMUNICATIONNETSTACK_WEBSOCKET_EXEC_COMMON_H
#define COMMUNICATIONNETSTACK_WEBSOCKET_EXEC_COMMON_H

#include <map>
#include <cstdint>
#include <string>
#include "libwebsockets.h"
#include "netstack_log.h"

namespace OHOS::NetStack::Websocket {
struct WebSocketConnection {
    std::string clientIP;
    uint32_t clientPort;
};

class UserData {
public:
    struct SendData {
        SendData(void *paraData, size_t paraLength, lws_write_protocol paraProtocol)
            : data(paraData), length(paraLength), protocol(paraProtocol)
        {
        }

        SendData() = delete;

        ~SendData() = default;

        void *data;
        size_t length;
        lws_write_protocol protocol;
    };

    explicit UserData(lws_context *context)
        : closeStatus(LWS_CLOSE_STATUS_NOSTATUS), openStatus(0), closed_(false), threadStop_(false), context_(context)
    {
    }

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

    std::map<std::string, std::string> header;

    lws_close_status closeStatus;

    std::string closeReason;

    uint32_t openStatus;

    std::string openMessage;

    lws_retry_bo_t retry_policy {
        .secs_since_valid_ping   = 30,
        .secs_since_valid_hangup = 60,
        .jitter_percent          = 20,
    };

private:
    volatile bool closed_;

    std::atomic_bool threadStop_;

    std::mutex mutex_;

    std::mutex mutexForLws_;

    lws_context *context_;

    std::queue<SendData> dataQueue_;

    lws *wsi_ = nullptr;
};
} // namespace OHOS::NetStack::Websocket
#endif