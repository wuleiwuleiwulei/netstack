/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_EPOLL_REQUEST_HANDLER_H
#define COMMUNICATIONNETSTACK_EPOLL_REQUEST_HANDLER_H

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>

#include "curl/curl.h"

#include "thread_safe_storage.h"
#include "transfer_callbacks.h"
#include "request_info.h"

namespace OHOS::NetStack::HttpOverCurl {

struct RequestInfo;

class EpollRequestHandler {
public:
    explicit EpollRequestHandler(int sleepTimeoutMs = 5000);
    ~EpollRequestHandler();

    void Process(CURL *easyHandle, TransferCallbacks callbacks, void *opaqueData = nullptr);

private:
    void WorkingThread();
    std::atomic_bool stop_ = false;
    std::once_flag init_;
    int sleepTimeoutMs_;
    std::thread workThread_;

    std::shared_ptr<HttpOverCurl::ThreadSafeStorage<RequestInfo *>> incomingQueue_;
};

} // namespace OHOS::NetStack::HttpOverCurl

#endif // COMMUNICATIONNETSTACK_EPOLL_REQUEST_HANDLER_H
