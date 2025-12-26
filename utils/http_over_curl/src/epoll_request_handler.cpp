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

#include "epoll_request_handler.h"

#include <thread>

#include "epoll_multi_driver.h"
#include "netstack_log.h"
#include "request_info.h"

namespace OHOS::NetStack::HttpOverCurl {
static constexpr const char *HTTP_WORK_THREAD = "OS_NET_HttpWork";

EpollRequestHandler::EpollRequestHandler(int sleepTimeoutMs)
    : sleepTimeoutMs_(sleepTimeoutMs),
      incomingQueue_(std::make_shared<HttpOverCurl::ThreadSafeStorage<RequestInfo *>>())
{
}

EpollRequestHandler::~EpollRequestHandler()
{
    stop_ = true;
    if (workThread_.joinable()) {
        workThread_.join();
    }
}

void EpollRequestHandler::Process(CURL *easyHandle, const TransferCallbacks callbacks, void *opaqueData)
{
    auto requestInfo = new RequestInfo{easyHandle, callbacks, opaqueData};
    incomingQueue_->Push(requestInfo);

    auto start = [this]() {
        auto f = [this]() {
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
            pthread_setname_np(HTTP_WORK_THREAD);
#else
            pthread_setname_np(pthread_self(), HTTP_WORK_THREAD);
#endif
            WorkingThread();
        };
        workThread_ = std::thread(f);
        workThread_.detach();
    };

    std::call_once(init_, start);
}

void EpollRequestHandler::WorkingThread()
{
    EpollMultiDriver requestHandler(incomingQueue_);

    while (!stop_) {
        requestHandler.Step(sleepTimeoutMs_);
    }
}

} // namespace OHOS::NetStack::HttpOverCurl
