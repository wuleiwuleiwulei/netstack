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

#ifndef COMMUNICATIONNETSTACK_MANUAL_RESET_EVENT_H
#define COMMUNICATIONNETSTACK_MANUAL_RESET_EVENT_H

#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <unistd.h>

#include "epoller.h"

namespace OHOS::NetStack::HttpOverCurl {

struct ManualResetEvent {
    ManualResetEvent()
    {
        underlying_ = eventfd(0, 0);
    }

#ifdef HTTP_HANDOVER_FEATURE
    explicit ManualResetEvent(bool isSemaphore)
    {
        if (isSemaphore) {
            underlying_ = eventfd(0, EFD_SEMAPHORE);
        } else {
            underlying_ = eventfd(0, 0);
        }
    }
#endif

    ~ManualResetEvent()
    {
        close(underlying_);
    }

    ManualResetEvent(const ManualResetEvent &) = delete;
    ManualResetEvent(ManualResetEvent &&other) = default;

    void RegisterForPolling(Epoller &poller) const
    {
        poller.RegisterMe(underlying_);
    }

    [[nodiscard]] bool IsItYours(FileDescriptor descriptor) const
    {
        return descriptor == underlying_;
    }

    void Set()
    {
        uint64_t u = 1;
        write(underlying_, &u, sizeof(uint64_t));
    }

    void Reset()
    {
        uint64_t u;
        read(underlying_, &u, sizeof(uint64_t));
    }

private:
    FileDescriptor underlying_;
};

} // namespace OHOS::NetStack::HttpOverCurl

#endif // COMMUNICATIONNETSTACK_MANUAL_RESET_EVENT_H
