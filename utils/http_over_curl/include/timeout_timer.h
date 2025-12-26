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

#ifndef COMMUNICATIONNETSTACK_TIMEOUT_TIMER_H
#define COMMUNICATIONNETSTACK_TIMEOUT_TIMER_H

#include <sys/epoll.h>
#include <sys/timerfd.h>

#include <string.h>
#include <unistd.h>

#include "epoller.h"
#include "file_descriptor.h"
#include "securec.h"

namespace OHOS::NetStack::HttpOverCurl {

static constexpr long MILLISECONDS_IN_SECOND = 1000;
static constexpr long NANOSECONDS_IN_MILLISECOND = 1000 * 1000;

struct TimeoutTimer {
    TimeoutTimer()
    {
        underlying_ = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    }

    ~TimeoutTimer()
    {
        close(underlying_);
    }

    TimeoutTimer(const TimeoutTimer &) = delete;
    TimeoutTimer(TimeoutTimer &&other) = default;

    void RegisterForPolling(Epoller &poller) const
    {
        poller.RegisterMe(underlying_);
    }

    [[nodiscard]] bool IsItYours(FileDescriptor descriptor) const
    {
        return descriptor == underlying_;
    }

    void Stop()
    {
        SetTimeoutMs(0);
    }

    void SetTimeoutNs(long timeoutNs)
    {
        itimerspec its{};
        memset_s(&its, sizeof(itimerspec), 0, sizeof(itimerspec));

        if (timeoutNs > 0) {
            its.it_value.tv_nsec = timeoutNs;
        }

        timerfd_settime(underlying_, 0, &its, nullptr);
    }

    void SetTimeoutMs(long timeoutMs)
    {
        itimerspec its{};
        memset_s(&its, sizeof(itimerspec), 0, sizeof(itimerspec));

        if (timeoutMs > 0) {
            its.it_value.tv_sec = timeoutMs / MILLISECONDS_IN_SECOND;
            its.it_value.tv_nsec = (timeoutMs % MILLISECONDS_IN_SECOND) * NANOSECONDS_IN_MILLISECOND;
        }

        timerfd_settime(underlying_, 0, &its, nullptr);
    }

    void ResetEvent()
    {
        uint64_t count = 0;
        read(underlying_, &count, sizeof(uint64_t));
    }

private:
    FileDescriptor underlying_;
};

} // namespace OHOS::NetStack::HttpOverCurl

#endif // COMMUNICATIONNETSTACK_TIMEOUT_TIMER_H
