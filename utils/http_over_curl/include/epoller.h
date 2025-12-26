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

#ifndef COMMUNICATIONNETSTACK_EPOLLER_H
#define COMMUNICATIONNETSTACK_EPOLLER_H

#include <sys/epoll.h>

#include <string.h>
#include <unistd.h>

#include "file_descriptor.h"

namespace OHOS::NetStack::HttpOverCurl {

struct Epoller {
    Epoller()
    {
        underlying_ = epoll_create1(EPOLL_CLOEXEC);
    }

    ~Epoller()
    {
        close(underlying_);
    }

    Epoller(const Epoller &) = delete;
    Epoller(Epoller &&other) = default;

    void RegisterMe(FileDescriptor descriptor) const
    {
        RegisterMe(descriptor, EPOLLIN);
    }

    void RegisterMe(FileDescriptor descriptor, uint32_t flags) const
    {
        epoll_event ev{};
        ev.events = flags;
        ev.data.fd = descriptor;
        epoll_ctl(underlying_, EPOLL_CTL_ADD, descriptor, &ev);
    }

    void UnregisterMe(FileDescriptor descriptor) const
    {
        if (descriptor) {
            epoll_ctl(underlying_, EPOLL_CTL_DEL, descriptor, nullptr);
        }
    }

    int Wait(epoll_event *events, int maxEvents, int timeout) const
    {
        return epoll_wait(underlying_, events, maxEvents, timeout);
    }

private:
    FileDescriptor underlying_;
};

} // namespace OHOS::NetStack::HttpOverCurl

#endif // COMMUNICATIONNETSTACK_EPOLLER_H
