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

#ifndef COMMUNICATIONNETSTACK_SPINLOCK_MUTEX_H
#define COMMUNICATIONNETSTACK_SPINLOCK_MUTEX_H

namespace OHOS::NetStack::HttpOverCurl {

struct spinlock_mutex {
    std::atomic_flag flag = ATOMIC_FLAG_INIT;
    spinlock_mutex() = default;

    void lock()
    {
        while (flag.test_and_set(std::memory_order_acquire))
            ;
    }

    void unlock()
    {
        flag.clear(std::memory_order_release);
    }
};

} // namespace OHOS::NetStack::HttpOverCurl

#endif // COMMUNICATIONNETSTACK_SPINLOCK_MUTEX_H
