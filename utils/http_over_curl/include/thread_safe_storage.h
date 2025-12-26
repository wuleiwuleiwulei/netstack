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

#ifndef COMMUNICATIONNETSTACK_THREAD_SAFE_STORAGE_H
#define COMMUNICATIONNETSTACK_THREAD_SAFE_STORAGE_H

#include <mutex>
#include <queue>
#include <utility>
#include <vector>

#include "manual_reset_event.h"
#include "spinlock_mutex.h"

namespace OHOS::NetStack::HttpOverCurl {

template <typename T> class ThreadSafeStorage {
public:
    void Push(const T &element);
    std::vector<T> Flush();
    [[nodiscard]] bool IsEmpty() const;
    [[nodiscard]] const ManualResetEvent &GetSyncEvent() const;

private:
    spinlock_mutex queueMutex_;
    std::queue<T> queue_;
    ManualResetEvent syncEvent_;
};

template <typename T> const ManualResetEvent &ThreadSafeStorage<T>::GetSyncEvent() const
{
    return syncEvent_;
}

template <typename T> void ThreadSafeStorage<T>::Push(const T &element)
{
    std::lock_guard lock(queueMutex_);
    queue_.push(element);
    syncEvent_.Set();
}

template <typename T> std::vector<T> ThreadSafeStorage<T>::Flush()
{
    std::vector<T> elementsToReturn;
    std::lock_guard lock(queueMutex_);

    while (!queue_.empty()) {
        elementsToReturn.push_back(std::move(queue_.front()));
        queue_.pop();
    }

    syncEvent_.Reset();
    return elementsToReturn;
}

template <typename T> bool ThreadSafeStorage<T>::IsEmpty() const
{
    std::lock_guard lock(queueMutex_);
    return queue_.empty();
}

} // namespace OHOS::NetStack::HttpOverCurl

#endif // COMMUNICATIONNETSTACK_THREAD_SAFE_STORAGE_H
