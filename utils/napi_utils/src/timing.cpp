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
#include "timing.h"

#include <chrono>
#include <map>

static constexpr const double MICROSECONDS_TO_MILLISECONDS = 1000.0;

namespace OHOS::NetStack::Timing {
Timer &TimerMap::RecieveTimer(const char *const type)
{
    std::map<const char *const, Timer>::iterator it = timerMap_.find(type);
    if (it != timerMap_.end()) {
        return it->second;
    } else {
        Timer timer;
        timer.timerName_ = type;
        timerMap_.insert(std::pair<const char *const, Timer>(type, timer));
        return timerMap_[type];
    }
}

Timer::Timer() {}

void Timer::Start()
{
    Timer::Start(0L);
}

void Timer::Start(time_t time)
{
    if (time > 0) {
        startTime_ = time;
    } else {
        startTime_ = TimeUtils::GetNowTimeMicroseconds();
    }
}

void Timer::Stop()
{
    endTime_ = TimeUtils::GetNowTimeMicroseconds();
}

double Timer::Elapsed() const
{
    double elapsedTime = TimeUtils::Microseconds2Milliseconds(endTime_ - startTime_);
    return elapsedTime <= 0 ? 0 : elapsedTime;
}

time_t TimeUtils::GetNowTimeMicroseconds()
{
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
}

double TimeUtils::Microseconds2Milliseconds(time_t microseconds)
{
    if (microseconds == 0) {
        return 0.0;
    }
    return double(microseconds / MICROSECONDS_TO_MILLISECONDS);
}
} // namespace OHOS::NetStack::Timing