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
#ifndef COMMUNICATIONNETSTACK_NETSTACK_TIMIMG_H
#define COMMUNICATIONNETSTACK_NETSTACK_TIMIMG_H

#include <map>
#include <ctime>

namespace OHOS::NetStack::Timing {

class Timer {
public:
    const char* timerName_ = nullptr;
    Timer();
    void Start(time_t time);
    void Start();
    void Stop();
    double Elapsed() const;

private:
    time_t startTime_ = 0;
    time_t endTime_ = 0;
};

class TimerMap {
public:
    Timer& RecieveTimer(const char *const type);

private:
    std::map<const char *const, Timer> timerMap_;
};

class TimeUtils {
public:
    static time_t GetNowTimeMicroseconds();

    static double Microseconds2Milliseconds(time_t microseconds);
};
} // namespace OHOS::NetStack::Timing
#endif /* COMMUNICATIONNETSTACK_NETSTACK_TIMING_H */