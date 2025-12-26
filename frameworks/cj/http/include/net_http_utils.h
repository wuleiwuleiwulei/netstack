/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NET_HTTP_UTILS_H
#define NET_HTTP_UTILS_H

#include <cstddef>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <chrono>
#include <map>

#include "constant.h"
#include "cj_ffi/cj_common_ffi.h"

namespace OHOS::NetStack::Http {
const double MICROSECONDS_TO_MILLISECONDS = 1000.0;
char* MallocCString(const std::string& origin);

class Timer {
public:
    const char* timerName_{nullptr};
    Timer();
    void Start(time_t time);
    void Start();
    void Stop();
    double Elapsed() const;

private:
    time_t startTime_{0};
    time_t endTime_{0};
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

time_t StrTimeToTimestamp(const std::string &time_str);

time_t GetNowTimeSeconds();

std::string GetNowTimeGMT();

std::string Encode(const std::string &source);

std::string Decode(const std::string &encoded);

class SecureChar {
public:
    SecureChar();
    ~SecureChar();
    explicit SecureChar(const std::string &secureChar);
    SecureChar(const uint8_t *secureChar, size_t length);
    SecureChar(const SecureChar &secureChar);
    SecureChar &operator=(const SecureChar &secureChar);

    const char *Data() const;
    size_t Length() const;

private:
    size_t length_ = 0;
    std::unique_ptr<char[]> data_ = nullptr;
};

CArrString g_map2CArrString(std::map<std::string, std::string> map);
} // namespace OHOS::NetStack::Http
#endif // NET_HTTP_UTILS_H
