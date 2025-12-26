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

#include "net_http_utils.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

#include "securec.h"
#include "netstack_log.h"

static constexpr const char *GMT_TIME = "%a, %d %b %Y %H:%M:%S GMT";

static constexpr const int MAX_TIME_LEN = 128;

namespace OHOS::NetStack::Http {

char* MallocCString(const std::string& origin)
{
    if (origin.empty()) {
        return nullptr;
    }
    auto len = origin.length() + 1;
    char* res = static_cast<char*>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

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


time_t StrTimeToTimestamp(const std::string &timeStr)
{
    std::tm tm = {0};
    std::stringstream ss(timeStr);
    ss >> std::get_time(&tm, GMT_TIME);
    auto tp = std::chrono::system_clock::from_time_t(std::mktime(&tm));

    auto tmp = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch());
    return tmp.count();
}

time_t GetNowTimeSeconds()
{
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
}

std::string GetNowTimeGMT()
{
    auto now = std::chrono::system_clock::now();
    time_t timeSeconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    std::tm timeInfo = {0};
#ifdef WINDOWS_PLATFORM
    if (gmtime_s(&timeInfo, &timeSeconds) == 0) {
#else
    if (gmtime_r(&timeSeconds, &timeInfo) == nullptr) {
#endif
        return {};
    }
    char s[MAX_TIME_LEN] = {0};
    if (strftime(s, sizeof(s), GMT_TIME, &timeInfo) == 0) {
        return {};
    }
    return s;
}

#ifdef __linux__
static std::string BASE64_CHARS = /* NOLINT */
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static constexpr const uint32_t CHAR_ARRAY_LENGTH_THREE = 3;
static constexpr const uint32_t CHAR_ARRAY_LENGTH_FOUR = 4;

enum BASE64_ENCODE_CONSTANT : uint8_t {
    BASE64_ENCODE_MASK1 = 0xfc,
    BASE64_ENCODE_MASK2 = 0x03,
    BASE64_ENCODE_MASK3 = 0x0f,
    BASE64_ENCODE_MASK4 = 0x3f,
    BASE64_ENCODE_MASK5 = 0xf0,
    BASE64_ENCODE_MASK6 = 0xc0,
    BASE64_ENCODE_OFFSET2 = 2,
    BASE64_ENCODE_OFFSET4 = 4,
    BASE64_ENCODE_OFFSET6 = 6,
    BASE64_ENCODE_INDEX0 = 0,
    BASE64_ENCODE_INDEX1 = 1,
    BASE64_ENCODE_INDEX2 = 2,
};

enum BASE64_DECODE_CONSTANT : uint8_t {
    BASE64_DECODE_MASK1 = 0x30,
    BASE64_DECODE_MASK2 = 0xf,
    BASE64_DECODE_MASK3 = 0x3c,
    BASE64_DECODE_MASK4 = 0x3,
    BASE64_DECODE_OFFSET2 = 2,
    BASE64_DECODE_OFFSET4 = 4,
    BASE64_DECODE_OFFSET6 = 6,
    BASE64_DECODE_INDEX0 = 0,
    BASE64_DECODE_INDEX1 = 1,
    BASE64_DECODE_INDEX2 = 2,
    BASE64_DECODE_INDEX3 = 3,
};

static inline bool IsBase64Char(const char c)
{
    return (isalnum(c) || (c == '+') || (c == '/'));
}

static inline void MakeCharFour(const std::array<uint8_t, CHAR_ARRAY_LENGTH_THREE> &charArrayThree,
                                std::array<uint8_t, CHAR_ARRAY_LENGTH_FOUR> &charArrayFour)
{
    const uint8_t table[CHAR_ARRAY_LENGTH_FOUR] = {
        static_cast<uint8_t>((charArrayThree[BASE64_ENCODE_INDEX0] & BASE64_ENCODE_MASK1) >> BASE64_ENCODE_OFFSET2),
        static_cast<uint8_t>(((charArrayThree[BASE64_ENCODE_INDEX0] & BASE64_ENCODE_MASK2) << BASE64_ENCODE_OFFSET4) +
                             ((charArrayThree[BASE64_ENCODE_INDEX1] & BASE64_ENCODE_MASK5) >> BASE64_ENCODE_OFFSET4)),
        static_cast<uint8_t>(((charArrayThree[BASE64_ENCODE_INDEX1] & BASE64_ENCODE_MASK3) << BASE64_ENCODE_OFFSET2) +
                             ((charArrayThree[BASE64_ENCODE_INDEX2] & BASE64_ENCODE_MASK6) >> BASE64_ENCODE_OFFSET6)),
        static_cast<uint8_t>(charArrayThree[BASE64_ENCODE_INDEX2] & BASE64_ENCODE_MASK4),
    };
    for (size_t index = 0; index < CHAR_ARRAY_LENGTH_FOUR; ++index) {
        charArrayFour[index] = table[index];
    }
}

static inline void MakeCharTree(const std::array<uint8_t, CHAR_ARRAY_LENGTH_FOUR> &charArrayFour,
                                std::array<uint8_t, CHAR_ARRAY_LENGTH_THREE> &charArrayThree)
{
    const uint8_t table[CHAR_ARRAY_LENGTH_THREE] = {
        static_cast<uint8_t>((charArrayFour[BASE64_DECODE_INDEX0] << BASE64_DECODE_OFFSET2) +
                             ((charArrayFour[BASE64_DECODE_INDEX1] & BASE64_DECODE_MASK1) >> BASE64_DECODE_OFFSET4)),
        static_cast<uint8_t>(((charArrayFour[BASE64_DECODE_INDEX1] & BASE64_DECODE_MASK2) << BASE64_DECODE_OFFSET4) +
                             ((charArrayFour[BASE64_DECODE_INDEX2] & BASE64_DECODE_MASK3) >> BASE64_DECODE_OFFSET2)),
        static_cast<uint8_t>(((charArrayFour[BASE64_DECODE_INDEX2] & BASE64_DECODE_MASK4) << BASE64_DECODE_OFFSET6) +
                             charArrayFour[BASE64_DECODE_INDEX3]),
    };
    for (size_t index = 0; index < CHAR_ARRAY_LENGTH_THREE; ++index) {
        charArrayThree[index] = table[index];
    }
}

#endif

std::string Encode(const std::string &source)
{
#ifdef __linux__
    auto it = source.begin();
    std::string ret;
    size_t index = 0;
    std::array<uint8_t, CHAR_ARRAY_LENGTH_THREE> charArrayThree = {0};
    std::array<uint8_t, CHAR_ARRAY_LENGTH_FOUR> charArrayFour = {0};

    while (it != source.end()) {
        charArrayThree[index] = *it;
        ++index;
        ++it;
        if (index != CHAR_ARRAY_LENGTH_THREE) {
            continue;
        }
        MakeCharFour(charArrayThree, charArrayFour);
        for (auto idx : charArrayFour) {
            ret += BASE64_CHARS[idx];
        }
        index = 0;
    }
    if (index == 0) {
        return ret;
    }

    for (auto i = index; i < CHAR_ARRAY_LENGTH_THREE; ++i) {
        charArrayThree[i] = 0;
    }
    MakeCharFour(charArrayThree, charArrayFour);

    for (size_t i = 0; i < index + 1; ++i) {
        ret += BASE64_CHARS[charArrayFour[i]];
    }

    while (index < CHAR_ARRAY_LENGTH_THREE) {
        ret += '=';
        ++index;
    }
    return ret;
#else
    return {};
#endif
}

std::string Decode(const std::string &encoded)
{
#ifdef __linux__
    auto it = encoded.begin();
    size_t index = 0;
    std::array<uint8_t, CHAR_ARRAY_LENGTH_THREE> charArrayThree = {0};
    std::array<uint8_t, CHAR_ARRAY_LENGTH_FOUR> charArrayFour = {0};
    std::string ret;

    while (it != encoded.end() && IsBase64Char(*it)) {
        charArrayFour[index] = *it;
        ++index;
        ++it;
        if (index != CHAR_ARRAY_LENGTH_FOUR) {
            continue;
        }
        for (index = 0; index < CHAR_ARRAY_LENGTH_FOUR; ++index) {
            charArrayFour[index] = BASE64_CHARS.find(static_cast<char>(charArrayFour[index]));
        }
        MakeCharTree(charArrayFour, charArrayThree);
        for (auto idx : charArrayThree) {
            ret += static_cast<char>(idx);
        }
        index = 0;
    }
    if (index == 0) {
        return ret;
    }

    for (auto i = index; i < CHAR_ARRAY_LENGTH_FOUR; ++i) {
        charArrayFour[i] = 0;
    }
    for (unsigned char &i : charArrayFour) {
        i = BASE64_CHARS.find(static_cast<char>(i));
    }
    MakeCharTree(charArrayFour, charArrayThree);

    for (size_t i = 0; i < index - 1; i++) {
        ret += static_cast<char>(charArrayThree[i]);
    }
    return ret;
#else
    return {};
#endif
}

SecureChar::SecureChar() : data_(std::make_unique<char[]>(0)) {}

SecureChar::~SecureChar()
{
    (void)memset_s(data_.get(), length_, 0, length_);
}

SecureChar::SecureChar(const std::string &secureChar)
    : length_(secureChar.length()), data_(std::make_unique<char[]>(length_ + 1))
{
    if (length_ == 0) {
        return;
    }
    data_.get()[length_] = 0;
    if (memcpy_s(data_.get(), length_, secureChar.c_str(), length_) != EOK) {
        NETSTACK_LOGE("memcpy_s failed!");
        return;
    }
}

SecureChar::SecureChar(const uint8_t *secureChar, size_t length)
{
    data_ = std::make_unique<char[]>(length + 1);
    length_ = length;
    data_.get()[length_] = 0;
    if (memcpy_s(data_.get(), length_, secureChar, length_) != EOK) {
        NETSTACK_LOGE("memcpy_s failed!");
    }
}

SecureChar::SecureChar(const SecureChar &secureChar)
{
    *this = secureChar;
}

SecureChar &SecureChar::operator=(const SecureChar &secureChar)
{
    if (this != &secureChar) {
        if (secureChar.Length() == 0) {
            return *this;
        }
        length_ = secureChar.Length();
        data_ = std::make_unique<char[]>(length_ + 1);
        data_.get()[length_] = 0;
        if (memcpy_s(data_.get(), length_, secureChar.Data(), length_) != EOK) {
            NETSTACK_LOGE("memcpy_s failed!");
        }
    }
    return *this;
}

const char *SecureChar::Data() const
{
    return data_.get();
}

size_t SecureChar::Length() const
{
    return length_;
}

CArrString g_map2CArrString(std::map<std::string, std::string> map)
{
    auto size = map.size() * MAP_TUPLE_SIZE;
    CArrString ret{ .head = nullptr, .size = 0};
    if (size <= 0) {
        return ret;
    }
    ret.head = static_cast<char**>(malloc(sizeof(char*) * size));
    if (ret.head == nullptr) {
        return ret;
    }
    ret.size = static_cast<int64_t>(size);
    int index = 0;
    for (const auto& [key, value] : map) {
        ret.head[index] = MallocCString(key);
        ret.head[index + 1] = MallocCString(value);
        index += MAP_TUPLE_SIZE;
    }
    return ret;
}
} // namespace OHOS::NetStack::Http
