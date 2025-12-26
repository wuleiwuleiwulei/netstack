/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "net_websocket_utils.h"

#include "securec.h"
#include "netstack_log.h"

namespace OHOS::NetStack::NetWebSocket {

uint8_t* MallocUInt8(const std::string& origin)
{
    auto len = origin.length();
    if (len <= 0) {
        return nullptr;
    }
    char* res = static_cast<char*>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        return nullptr;
    }
    return reinterpret_cast<uint8_t*>(std::char_traits<char>::copy(res, origin.c_str(), len));
}

char* MallocCString(const std::string &origin)
{
    if (origin.empty()) {
        return nullptr;
    }
    auto len = origin.length() + 1;
    char *res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

CArrString Map2CArrString(std::map<std::string, std::string> map)
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

void FreeCArrString(CArrString& arrStr)
{
    if (arrStr.head == nullptr) {
        return;
    }
    for (int64_t i = 0; i < arrStr.size; i++) {
        free(arrStr.head[i]);
    }
    free(arrStr.head);
    arrStr.head = nullptr;
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
    if (memcpy_s(data_.get(), length_, secureChar.c_str(), length_) != ERR_OK) {
        NETSTACK_LOGE("memcpy_s failed!");
        return;
    }
}

SecureChar::SecureChar(const uint8_t *secureChar, size_t length)
{
    data_ = std::make_unique<char[]>(length + 1);
    length_ = length;
    data_.get()[length_] = 0;
    if (memcpy_s(data_.get(), length_, secureChar, length_) != ERR_OK) {
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
        if (memcpy_s(data_.get(), length_, secureChar.Data(), length_) != ERR_OK) {
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
}