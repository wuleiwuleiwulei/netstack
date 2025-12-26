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

#include "secure_char.h"

#include "securec.h"
#include "netstack_log.h"

namespace OHOS::NetStack::Secure {
SecureChar::SecureChar() : data_(std::make_unique<char[]>(0)) {}

SecureChar::~SecureChar()
{
    (void)memset_s(data_.get(), length_, 0, length_);
}

SecureChar::SecureChar(const std::string &SecureChar)
    : length_(SecureChar.length()), data_(std::make_unique<char[]>(length_ + 1))
{
    if (length_ == 0) {
        return;
    }
    data_.get()[length_] = 0;
    if (memcpy_s(data_.get(), length_, SecureChar.c_str(), length_) != EOK) {
        NETSTACK_LOGE("memcpy_s failed!");
        return;
    }
}

SecureChar::SecureChar(const uint8_t *SecureChar, size_t length)
{
    data_ = std::make_unique<char[]>(length + 1);
    length_ = length;
    data_.get()[length_] = 0;
    if (memcpy_s(data_.get(), length_, SecureChar, length_) != EOK) {
        NETSTACK_LOGE("memcpy_s failed!");
    }
}

SecureChar::SecureChar(const SecureChar &SecureChar)
{
    *this = SecureChar;
}

SecureChar &SecureChar::operator=(const SecureChar &SecureChar)
{
    if (this != &SecureChar) {
        if (SecureChar.Length() == 0) {
            return *this;
        }
        length_ = SecureChar.Length();
        data_ = std::make_unique<char[]>(length_ + 1);
        data_.get()[length_] = 0;
        if (memcpy_s(data_.get(), length_, SecureChar.Data(), length_) != EOK) {
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
} // namespace OHOS::NetStack::Secure