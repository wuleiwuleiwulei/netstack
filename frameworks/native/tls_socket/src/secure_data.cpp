/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "secure_data.h"

#include <securec.h>

#include "netstack_log.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
SecureData::SecureData() : data_(std::make_unique<char[]>(0)) {}

SecureData::~SecureData()
{
    if (memset_s(data_.get(), length_, 0, length_) != EOK) {
        NETSTACK_LOGE("memcpy_s failed!");
    }
}

SecureData::SecureData(const std::string &secureData)
    : length_(secureData.length()), data_(std::make_unique<char[]>(length_ + 1))
{
    if (length_ == 0) {
        return;
    }
    data_.get()[length_] = 0;
    if (memcpy_s(data_.get(), length_, secureData.c_str(), length_) != EOK) {
        NETSTACK_LOGE("memcpy_s failed!");
        return;
    }
}

SecureData::SecureData(const uint8_t *secureData, size_t length)
{
    data_ = std::make_unique<char[]>(length + 1);
    length_ = length;
    data_.get()[length_] = 0;
    if (memcpy_s(data_.get(), length_, secureData, length_) != EOK) {
        NETSTACK_LOGE("memcpy_s failed!");
    }
}

SecureData::SecureData(const SecureData &secureData)
{
    *this = secureData;
}

SecureData &SecureData::operator=(const SecureData &secureData)
{
    if (this != &secureData) {
        if (secureData.Length() == 0) {
            return *this;
        }
        length_ = secureData.Length();
        data_ = std::make_unique<char[]>(length_ + 1);
        data_.get()[length_] = 0;
        if (memcpy_s(data_.get(), length_, secureData.Data(), length_) != EOK) {
            NETSTACK_LOGE("memcpy_s failed!");
        }
    }
    return *this;
}

const char *SecureData::Data() const
{
    return data_.get();
}

size_t SecureData::Length() const
{
    return length_;
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
