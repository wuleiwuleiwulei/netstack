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

#ifndef COMMUNICATION_NETSTACK_SECURE_CHAR_H
#define COMMUNICATION_NETSTACK_SECURE_CHAR_H

#include <cstddef>
#include <memory>
#include <string>

namespace OHOS::NetStack::Secure {
class SecureChar {
public:
    SecureChar();
    ~SecureChar();
    explicit SecureChar(const std::string &SecureChar);
    SecureChar(const uint8_t *SecureChar, size_t length);
    SecureChar(const SecureChar &SecureChar);
    SecureChar &operator=(const SecureChar &SecureChar);

    const char *Data() const;
    size_t Length() const;

private:
    size_t length_ = 0;
    std::unique_ptr<char[]> data_ = nullptr;
};
} // namespace OHOS::NetStack::Secure
#endif // COMMUNICATION_NETSTACK_SECURE_CHAR_H