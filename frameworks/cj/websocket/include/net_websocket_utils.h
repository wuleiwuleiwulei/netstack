/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef NET_WEBSOCKET_UTILS_H
#define NET_WEBSOCKET_UTILS_H

#include <cstddef>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <chrono>
#include <map>

#include "constant.h"
#include "cj_ffi/cj_common_ffi.h"

namespace OHOS::NetStack::NetWebSocket {
uint8_t* MallocUInt8(const std::string& origin);
char* MallocCString(const std::string& origin);
CArrString Map2CArrString(std::map<std::string, std::string> map);
void FreeCArrString(CArrString& arrStr);

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
}
#endif

