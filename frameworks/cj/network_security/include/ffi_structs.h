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

#ifndef NET_NETWORK_SECURITY_FFI_STRUCTS_H
#define NET_NETWORK_SECURITY_FFI_STRUCTS_H

#include <cstdint>

#include "cj_common_ffi.h"

namespace OHOS::NetStack::NetworkSecurity {
using namespace OHOS::NetStack::NetworkSecurity;

struct CCertBlob {
    int64_t certType;
    CArrUI8 certData;
};

} // namespace OHOS::NetStack::NetworkSecurity

#endif