/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef NETSTACK_HTTP_TLS_CONFIG_H
#define NETSTACK_HTTP_TLS_CONFIG_H

#include <functional>
#include <map>
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <unordered_set>

#include "securec.h"

namespace OHOS::NetStack::Http {
enum class CipherSuite {
    INVALID = -1,
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0x009c,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0x009d,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc009,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc013,
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0xc00a,
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0xc014,
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000a,
};

enum class TlsVersion {
    DEFAULT = 0,
    TLSv1_0 = 4,
    TLSv1_1 = 5,
    TLSv1_2 = 6,
    TLSv1_3 = 7,
};

struct TlsCipherString {
    std::string ciperSuiteString;
    std::string tlsV13CiperSuiteString;
};

[[nodiscard]] CipherSuite GetTlsCipherSuiteFromStandardName(const std::string &standardName);
[[nodiscard]] std::string GetInnerNameFromCipherSuite(CipherSuite cipherSuite);
[[nodiscard]] TlsCipherString ConvertCipherSuiteToCipherString(const std::unordered_set<CipherSuite> &cipherSuite);

} // namespace OHOS::NetStack::Http
#endif // NETSTACK_HTTP_TLS_CONFIG_H
