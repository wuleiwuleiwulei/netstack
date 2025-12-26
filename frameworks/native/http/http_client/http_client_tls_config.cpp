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

#include "http_client_tls_config.h"

namespace OHOS::NetStack::HttpClient {
struct CipherSuiteConvertor {
    CipherSuite cipherSuite = CipherSuite::INVALID;
    const char *innerName = nullptr;
    const char *standardName = nullptr;
};

static constexpr const CipherSuiteConvertor CIPHER_SUITE_CONVERTOR[] = {
    {
        .cipherSuite = CipherSuite::TLS_AES_128_GCM_SHA256,
        .innerName = "TLS_AES_128_GCM_SHA256",
        .standardName = "TLS_AES_128_GCM_SHA256",
    },
    {
        .cipherSuite = CipherSuite::TLS_AES_256_GCM_SHA384,
        .innerName = "TLS_AES_256_GCM_SHA384",
        .standardName = "TLS_AES_256_GCM_SHA384",
    },
    {
        .cipherSuite = CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        .innerName = "TLS_CHACHA20_POLY1305_SHA256",
        .standardName = "TLS_CHACHA20_POLY1305_SHA256",
    },
    {
        .cipherSuite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .innerName = "ECDHE-ECDSA-AES128-GCM-SHA256",
        .standardName = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    },
    {
        .cipherSuite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .innerName = "ECDHE-RSA-AES128-GCM-SHA256",
        .standardName = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    },
    {
        .cipherSuite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        .innerName = "ECDHE-ECDSA-AES256-GCM-SHA384",
        .standardName = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    },
    {
        .cipherSuite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        .innerName = "ECDHE-RSA-AES256-GCM-SHA384",
        .standardName = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    },
    {
        .cipherSuite = CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        .innerName = "ECDHE-ECDSA-CHACHA20-POLY1305",
        .standardName = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    },
    {
        .cipherSuite = CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .innerName = "ECDHE-RSA-CHACHA20-POLY1305",
        .standardName = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    },
    {
        .cipherSuite = CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
        .innerName = "AES128-GCM-SHA256",
        .standardName = "TLS_RSA_WITH_AES_128_GCM_SHA256",
    },
    {
        .cipherSuite = CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
        .innerName = "AES256-GCM-SHA384",
        .standardName = "TLS_RSA_WITH_AES_256_GCM_SHA384",
    },
    {
        .cipherSuite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        .innerName = "ECDHE-ECDSA-AES128-SHA",
        .standardName = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    },
    {
        .cipherSuite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        .innerName = "ECDHE-RSA-AES128-SHA",
        .standardName = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    },
    {
        .cipherSuite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        .innerName = "ECDHE-ECDSA-AES256-SHA",
        .standardName = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    },
    {
        .cipherSuite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        .innerName = "ECDHE-RSA-AES256-SHA",
        .standardName = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    },
    {
        .cipherSuite = CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
        .innerName = "AES128-SHA",
        .standardName = "TLS_RSA_WITH_AES_128_CBC_SHA",
    },
    {
        .cipherSuite = CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
        .innerName = "AES256-SHA",
        .standardName = "TLS_RSA_WITH_AES_256_CBC_SHA",
    },
    {
        .cipherSuite = CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        .innerName = "DES-CBC3-SHA",
        .standardName = "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    },
};

CipherSuite GetTlsCipherSuiteFromStandardName(const std::string &standardName)
{
    for (const auto &suite : CIPHER_SUITE_CONVERTOR) {
        if (suite.standardName == standardName) {
            return suite.cipherSuite;
        }
    }
    return CipherSuite::INVALID;
}

std::string GetInnerNameFromCipherSuite(CipherSuite cipherSuite)
{
    for (const auto &suite : CIPHER_SUITE_CONVERTOR) {
        if (suite.cipherSuite == cipherSuite) {
            return suite.innerName;
        }
    }
    return {};
}

static bool IsTlsV13Cipher(const std::string &innerName)
{
    return innerName == "TLS_AES_128_GCM_SHA256" || innerName == "TLS_AES_256_GCM_SHA384" ||
           innerName == "TLS_CHACHA20_POLY1305_SHA256";
}

TlsCipherString ConvertCipherSuiteToCipherString(const std::unordered_set<CipherSuite> &cipherSuite)
{
    TlsCipherString cipherString;
    for (const auto &cipher : cipherSuite) {
        auto innerName = GetInnerNameFromCipherSuite(cipher);
        if (innerName.empty()) {
            continue;
        }
        if (IsTlsV13Cipher(innerName)) {
            cipherString.tlsV13CiperSuiteString.append(innerName).append(":");
        } else {
            cipherString.ciperSuiteString.append(innerName).append(":");
        }
    }
    if (!cipherString.tlsV13CiperSuiteString.empty()) {
        cipherString.tlsV13CiperSuiteString.pop_back();
    }
    if (!cipherString.ciperSuiteString.empty()) {
        cipherString.ciperSuiteString.pop_back();
    }
    return cipherString;
}

} // namespace OHOS::NetStack::HttpClient