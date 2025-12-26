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

#include "tls_config_enhanced.h"

namespace OHOS::NetStack::TlsSocket {
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

std::string ClientCertificate::GetCertTypeString() const
{
    switch (type) {
        case CertType::PEM:
            return "PEM";
        case CertType::DER:
            return "DER";
        case CertType::P12:
            return "P12";
        default:
            break;
    }
    return "";
}

std::string DnsServers::ToString() const
{
    std::string s;
    for (const auto &server : *this) {
        // Do not add 0
        s.append(server.ip).append(server.port != 0 ? ":" + std::to_string(server.port) : "").append(",");
    }
    if (!s.empty()) {
        s.pop_back(); // last ','
    }
    return s;
}

std::string TransferRange::ToHeaderString() const
{
    std::string s;
    for (const auto &range : *this) {
        if (!range.from && !range.to) {
            continue;
        }
        std::string from = range.from ? std::to_string(range.from.value()) : "";
        std::string to = range.to ? std::to_string(range.to.value()) : "";
        s.append(from).append("-").append(to).append(", ");
    }
    if (s.size() > std::string(", ").size()) {
        s.pop_back(); // pop last ', '
        s.pop_back(); // pop last ', '
    }
    return s;
}

CipherSuite GetCipherSuiteFromStandardName(const std::string &standardName)
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

TlsVersion ConvertTlsVersion(const std::string &tlsVersion)
{
    if (tlsVersion == "default") {
        return TlsVersion::DEFAULT;
    }
    if (tlsVersion == "TlsV1.0") {
        return TlsVersion::TLSv1_0;
    }
    if (tlsVersion == "TlsV1.1") {
        return TlsVersion::TLSv1_1;
    }
    if (tlsVersion == "TlsV1.2") {
        return TlsVersion::TLSv1_2;
    }
    if (tlsVersion == "TlsV1.3") {
        return TlsVersion::TLSv1_3;
    }
    return TlsVersion::DEFAULT;
}

TlsVersionRange ConvertTlsVersion(TlsVersion tlsVersion)
{
    TlsVersionRange range;
    if (tlsVersion == TlsVersion::DEFAULT) {
        return range;
    }
    if (tlsVersion == TlsVersion::TLSv1_0) {
        range.min.emplace(TlsVersion::TLSv1_0);
        range.max.emplace(TlsVersion::TLSv1_0);
        return range;
    }
    if (tlsVersion == TlsVersion::TLSv1_1) {
        range.min.emplace(TlsVersion::TLSv1_1);
        range.max.emplace(TlsVersion::TLSv1_1);
        return range;
    }
    if (tlsVersion == TlsVersion::TLSv1_2) {
        range.min.emplace(TlsVersion::TLSv1_2);
        range.max.emplace(TlsVersion::TLSv1_2);
        return range;
    }
    if (tlsVersion == TlsVersion::TLSv1_3) {
        range.min.emplace(TlsVersion::TLSv1_3);
        range.max.emplace(TlsVersion::TLSv1_3);
        return range;
    }
    return range;
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

HashAlgorithm GetHashAlgorithm(const std::string &hashAlgorithm)
{
    if (hashAlgorithm == "SHA-256") {
        return HashAlgorithm::SHA256;
    }
    return HashAlgorithm::INVALID;
}
} // namespace OHOS::NetStack::TlsSocket