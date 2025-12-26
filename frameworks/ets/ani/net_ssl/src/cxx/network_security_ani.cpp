/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "network_security_ani.h"

#include "net_ssl.h"
#include "wrapper.rs.h"
#include "net_ssl_verify_cert.h"

namespace OHOS {
namespace NetStackAni {

static const std::map<int32_t, const char *> SSL_ERR_MAP = {
    {NetStack::Ssl::SslErrorCode::SSL_NONE_ERR, "Verify success."},
    {NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_UNSPECIFIED, "Unspecified error."},
    {NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
        "Unable to get issuer certificate."},
    {NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_UNABLE_TO_GET_CRL,
        "Unable to get certificate revocation list (CRL)."},
    {NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE,
        "Unable to decrypt certificate signature."},
    {NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE,
        "Unable to decrypt CRL signature."},
    {NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY,
        "Unable to decode issuer public key."},
    {NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_CERT_SIGNATURE_FAILURE, "Certificate signature failure."},
    {NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_CRL_SIGNATURE_FAILURE, "CRL signature failure."},
    {NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_CERT_NOT_YET_VALID, "Certificate is not yet valid."},
    {NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_CERT_HAS_EXPIRED, "Certificate has expired."},
    {NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_CRL_NOT_YET_VALID, "CRL is not yet valid."},
    {NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_CRL_HAS_EXPIRED, "CRL has expired."},
    {NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_CERT_REVOKED, "Certificate has been revoked."},
    {NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_INVALID_CA, "Invalid certificate authority (CA)."},
    {NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_CERT_UNTRUSTED, "Certificate is untrusted."},
    {NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, "self-signed certificate."},
    {NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_INVALID_CALL, "invalid certificate verification context."}
};

static std::string GetErrorMessage(int32_t errorCode)
{
    auto pos = SSL_ERR_MAP.find(errorCode);
    if (pos != SSL_ERR_MAP.end()) {
        return pos->second;
    }
    return SSL_ERR_MAP.at(NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_CERT_UNTRUSTED);
}

static int32_t GetErrorCode(int32_t errorCode)
{
    const auto &errorCodeSet = NetStack::Ssl::SslErrorCodeSetSinceAPI12;

    if (errorCodeSet.find(errorCode) == errorCodeSet.end()) {
        errorCode = NetStack::Ssl::SSL_X509_V_ERR_UNSPECIFIED;
    }
    return errorCode;
}

rust::String GetErrorCodeAndMessage(int32_t &errorCode)
{
    int originCode = errorCode;
    errorCode = GetErrorCode(originCode);
    return rust::string(GetErrorMessage(originCode));
}

uint32_t NetStackVerifyCertificationCa(const CertBlob &cert, const CertBlob &caCert)
{
    std::string a;
    NetStack::Ssl::CertBlob nativeCert{.type = cert.cert_type,
                                       .size = cert.data.size(),
                                       .data = const_cast<uint8_t *>(cert.data.data()),
                                       };

    NetStack::Ssl::CertBlob nativeCaCert{.type = caCert.cert_type,
                                         .size = caCert.data.size(),
                                         .data = const_cast<uint8_t *>(caCert.data.data()),
                                         };
    return NetStack::Ssl::NetStackVerifyCertification(&nativeCert, &nativeCaCert);
}

uint32_t NetStackVerifyCertification(const CertBlob &cert)
{
    NetStack::Ssl::CertBlob nativeCert{.type = cert.cert_type,
                                       .size = cert.data.size(),
                                       .data = const_cast<uint8_t *>(cert.data.data()),
                                       };
    return NetStack::Ssl::NetStackVerifyCertification(&nativeCert);
}

} // namespace NetStackAni
} // namespace OHOS
