/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_VERIFY_CERT_H
#define COMMUNICATIONNETSTACK_VERIFY_CERT_H

#include <fstream>
#include <iostream>
#include <set>

#include <openssl/ssl.h>

#include "net_ssl_type.h"

namespace OHOS {
namespace NetStack {
namespace Ssl {
class SslConstant final {
public:
    /* Sys Ca Path */
    static const char *const SYSPRECAPATH;
    /* User Installed Ca Path */
    static const char *const USERINSTALLEDCAPATH;
    /* Uidtransformdivisor */
    static const int UIDTRANSFORMDIVISOR;
};

enum VerifyResult { VERIFY_RESULT_UNKNOWN = -1, VERIFY_RESULT_FAIL = 0, VERIFY_RESULT_SUCCESS = 1 };

enum SslErrorCode {
    SSL_NONE_ERR = 0,
    SSL_ERROR_CODE_BASE = 2305000,
    // The following error codes are added since API11
    SSL_X509_V_ERR_UNSPECIFIED = SSL_ERROR_CODE_BASE + X509_V_ERR_UNSPECIFIED,
    SSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT = SSL_ERROR_CODE_BASE + X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
    SSL_X509_V_ERR_UNABLE_TO_GET_CRL = SSL_ERROR_CODE_BASE + X509_V_ERR_UNABLE_TO_GET_CRL,
    SSL_X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE = SSL_ERROR_CODE_BASE + X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE,
    SSL_X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE = SSL_ERROR_CODE_BASE + X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE,
    SSL_X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY =
        SSL_ERROR_CODE_BASE + X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY,
    SSL_X509_V_ERR_CERT_SIGNATURE_FAILURE = SSL_ERROR_CODE_BASE + X509_V_ERR_CERT_SIGNATURE_FAILURE,
    SSL_X509_V_ERR_CRL_SIGNATURE_FAILURE = SSL_ERROR_CODE_BASE + X509_V_ERR_CRL_SIGNATURE_FAILURE,
    SSL_X509_V_ERR_CERT_NOT_YET_VALID = SSL_ERROR_CODE_BASE + X509_V_ERR_CERT_NOT_YET_VALID,
    SSL_X509_V_ERR_CERT_HAS_EXPIRED = SSL_ERROR_CODE_BASE + X509_V_ERR_CERT_HAS_EXPIRED,
    SSL_X509_V_ERR_CRL_NOT_YET_VALID = SSL_ERROR_CODE_BASE + X509_V_ERR_CRL_NOT_YET_VALID,
    SSL_X509_V_ERR_CRL_HAS_EXPIRED = SSL_ERROR_CODE_BASE + X509_V_ERR_CRL_HAS_EXPIRED,
    SSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY =
        SSL_ERROR_CODE_BASE + X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
    SSL_X509_V_ERR_CERT_REVOKED = SSL_ERROR_CODE_BASE + X509_V_ERR_CERT_REVOKED,
    SSL_X509_V_ERR_INVALID_CA = SSL_ERROR_CODE_BASE + X509_V_ERR_INVALID_CA,
    SSL_X509_V_ERR_CERT_UNTRUSTED = SSL_ERROR_CODE_BASE + X509_V_ERR_CERT_UNTRUSTED,
    // The following error codes are added since API12
    SSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = SSL_ERROR_CODE_BASE + X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
    SSL_X509_V_ERR_INVALID_CALL = SSL_ERROR_CODE_BASE + X509_V_ERR_INVALID_CALL,
    SSL_X509_V_ERR_OUT_OF_MEMORY = SSL_ERROR_CODE_BASE + 999
};

static const std::multiset<uint32_t> SslErrorCodeSetBase{SSL_NONE_ERR,
                                                         SSL_ERROR_CODE_BASE,
                                                         SSL_X509_V_ERR_UNSPECIFIED,
                                                         SSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
                                                         SSL_X509_V_ERR_UNABLE_TO_GET_CRL,
                                                         SSL_X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE,
                                                         SSL_X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE,
                                                         SSL_X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY,
                                                         SSL_X509_V_ERR_CERT_SIGNATURE_FAILURE,
                                                         SSL_X509_V_ERR_CRL_SIGNATURE_FAILURE,
                                                         SSL_X509_V_ERR_CERT_NOT_YET_VALID,
                                                         SSL_X509_V_ERR_CERT_HAS_EXPIRED,
                                                         SSL_X509_V_ERR_CRL_NOT_YET_VALID,
                                                         SSL_X509_V_ERR_CRL_HAS_EXPIRED,
                                                         SSL_X509_V_ERR_CERT_REVOKED,
                                                         SSL_X509_V_ERR_INVALID_CA,
                                                         SSL_X509_V_ERR_CERT_UNTRUSTED};

static const std::multiset<uint32_t> SslErrorCodeSetSinceAPI12{SSL_NONE_ERR,
                                                               SSL_ERROR_CODE_BASE,
                                                               SSL_X509_V_ERR_UNSPECIFIED,
                                                               SSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
                                                               SSL_X509_V_ERR_UNABLE_TO_GET_CRL,
                                                               SSL_X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE,
                                                               SSL_X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE,
                                                               SSL_X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY,
                                                               SSL_X509_V_ERR_CERT_SIGNATURE_FAILURE,
                                                               SSL_X509_V_ERR_CRL_SIGNATURE_FAILURE,
                                                               SSL_X509_V_ERR_CERT_NOT_YET_VALID,
                                                               SSL_X509_V_ERR_CERT_HAS_EXPIRED,
                                                               SSL_X509_V_ERR_CRL_NOT_YET_VALID,
                                                               SSL_X509_V_ERR_CRL_HAS_EXPIRED,
                                                               SSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
                                                               SSL_X509_V_ERR_CERT_REVOKED,
                                                               SSL_X509_V_ERR_INVALID_CA,
                                                               SSL_X509_V_ERR_CERT_UNTRUSTED,
                                                               // New error code since API12.
                                                               SSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
                                                               SSL_X509_V_ERR_INVALID_CALL,
                                                               SSL_X509_V_ERR_OUT_OF_MEMORY};

std::string GetUserInstalledCaPath();

X509 *PemToX509(const uint8_t *pemCert, size_t pemSize);

X509 *DerToX509(const uint8_t *derCert, size_t derSize);

X509 *CertBlobToX509(const CertBlob *cert);

uint32_t VerifyCert(const CertBlob *cert);

uint32_t VerifyCert(const CertBlob *cert, const CertBlob *caCert);

void FreeResources(X509 **certX509, X509 **caX509, X509_STORE **store, X509_STORE_CTX **ctx);
} // namespace Ssl
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATIONNETSTACK_VERIFY_CERT_H
