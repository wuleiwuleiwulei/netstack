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

#include <fstream>
#include <iostream>
#include <string>

#include "ipc_skeleton.h"
#include "net_ssl_verify_cert.h"
#include "netstack_log.h"

namespace OHOS {
namespace NetStack {
namespace Ssl {

const char *const SslConstant::SYSPRECAPATH = "/etc/security/certificates";
const char *const SslConstant::USERINSTALLEDCAPATH = "/data/certificates/user_cacerts";
const int SslConstant::UIDTRANSFORMDIVISOR = 200000;

std::string GetUserInstalledCaPath()
{
    std::string userInstalledCaPath = SslConstant::USERINSTALLEDCAPATH;
    int32_t uid = OHOS::IPCSkeleton::GetCallingUid();
    NETSTACK_LOGD("uid: %{public}d\n", uid);
    uid /= SslConstant::UIDTRANSFORMDIVISOR;
    return userInstalledCaPath.append("/").append(std::to_string(uid).c_str());
}

X509 *PemToX509(const uint8_t *pemCert, size_t pemSize)
{
    BIO *bio = BIO_new_mem_buf(pemCert, pemSize);
    if (bio == nullptr) {
        NETSTACK_LOGE("Failed to create BIO of PEM\n");
        return nullptr;
    }

    X509 *x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (x509 == nullptr) {
        NETSTACK_LOGE("Failed to convert PEM to X509\n");
        BIO_free(bio);
        bio = nullptr;
        return nullptr;
    }

    BIO_free(bio);
    bio = nullptr;
    return x509;
}

X509 *DerToX509(const uint8_t *derCert, size_t derSize)
{
    BIO *bio = BIO_new_mem_buf(derCert, derSize);
    if (bio == nullptr) {
        NETSTACK_LOGE("Failed to create BIO of DER\n");
        return nullptr;
    }

    X509 *x509 = d2i_X509_bio(bio, nullptr);
    if (x509 == nullptr) {
        NETSTACK_LOGE("Failed to convert DER to X509\n");
        BIO_free(bio);
        bio = nullptr;
        return nullptr;
    }

    BIO_free(bio);
    bio = nullptr;
    return x509;
}

X509 *CertBlobToX509(const CertBlob *cert)
{
    X509 *x509 = nullptr;
    do {
        if (cert == nullptr) {
            continue;
        }
        switch (cert->type) {
            case CERT_TYPE_PEM:
                x509 = PemToX509(cert->data, cert->size);
                if (x509 == nullptr) {
                    NETSTACK_LOGE("x509 of PEM cert is nullptr\n");
                }
                break;
            case CERT_TYPE_DER:
                x509 = DerToX509(cert->data, cert->size);
                if (x509 == nullptr) {
                    NETSTACK_LOGE("x509 of DER cert is nullptr\n");
                }
                break;
            default:
                break;
        }
    } while (false);
    return x509;
}

uint32_t VerifyCert(const CertBlob *cert)
{
    uint32_t verifyResult = SSL_X509_V_ERR_UNSPECIFIED;
    X509 *certX509 = nullptr;
    X509_STORE *store = nullptr;
    X509_STORE_CTX *ctx = nullptr;
    do {
        certX509 = CertBlobToX509(cert);
        if (certX509 == nullptr) {
            NETSTACK_LOGE("x509 of cert is nullptr\n");
        }
        store = X509_STORE_new();
        if (store == nullptr) {
            continue;
        }
        std::string userInstalledCaPath = GetUserInstalledCaPath();
        if (X509_STORE_load_locations(store, nullptr, SslConstant::SYSPRECAPATH) != VERIFY_RESULT_SUCCESS) {
            NETSTACK_LOGE("load SYSPRECAPATH store failed\n");
        }
        if (X509_STORE_load_locations(store, nullptr, userInstalledCaPath.c_str()) != VERIFY_RESULT_SUCCESS) {
            NETSTACK_LOGI("load userInstalledCaPath store failed\n");
        }
        ctx = X509_STORE_CTX_new();
        if (ctx == nullptr) {
            continue;
        }
        X509_STORE_CTX_init(ctx, store, certX509, nullptr);
        verifyResult = static_cast<uint32_t>(X509_verify_cert(ctx));
        if (verifyResult != VERIFY_RESULT_SUCCESS) {
            verifyResult = static_cast<uint32_t>(X509_STORE_CTX_get_error(ctx) + SSL_ERROR_CODE_BASE);
            NETSTACK_LOGE("failed to verify certificate: %{public}s (%{public}d)\n",
                          X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)), verifyResult);
            break;
        } else {
            verifyResult = X509_V_OK;
            NETSTACK_LOGD("certificate validation succeeded.\n");
        }
    } while (false);

    FreeResources(&certX509, nullptr, &store, &ctx);
    return verifyResult;
}

uint32_t VerifyCert(const CertBlob *cert, const CertBlob *caCert)
{
    uint32_t verifyResult = SSL_X509_V_ERR_UNSPECIFIED;
    X509 *certX509 = nullptr;
    X509 *caX509 = nullptr;
    X509_STORE *store = nullptr;
    X509_STORE_CTX *ctx = nullptr;
    do {
        certX509 = CertBlobToX509(cert);
        if (certX509 == nullptr) {
            NETSTACK_LOGE("x509 of cert is nullptr\n");
        }
        caX509 = CertBlobToX509(caCert);
        if (caX509 == nullptr) {
            NETSTACK_LOGE("x509 of ca is nullptr\n");
        }
        store = X509_STORE_new();
        if (store == nullptr) {
            continue;
        }
        if (X509_STORE_add_cert(store, caX509) != VERIFY_RESULT_SUCCESS) {
            NETSTACK_LOGE("add ca to store failed\n");
        }
        ctx = X509_STORE_CTX_new();
        if (ctx == nullptr) {
            continue;
        }
        X509_STORE_CTX_init(ctx, store, certX509, nullptr);
        verifyResult = static_cast<uint32_t>(X509_verify_cert(ctx));
        if (verifyResult != VERIFY_RESULT_SUCCESS) {
            verifyResult = static_cast<uint32_t>(X509_STORE_CTX_get_error(ctx) + SSL_ERROR_CODE_BASE);
            NETSTACK_LOGE("failed to verify certificate: %{public}s (%{public}d)\n",
                          X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)), verifyResult);
            break;
        } else {
            verifyResult = X509_V_OK;
            NETSTACK_LOGD("certificate validation succeeded.\n");
        }
    } while (false);

    FreeResources(&certX509, &caX509, &store, &ctx);
    return verifyResult;
}

void FreeResources(X509 **certX509, X509 **caX509, X509_STORE **store, X509_STORE_CTX **ctx)
{
    if (certX509 != nullptr) {
        if (*certX509 != nullptr) {
            X509_free(*certX509);
            *certX509 = nullptr;
        }
    }
    if (caX509 != nullptr) {
        if (*caX509 != nullptr) {
            X509_free(*caX509);
            *caX509 = nullptr;
        }
    }
    if (store != nullptr) {
        if (*store != nullptr) {
            X509_STORE_free(*store);
            *store = nullptr;
        }
    }
    if (ctx != nullptr) {
        if (*ctx != nullptr) {
            X509_STORE_CTX_free(*ctx);
            *ctx = nullptr;
        }
    }
}
} // namespace Ssl
} // namespace NetStack
} // namespace OHOS