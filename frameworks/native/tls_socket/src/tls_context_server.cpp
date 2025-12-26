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

#include "tls_context_server.h"

#include <cinttypes>
#include <string>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "netstack_log.h"
#include "netstack_common_utils.h"
#include "tls_utils.h"
#ifdef HAS_NETMANAGER_BASE
#include "network_security_config.h"
#endif

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
VerifyMode TLSContextServer::verifyMode_ = TWO_WAY_MODE;
std::unique_ptr<TLSContextServer> TLSContextServer::CreateConfiguration(const TLSConfiguration &configuration)
{
    auto tlsContext = std::make_unique<TLSContextServer>();
    if (!InitTlsContext(tlsContext.get(), configuration)) {
        NETSTACK_LOGE("Failed to init tls context");
        return nullptr;
    }
    return tlsContext;
}

void InitEnvServer()
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

bool TLSContextServer::SetCipherList(TLSContextServer *tlsContext, const TLSConfiguration &configuration)
{
    if (!tlsContext) {
        NETSTACK_LOGE("tlsContext is null");
        return false;
    }
    NETSTACK_LOGD("GetCipherSuite = %{public}s", configuration.GetCipherSuite().c_str());
    if (SSL_CTX_set_cipher_list(tlsContext->ctx_, configuration.GetCipherSuite().c_str()) <= 0) {
        NETSTACK_LOGE("Error setting the cipher list");
        return false;
    }
    return true;
}

void TLSContextServer::GetCiphers(TLSContextServer *tlsContext)
{
    if (!tlsContext) {
        NETSTACK_LOGE("tlsContext is null");
        return;
    }
    std::vector<CipherSuite> cipherSuiteVec;
    STACK_OF(SSL_CIPHER) *sk = SSL_CTX_get_ciphers(tlsContext->ctx_);
    if (!sk) {
        NETSTACK_LOGE("sk is null");
        return;
    }
    CipherSuite cipherSuite;
    for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
        const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(sk, i);
        cipherSuite.cipherId_ = SSL_CIPHER_get_id(cipher);
        cipherSuite.cipherName_ = SSL_CIPHER_get_name(cipher);
        cipherSuiteVec.push_back(cipherSuite);
    }
}

bool TLSContextServer::SetSignatureAlgorithms(TLSContextServer *tlsContext, const TLSConfiguration &configuration)
{
    if (!tlsContext) {
        NETSTACK_LOGE("tlsContext is null");
        return false;
    }
    if (configuration.GetSignatureAlgorithms().empty()) {
        NETSTACK_LOGE("configuration get signature algorithms is empty");
        return false;
    }

    if (!SSL_CTX_set1_sigalgs_list(tlsContext->ctx_, configuration.GetSignatureAlgorithms().c_str())) {
        NETSTACK_LOGE("Error setting the Signature Algorithms");
        return false;
    }
    return true;
}

void TLSContextServer::UseRemoteCipher(TLSContextServer *tlsContext)
{
    if (!tlsContext) {
        NETSTACK_LOGE("TLSContextServer::UseRemoteCipher: tlsContext is null");
        return;
    }
    if (tlsContext->tlsConfiguration_.GetUseRemoteCipherPrefer()) {
        SSL_CTX_set_options(tlsContext->ctx_, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }
    NETSTACK_LOGI("SSL_CTX_get_options = %{public}" PRIx64,
                  static_cast<uint64_t>(SSL_CTX_get_options(tlsContext->ctx_)));
}

void TLSContextServer::SetMinAndMaxProtocol(TLSContextServer *tlsContext)
{
    if (!tlsContext) {
        NETSTACK_LOGE("TLSContextServer::SetMinAndMaxProtocol: tlsContext is null");
        return;
    }
    const long anyVersion = TLS_ANY_VERSION;
    long minVersion = anyVersion;
    long maxVersion = anyVersion;

    switch (tlsContext->tlsConfiguration_.GetMinProtocol()) {
        case TLS_V1_2:
            minVersion = TLS1_2_VERSION;
            break;
        case TLS_V1_3:
            minVersion = TLS1_3_VERSION;
            break;
        case UNKNOW_PROTOCOL:
            break;
        default:
            break;
    }

    switch (tlsContext->tlsConfiguration_.GetMaxProtocol()) {
        case TLS_V1_2:
            maxVersion = TLS1_2_VERSION;
            break;
        case TLS_V1_3:
            maxVersion = TLS1_3_VERSION;
            break;
        case UNKNOW_PROTOCOL:
            break;
        default:
            break;
    }

    if (minVersion != anyVersion && !SSL_CTX_set_min_proto_version(tlsContext->ctx_, minVersion)) {
        NETSTACK_LOGE("Error while setting the minimal protocol version");
        return;
    }

    if (maxVersion != anyVersion && !SSL_CTX_set_max_proto_version(tlsContext->ctx_, maxVersion)) {
        NETSTACK_LOGE("Error while setting the maximum protocol version");
        return;
    }

    NETSTACK_LOGD("minProtocol = %{public}lx, maxProtocol = %{public}lx",
                  SSL_CTX_get_min_proto_version(tlsContext->ctx_), SSL_CTX_get_max_proto_version(tlsContext->ctx_));
}

bool TLSContextServer::SetDefaultCa(TLSContextServer *tlsContext, const TLSConfiguration &configuration)
{
#ifdef HAS_NETMANAGER_BASE
    auto hostname = CommonUtils::GetHostnameFromURL(configuration.GetNetAddress().GetAddress());
    // customize trusted CAs.
    std::vector<std::string> cert_paths;

    if (NetManagerStandard::NetworkSecurityConfig::GetInstance().
        GetTrustAnchorsForHostName(hostname, cert_paths) != 0) {
        NETSTACK_LOGE("get customize trusted CAs failed");
        return false;
    }
    for (const auto &path : cert_paths) {
        if (!X509_STORE_load_path(SSL_CTX_get_cert_store(tlsContext->ctx_), path.c_str())) {
            NETSTACK_LOGE("load customize certificates failed");
            return false;
        }
    }
#endif // HAS_NETMANAGER_BASE

    if (access(ROOT_CERT_PATH.c_str(), F_OK | R_OK) == 0) {
        NETSTACK_LOGD("root CA certificates folder exist and can read");
        if (!X509_STORE_load_path(SSL_CTX_get_cert_store(tlsContext->ctx_), ROOT_CERT_PATH.c_str())) {
            NETSTACK_LOGE("load root certificates failed");
            return false;
        }
    } else {
        NETSTACK_LOGD("root CA certificates folder not exist or can not read");
    }
    std::string userCertPath = BASE_PATH + std::to_string(getuid() / UID_TRANSFORM_DIVISOR);
    if (access(userCertPath.c_str(), F_OK | R_OK) == 0) {
        NETSTACK_LOGD("user CA certificates folder exist and can read");
        if (!X509_STORE_load_path(SSL_CTX_get_cert_store(tlsContext->ctx_), userCertPath.c_str())) {
            NETSTACK_LOGE("load user certificates failed");
            return false;
        }
    } else {
        NETSTACK_LOGD("user CA certificates folder not exist or can not read");
    }
    if (!X509_STORE_load_path(SSL_CTX_get_cert_store(tlsContext->ctx_), SYSTEM_REPLACE_CA_PATH.c_str())) {
        NETSTACK_LOGE("load system replace certificates failed");
        return false;
    }
    return true;
}

bool TLSContextServer::SetCaAndVerify(TLSContextServer *tlsContext, const TLSConfiguration &configuration)
{
    NETSTACK_LOGI("SetCaAndVerify  ");

    if (!tlsContext) {
        NETSTACK_LOGE("tlsContext is null");
        return false;
    }

    if (configuration.GetCaCertificate().empty()) {
        return SetDefaultCa(tlsContext, configuration);
    } else {
        for (const auto &cert : configuration.GetCaCertificate()) {
            TLSCertificate ca(cert, CA_CERT);
            if (!X509_STORE_add_cert(SSL_CTX_get_cert_store(tlsContext->ctx_), static_cast<X509 *>(ca.handle()))) {
                NETSTACK_LOGE("Failed to add x509 cert");
                return false;
            }
        }
    }

    NETSTACK_LOGI("SetCaAndVerify  ok");
    return true;
}

bool TLSContextServer::SetLocalCertificate(TLSContextServer *tlsContext, const TLSConfiguration &configuration)
{
    if (!tlsContext) {
        NETSTACK_LOGE("tlsContext is null");
        return false;
    }
        
    const auto& certificate = configuration.GetLocalCertificate();
    if (certificate.empty()) {
        NETSTACK_LOGE("Certificate list is empty");
        return false;
    }

    if (!SSL_CTX_use_certificate(tlsContext->ctx_, static_cast<X509 *>(certificate.front().handle()))) {
        NETSTACK_LOGE("Failed to set main certificate");
        return false;
    }

    for (uint32_t i = 1; i < certificate.size(); ++i) {
        if (!SSL_CTX_add_extra_chain_cert(tlsContext->ctx_, static_cast<X509 *>(certificate[i].handle()))) {
            NETSTACK_LOGE("Failed to add chain certificate");
            return false;
        }
    }

    return true;
}

bool TLSContextServer::SetKeyAndCheck(TLSContextServer *tlsContext, const TLSConfiguration &configuration)
{
    if (!tlsContext) {
        NETSTACK_LOGE("The parameter tlsContext is null");
        return false;
    }
    if (configuration.GetPrivateKey().Algorithm() == OPAQUE) {
        tlsContext->pkey_ = reinterpret_cast<EVP_PKEY *>(configuration.GetPrivateKey().handle());
    } else {
        tlsContext->pkey_ = EVP_PKEY_new();
        if (configuration.GetPrivateKey().Algorithm() == ALGORITHM_RSA) {
            EVP_PKEY_set1_RSA(tlsContext->pkey_, reinterpret_cast<RSA *>(configuration.GetPrivateKey().handle()));
        } else if (tlsContext->tlsConfiguration_.GetPrivateKey().Algorithm() == ALGORITHM_DSA) {
            EVP_PKEY_set1_DSA(tlsContext->pkey_, reinterpret_cast<DSA *>(configuration.GetPrivateKey().handle()));
        }
    }

    if (configuration.GetPrivateKey().Algorithm() == OPAQUE) {
        tlsContext->pkey_ = nullptr;
    }
    auto pkey_ = tlsContext->pkey_;
    if (!SSL_CTX_use_PrivateKey(tlsContext->ctx_, pkey_)) {
        NETSTACK_LOGE("SSL_CTX_use_PrivateKey is error");
        return false;
    }

    if (!configuration.GetPrivateKey().GetKeyPass().Length()) {
        SSL_CTX_set_default_passwd_cb_userdata(tlsContext->ctx_,
                                               reinterpret_cast<void *>(const_cast<char *>(
                                                   tlsContext->tlsConfiguration_.GetPrivateKey().GetKeyPass().Data())));
    }
    // Check if the certificate matches the private key.
    if (!SSL_CTX_check_private_key(tlsContext->ctx_)) {
        NETSTACK_LOGE("Check if the certificate matches the private key is error");
        return false;
    }
    return true;
}

void TLSContextServer::SetVerify(TLSContextServer *tlsContext)
{
    if (!tlsContext) {
        NETSTACK_LOGE("tlsContext is null");
        return;
    }

    if (!tlsContext->tlsConfiguration_.GetCertificate().data.Length() ||
        !tlsContext->tlsConfiguration_.GetPrivateKey().GetKeyData().Length() ||
        tlsContext->tlsConfiguration_.GetVerifyMode() == ONE_WAY_MODE) {
        SSL_CTX_set_verify(tlsContext->ctx_, SSL_VERIFY_NONE, nullptr);
        verifyMode_ = ONE_WAY_MODE;
    } else {
        verifyMode_ = TWO_WAY_MODE;
        SSL_CTX_set_verify(tlsContext->ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    }

    NETSTACK_LOGD("Authentication mode is %{public}s",
                  verifyMode_ ? "two-way authentication" : "one-way authentication");
}

bool TLSContextServer::InitTlsContext(TLSContextServer *tlsContext, const TLSConfiguration &configuration)
{
    if (!tlsContext) {
        NETSTACK_LOGE("tlsContext is null");
        return false;
    }
    InitEnvServer();
    tlsContext->tlsConfiguration_ = configuration;
    tlsContext->ctx_ = SSL_CTX_new(TLS_server_method());
    if (tlsContext->ctx_ == nullptr) {
        NETSTACK_LOGE("ctx is nullptr");
        return false;
    }
    if (!configuration.GetCipherSuite().empty()) {
        if (!SetCipherList(tlsContext, configuration)) {
            NETSTACK_LOGE("Failed to set cipher suite");
            return false;
        }
    }
    if (!configuration.GetSignatureAlgorithms().empty()) {
        if (!SetSignatureAlgorithms(tlsContext, configuration)) {
            NETSTACK_LOGE("Failed to set signature algorithms");
            return false;
        }
    }
    GetCiphers(tlsContext);
    UseRemoteCipher(tlsContext);
    SetMinAndMaxProtocol(tlsContext);
    SetVerify(tlsContext);
    if (!SetCaAndVerify(tlsContext, configuration)) {
        return false;
    }
    if (!SetLocalCertificate(tlsContext, configuration)) {
        return false;
    }
    if (!SetKeyAndCheck(tlsContext, configuration)) {
        return false;
    }
    return true;
}
SSL *TLSContextServer::CreateSsl()
{
    ctxSsl_ = SSL_new(ctx_);
    return ctxSsl_;
}

void TLSContextServer::CloseCtx()
{
    SSL_CTX_free(ctx_);
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
