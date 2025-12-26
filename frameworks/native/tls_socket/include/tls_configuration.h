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

#ifndef COMMUNICATION_NETSTACK_TLS_CONFIGURATION_H
#define COMMUNICATION_NETSTACK_TLS_CONFIGURATION_H

#include <memory>
#include <string>
#include <vector>
#include <shared_mutex>

#include "tls.h"
#include "tls_certificate.h"
#include "tls_key.h"
#include "net_address.h"
namespace OHOS {
namespace NetStack {
namespace TlsSocket {
class TLSConfiguration {
public:
    TLSConfiguration() = default;
    explicit TLSConfiguration(TLSConfiguration *tlsConfiguration);
    ~TLSConfiguration() = default;
    TLSConfiguration(const TLSConfiguration &other);
    TLSConfiguration &operator=(const TLSConfiguration &other);

    void SetLocalCertificate(const TLSCertificate &certificate);
    void SetLocalCertificate(const std::vector<std::string> &certificate);
    [[nodiscard]] std::vector<TLSCertificate> GetLocalCertificate() const;

    void SetCaCertificate(const TLSCertificate &certificate);
    void SetCaCertificate(const std::vector<std::string> &certificate);
    [[nodiscard]] std::vector<std::string> GetCaCertificate() const;

    [[nodiscard]] const TLSKey &PrivateKey() const;
    void SetPrivateKey(const TLSKey &key);
    void SetPrivateKey(const SecureData &key, const SecureData &keyPass);
    [[nodiscard]] TLSKey GetPrivateKey() const;

    void SetProtocol(const std::string &Protocol);
    void SetProtocol(const std::vector<std::string> &Protocol);
    [[nodiscard]] TLSProtocol GetMinProtocol() const;
    [[nodiscard]] TLSProtocol GetMaxProtocol() const;
    [[nodiscard]] TLSProtocol GetProtocol() const;

    void SetUseRemoteCipherPrefer(bool useRemoteCipherPrefer);
    [[nodiscard]] bool GetUseRemoteCipherPrefer() const;

    void SetCipherSuite(const std::string &cipherSuite);
    [[nodiscard]] std::string GetCipherSuite() const;

    [[nodiscard]] const X509CertRawData &GetCertificate() const;
    void SetSignatureAlgorithms(const std::string &signatureAlgorithms);
    [[nodiscard]] const std::string &GetSignatureAlgorithms() const;
    [[nodiscard]] std::vector<CipherSuite> GetCipherSuiteVec() const;

    void SetVerifyMode(VerifyMode verifyMode);
    [[nodiscard]] VerifyMode GetVerifyMode() const;

    void SetNetAddress(const Socket::NetAddress& address);
    [[nodiscard]] Socket::NetAddress GetNetAddress() const;

    void SetSkipFlag(bool whetherToSkip);
    [[nodiscard]] bool GetSkipFlag() const;

private:
    TLSProtocol minProtocol_ = TLS_V1_2;
    TLSProtocol maxProtocol_ = TLS_V1_3;
    TLSProtocol protocol_ = TLS_V1_3;

    std::string cipherSuite_;
    std::string signatureAlgorithms_;
    std::string localCertString_;

    bool useRemoteCipherPrefer_ = false;

    std::vector<CipherSuite> cipherSuiteVec_;

    TLSKey privateKey_;
    TLSCertificate localCertificate_;
    TLSCertificate caCertificate_;
    std::vector<TLSCertificate> localCertificateChain_;
    std::vector<std::string> caCertificateChain_;
    VerifyMode tlsVerifyMode_;
    Socket::NetAddress netAddress_;
    bool whetherToSkip_ = false;
    mutable std::shared_mutex certMutex_;
};
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
#endif // COMMUNICATION_NETSTACK_TLS_CONFIGURATION_H
