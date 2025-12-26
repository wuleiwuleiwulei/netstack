/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_HTTP_REQUEST_OPTIONS_H
#define COMMUNICATIONNETSTACK_HTTP_REQUEST_OPTIONS_H

#include <map>
#include <string>
#include <vector>

#include "constant.h"
#include "secure_char.h"
#include "http_tls_config.h"
#include "napi_utils.h"

namespace OHOS::NetStack::Http {
enum class HttpProtocol {
    HTTP1_1,
    HTTP2,
    HTTP3,
    HTTP_NONE, // default choose by curl
};

enum class UsingHttpProxyType {
    NOT_USE,
    USE_DEFAULT,
    USE_SPECIFIED,
};

struct MultiFormData {
    MultiFormData() = default;
    ~MultiFormData() = default;
    std::string name;
    std::string contentType;
    std::string remoteFileName;
    std::string data;
    std::string filePath;
};

enum class HashAlgorithm {
    SHA256,
    INVALID,
};

enum class AuthenticationType {
    AUTO,
    BASIC,
    NTLM,
    DIGEST,
};

struct Credential {
    NapiUtils::SecureData username;
    NapiUtils::SecureData password;
};

struct ServerAuthentication {
    Credential credential;
    AuthenticationType authenticationType = AuthenticationType::AUTO;
};

struct TlsOption {
    std::unordered_set<CipherSuite> cipherSuite;
    TlsVersion tlsVersionMin = TlsVersion::DEFAULT;
    TlsVersion tlsVersionMax = TlsVersion::DEFAULT;
};

struct CertificatePinning {
    HashAlgorithm hashAlgorithm = HashAlgorithm::SHA256;
    std::string publicKeyHash;
};

enum class SslType {
    TLS,
    TLCP,
};

class HttpRequestOptions final {
public:
    HttpRequestOptions();

    // https://man7.org/linux/man-pages/man7/tcp.7.html
    struct TcpConfiguration {
        friend class HttpRequestOptions;
        /*
        TCP_KEEPIDLE (since Linux 2.4)
            The time (in seconds) the connection needs to remain idle
            before TCP starts sending keepalive probes, if the socket
            option SO_KEEPALIVE has been set on this socket.  This
            option should not be used in code intended to be portable.
        For example, if the server will send FIN packet after 60 seconds, we suggest that set <keepIdle> to 61.
        */
        int keepIdle_ = 60 * 5; // Default value according to <NetworkKit> Cloud Service.
        /*
        TCP_KEEPINTVL (since Linux 2.4)
            The time (in seconds) between individual keepalive probes.
            This option should not be used in code intended to be
            portable.
        <keepCnt> == 1 means that we just probe once, if it fails, we close the connection.
        */
        int keepCnt_ = 1;
        /*
        TCP_KEEPINTVL (since Linux 2.4)
            The time (in seconds) between individual keepalive probes.
            This option should not be used in code intended to be
            portable.
        */
        int keepInterval_ = 1;
        
        /*
        TCP_USER_TIMEOUT (since Linux 2.6.37)
            This option takes an unsigned int as an argument.  When
            the value is greater than 0, it specifies the maximum
            amount of time in milliseconds that transmitted data may
            remain unacknowledged, or buffered data may remain
            untransmitted (due to zero window size) before TCP will
            forcibly close the corresponding connection and return
            ETIMEDOUT to the application.  If the option value is
            specified as 0, TCP will use the system default.
    
            Increasing user timeouts allows a TCP connection to
            survive extended periods without end-to-end connectivity.
            Decreasing user timeouts allows applications to "fail
            fast", if so desired.  Otherwise, failure may take up to
            20 minutes with the current system defaults in a normal
            WAN environment.
    
            This option can be set during any state of a TCP
            connection, but is effective only during the synchronized
            states of a connection (ESTABLISHED, FIN-WAIT-1, FIN-
            WAIT-2, CLOSE-WAIT, CLOSING, and LAST-ACK).  Moreover,
            when used with the TCP keepalive (SO_KEEPALIVE) option,
            TCP_USER_TIMEOUT will override keepalive to determine when
            to close a connection due to keepalive failure.
    
            The option has no effect on when TCP retransmits a packet,
            nor when a keepalive probe is sent.
    
            This option, like many others, will be inherited by the
            socket returned by accept(2), if it was set on the
            listening socket.
    
            Further details on the user timeout feature can be found
            in RFC 793 and RFC 5482 ("TCP User Timeout Option").
        */
        int userTimeout_ = HttpConstant::DEFAULT_READ_TIMEOUT;
        
        bool SetOptionToSocket(int sock);
        void SetTcpUserTimeout(const uint32_t &timeout);
    };

    void SetUrl(const std::string &url);

    void SetMethod(const std::string &method);

    void SetBody(const void *data, size_t length);

    void ReplaceBody(const void *data, size_t length);

    void SetHeader(const std::string &key, const std::string &val);

    void SetReadTimeout(uint32_t readTimeout);

    void SetMaxLimit(uint32_t maxLimit);

    void SetConnectTimeout(uint32_t connectTimeout);

    void SetUsingProtocol(HttpProtocol httpProtocol);

    void SetHttpDataType(HttpDataType dataType);

    void SetUsingHttpProxyType(UsingHttpProxyType type);

    void SetSpecifiedHttpProxy(const std::string &host, int32_t port, const std::string &exclusionList,
        const NapiUtils::SecureData &userName, const NapiUtils::SecureData &password);

    void SetCaPath(const std::string &SetCaPath);

    void SetCaData(const std::string &caData);

    void SetDnsServers(const std::vector<std::string> &dnsServers);

    void SetDohUrl(const std::string &SetDohUrl);

    void SetRangeNumber(int64_t resumeFromNumber, int64_t resumeToNumber);

    void SetClientCert(std::string &cert, std::string &certType, std::string &key, Secure::SecureChar &keyPasswd);

    void AddMultiFormData(const MultiFormData &multiFormData);

    void SetTlsOption(const TlsOption &tlsOption);

    void SetServerAuthentication(const ServerAuthentication &serverAuthentication);

    void SetCertificatePinning(const NapiUtils::SecureData &certPIN);

    void SetCanSkipCertVerifyFlag(bool canCertVerify);

    [[nodiscard]] NapiUtils::SecureData GetCertificatePinning() const;

    [[nodiscard]] const std::string &GetUrl() const;

    [[nodiscard]] const std::string &GetMethod() const;

    [[nodiscard]] const std::string &GetBody() const;

    [[nodiscard]] const std::map<std::string, std::string> &GetHeader() const;

    [[nodiscard]] uint32_t GetReadTimeout() const;

    [[nodiscard]] uint32_t GetMaxLimit() const;

    [[nodiscard]] uint32_t GetConnectTimeout() const;

    [[nodiscard]] uint32_t GetHttpVersion() const;

    void SetRequestTime(const std::string &time);

    [[nodiscard]] const std::string &GetRequestTime() const;

    [[nodiscard]] HttpDataType GetHttpDataType() const;

    void SetMaxRedirects(uint32_t maxRedirects);

    [[nodiscard]] uint32_t GetMaxRedirects() const;

    void SetPriority(uint32_t priority);

    [[nodiscard]] uint32_t GetPriority() const;

    [[nodiscard]] UsingHttpProxyType GetUsingHttpProxyType() const;

    void GetSpecifiedHttpProxy(std::string &host, int32_t &port, std::string &exclusionList,
        NapiUtils::SecureData &username, NapiUtils::SecureData &password);

    [[nodiscard]] const std::string &GetCaPath() const;

    [[nodiscard]] const std::string &GetCaData() const;

    [[nodiscard]] const std::string &GetDohUrl() const;

    [[nodiscard]] std::string GetRangeString() const;

    [[nodiscard]] const std::vector<std::string> &GetDnsServers() const;

    [[nodiscard]] bool GetCanSkipCertVerifyFlag() const;

    void GetClientCert(std::string &cert, std::string &certType, std::string &key, Secure::SecureChar &keyPasswd);

    std::vector<MultiFormData> GetMultiPartDataList();

    [[nodiscard]] const TlsOption GetTlsOption() const;
    [[nodiscard]] const TcpConfiguration GetTCPOption() const;

    [[nodiscard]] const ServerAuthentication GetServerAuthentication() const;

    void SetAddressFamily(std::string addressFamily);

    [[nodiscard]] std::string GetAddressFamily() const;

    void SetSslType(SslType sslType);
    [[nodiscard]] SslType GetSslType() const;

    void SetClientEncCert(std::string &cert, std::string &certType, std::string &key, Secure::SecureChar &keyPasswd);
    void GetClientEncCert(std::string &cert, std::string &certType, std::string &key, Secure::SecureChar &keyPasswd);

private:
    std::string url_;

    std::string body_;

    std::string method_;

    std::map<std::string, std::string> header_;

    uint32_t readTimeout_;

    uint32_t maxLimit_;

    uint32_t connectTimeout_;

    HttpProtocol usingProtocol_;

    std::string requestTime_;

    HttpDataType dataType_;

    uint32_t priority_;

    uint32_t maxRedirects_;

    UsingHttpProxyType usingHttpProxyType_;

    std::string httpProxyHost_;

    int32_t httpProxyPort_;

    std::string httpProxyExclusions_;

    NapiUtils::SecureData httpProxyUsername_;

    NapiUtils::SecureData httpProxyPassword_;

    std::string caPath_;

    std::string caData_;

    std::string dohUrl_;

    std::vector<std::string> dnsServers_;

    int64_t resumeFromNumber_;

    int64_t resumeToNumber_;

    std::string cert_;

    std::string certType_;

    std::string key_;

    Secure::SecureChar keyPasswd_;

    bool canSkipCertVerify_ = false;

    std::vector<MultiFormData> multiFormDataList_;

    NapiUtils::SecureData certificatePinning_;

    TlsOption tlsOption_;

    ServerAuthentication serverAuthentication_;

    std::string addressFamily_;

    SslType sslTypeEnc_;
    std::string certEnc_;
    std::string certTypeEnc_;
    std::string keyEnc_;
    Secure::SecureChar keyPasswdEnc_;

    TcpConfiguration tcpOption_;
};
} // namespace OHOS::NetStack::Http

#endif /* COMMUNICATIONNETSTACK_HTTP_REQUEST_OPTIONS_H */
