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

#ifndef COMMUNICATIONNETSTACK_HTTP_CLIENT_REQUEST_H
#define COMMUNICATIONNETSTACK_HTTP_CLIENT_REQUEST_H

#include <string>
#include <map>
#include <vector>
#include "http_client_secure_data.h"
#include "http_client_tls_config.h"
#include "common.h"

namespace OHOS {
namespace NetStack {
namespace HttpClient {
static constexpr const int64_t MIN_RESUM_NUMBER = 1;
static constexpr const int64_t MAX_RESUM_NUMBER = 4294967296;
enum HttpProxyType {
    NOT_USE,
    USE_SPECIFIED,
    PROXY_TYPE_MAX,
};

enum HttpProtocol {
    HTTP_NONE, // default choose by curl
    HTTP1_1,
    HTTP2,
    HTTP3,
    HTTP_PROTOCOL_MAX,
};

struct HttpProxy {
    std::string host;
    int32_t port;
    std::string exclusions;
    bool tunnel;

    HttpProxy() : host(""), port(0), exclusions(""), tunnel(false) {}
};

struct HttpClientCert {
    std::string certPath;
    std::string certType;
    std::string keyPath;
    std::string keyPassword;
};

enum SslType {
    TLS,
    TLCP
};

struct EscapedData {
    HttpDataType dataType;
    // If the type is object or arrayBuffer, the data format is required to be JSON.
    std::string data;
};

struct HttpMultiFormData {
    HttpMultiFormData() = default;
    ~HttpMultiFormData() = default;
    std::string name;
    std::string contentType;
    std::string remoteFileName;
    std::string data;
    std::string filePath;
};

enum class HttpAuthenticationType {
    AUTO,
    BASIC,
    NTLM,
    DIGEST,
};

struct HttpCredential {
    HttpClient::SecureData username;
    HttpClient::SecureData password;
};

struct HttpServerAuthentication {
    HttpCredential credential;
    HttpAuthenticationType authenticationType = HttpAuthenticationType::AUTO;
};

struct TlsOption {
    std::unordered_set<CipherSuite> cipherSuite;
    TlsVersion tlsVersionMin = TlsVersion::DEFAULT;
    TlsVersion tlsVersionMax = TlsVersion::DEFAULT;
};

struct CertsPath {
    CertsPath() = default;
    ~CertsPath() = default;
    std::vector<std::string> certPathList;
    std::string certFile;
};

class HttpClientRequest {
public:
    /**
     * Default constructor for HttpClientRequest.
     */
    HttpClientRequest();

    /**
     * Set the URL for the HTTP request.
     * @param url The URL to be set.
     */
    void SetURL(const std::string &url);

    /**
     * Set the method for the HTTP request.
     * @param method The method to be set.
     */
    void SetMethod(const std::string &method);

    /**
     * Set the body data for the HTTP request.
     * @param data Pointer to the data.
     * @param length Length of the data.
     */
    void SetBody(const void *data, size_t length);

    /**
     * Set a header field for the HTTP request.
     * @param key The header field key.
     * @param val The header field value.
     */
    void SetHeader(const std::string &key, const std::string &val);

    /**
     * Set the timeout for the HTTP request.
     * @param timeout The timeout value in seconds.
     */
    void SetTimeout(unsigned int timeout);

    /**
     * Set the connect timeout for the HTTP request.
     * @param timeout The connect timeout value in seconds.
     */
    void SetConnectTimeout(unsigned int timeout);

    /**
     * Set the HTTP protocol for the request.
     * @param protocol The HTTP protocol to be set.
     */
    void SetHttpProtocol(HttpProtocol protocol);

    /**
     * Set the HTTP proxy for the request.
     * @param proxy The HTTP proxy to be set.
     */
    void SetHttpProxy(const HttpProxy &proxy);

    /**
     * Set max limit data for the request.
     * @param maxLimit The HTTP max limit data to be set.
     */
    void SetMaxLimit(uint32_t maxLimit);

    /**
     * Set the HTTP proxy type for the request.
     * @param type The HTTP proxy type to be set.
     */
    void SetHttpProxyType(HttpProxyType type);

    /**
     * Set the CA certificate path for the HTTPS request.
     * @param path The CA certificate path to be set.
     */
    void SetCaPath(const std::string &path);

    /**
     * Set the priority for the HTTP request.
     * @param priority The priority value to be set.
     */
    void SetPriority(unsigned int priority);

    /**
     * Set the download start position. Only used in GET method.
     * @param resumeFrom The resumeFrom value to be set.
     */
    void SetResumeFrom(int64_t resumeFrom);

    /**
     * Set the download end position. Only used in GET method.
     * @param resumeTo The resumeTo value to be set.
     */
    void SetResumeTo(int64_t resumeTo);

    /**
     * Set the ClientCert for the HTTP request.
     * @param clientCert The clientCert value to be set.
     */
    void SetClientCert(const HttpClientCert &clientCert);

    /**
     * Set the AddressFamily for the HTTP request.
     * @param addressFamily The addressFamily value to be set.
     */
    void SetAddressFamily(const std::string &addressFamily);

    /**
     * Set the UsingCache for the HTTP request.
     * @param UsingCache The UsingCache value to be set.
     */
    void SetUsingCache(bool usingCache);

    /**
     * Set the DNSOverHttps for the HTTP request.
     * @param DNSOverHttps The DNSOverHttps value to be set.
     */
    void SetDNSOverHttps(const std::string &dnsOverHttps);

    /**
     * Set the canCertVerify for the HTTP request.
     * @param CanCertVerify The CanCertVerify value to be set.
     */
    void SetCanSkipCertVerifyFlag(bool canCertVerify);

    /**
     * Set the RemoteValidation for the HTTP request.
     * @param RemoteValidation The RemoteValidation value to be set.
     */
    void SetRemoteValidation(const std::string &remoteValidation);

    /**
     * Set the TLSOptions for the HTTP request.
     * @param TLSOptions The TLSOptions value to be set.
     */
    void SetTLSOptions(const TlsOption &tlsOptions);

    /**
     * Set the CertsPath for the HTTP request.
     * @param certPathList, certFile The cert info to be set.
     */
    void SetCertsPath(std::vector<std::string> &&certPathList, const std::string &certFile);

    /**
     * Set the ExtraData for the HTTP request.
     * @param ExtraData The ExtraData value to be set.
     */
    void SetExtraData(const EscapedData& extraData);

    /**
     * Set the ExpectDataType for the HTTP request.
     * @param ExpectDataType The ExpectDataType value to be set.
     */
    void SetExpectDataType(HttpDataType dataType);

    /**
     * Set the DNSServers for the HTTP request.
     * @param DNSServers The DNSServers value to be set.
     */
    void SetDNSServers(const std::vector<std::string>& dnsServers);

    /**
     * Add a HttpMultiFormData to the list for the HTTP request.
     * @param HttpMultiFormData The HttpMultiFormData value to be set.
     */
    void AddMultiFormData(const HttpMultiFormData& data);

    /**
     * Set the HttpServerAuthentication for the HTTP request.
     * @param HttpServerAuthentication The HttpServerAuthentication value to be set.
     */
    void SetServerAuthentication(const HttpServerAuthentication& server_auth);

    /**
     * Get the URL of the HTTP request.
     * @return The URL of the request.
     */
    [[nodiscard]] const std::string &GetURL() const;

    /**
     * Get the method of the HTTP request.
     * @return The method of the request.
     */
    [[nodiscard]] const std::string &GetMethod() const;

    /**
     * Get the body data of the HTTP request.
     * @return The body data of the request.
     */
    [[nodiscard]] const std::string &GetBody() const;

    /**
     * Get the header fields of the HTTP request.
     * @return A map of header field key-value pairs.
     */
    [[nodiscard]] const std::map<std::string, std::string> &GetHeaders() const;

    /**
     * Get the timeout of the HTTP request.
     * @return The timeout value in seconds.
     */
    [[nodiscard]] unsigned int GetTimeout();

    /**
     * Get the connect timeout of the HTTP request.
     * @return The connect timeout value in seconds.
     */
    [[nodiscard]] unsigned int GetConnectTimeout();

    /**
     * Get the HTTP protocol of the request.
     * @return The HTTP protocol of the request.
     */
    [[nodiscard]] HttpProtocol GetHttpProtocol();

    /**
     * Get the HTTP proxy of the request.
     * @return The HTTP proxy of the request.
     */
    [[nodiscard]] const HttpProxy &GetHttpProxy() const;

    /**
     * Get the dns servers of the request.
     * @return The max limit data of the request.
     */
    [[nodiscard]] uint32_t GetMaxLimit() const;

    /**
     * Get the HTTP proxy type of the request.
     * @return The HTTP proxy type of the request.
     */
    [[nodiscard]] HttpProxyType GetHttpProxyType();

    /**
     * Get the CA certificate path of the HTTPS request.
     * @return The CA certificate path of the request.
     */
    [[nodiscard]] const std::string &GetCaPath();

    /**
     * Get the priority of the HTTP request.
     * @return The priority value of the request.
     */
    [[nodiscard]] uint32_t GetPriority() const;

    /**
     * Get the download start position of the HTTP request.
     * @return The download start position of the request.
     */
    [[nodiscard]] int64_t GetResumeFrom() const;

    /**
     * Get the download end position of the HTTP request.
     * @return The end start position of the request.
     */
    [[nodiscard]] int64_t GetResumeTo() const;

    /**
     * Get the ClientCert for the HTTP request.
     * @param clientCert The clientCert value to be set.
     */
    [[nodiscard]] const HttpClientCert &GetClientCert() const;

     /**
     * Get the addressFamily of the HTTP request.
     * @return The addressFamily of the request.
     */
    [[nodiscard]] const std::string &GetAddressFamily() const;

    /**
     * Get the UsingCache of the HTTP request.
     * @return The UsingCache of the request.
     */
    [[nodiscard]] bool GetUsingCache() const;

    /**
     * Get the DNSOverHttps of the HTTP request.
     * @return The DNSOverHttps of the request.
     */
    [[nodiscard]] const std::string& GetDNSOverHttps() const;

    /**
     * Get the CanSkipCertVerifyFlag of the HTTP request.
     * @return The CanSkipCertVerifyFlag of the request.
     */
    [[nodiscard]] bool GetCanSkipCertVerifyFlag() const;

    /**
     * Get the RemoteValidation of the HTTP request.
     * @return The RemoteValidation of the request.
     */
    [[nodiscard]] const std::string& GetRemoteValidation() const;

    /**
     * Get the TLSOptions of the HTTP request.
     * @return The TLSOptions of the request.
     */
    [[nodiscard]] const TlsOption& GetTLSOptions() const;

    /**
     * Get the CertsPath of the HTTP request.
     * @return The CertsPath of the request.
     */
    [[nodiscard]] const CertsPath &GetCertsPath();

    /**
     * Get the ExtraData of the HTTP request.
     * @return The ExtraData of the request.
     */
    [[nodiscard]] const EscapedData& GetExtraData() const;

    /**
     * Get the ExpectDataType of the HTTP request.
     * @return The ExpectDataType of the request.
     */
    [[nodiscard]] HttpDataType GetExpectDataType() const;

    /**
     * Get the DNSServers of the HTTP request.
     * @return The DNSServers of the request.
     */
    [[nodiscard]] const std::vector<std::string>& GetDNSServers() const;

    /**
     * Get the MultiFormDataList of the HTTP request.
     * @return The MultiFormDataList of the request.
     */
    [[nodiscard]] const std::vector<HttpMultiFormData>& GetMultiFormDataList() const;

    /**
     * Get the ServerAuthentication of the HTTP request.
     * @return The ServerAuthentication of the request.
     */
    [[nodiscard]] const HttpServerAuthentication& GetServerAuthentication() const;

    /**
     * Check if the specified method is suitable for a GET request.
     * @param method The method to check.
     * @return True if the method is suitable for a GET request, false otherwise.
     */
    bool MethodForGet(const std::string &method);

    /**
     * Check if the specified method is suitable for a POST request.
     * @param method The method to check.
     * @return True if the method is suitable for a POST request, false otherwise.
     */
    bool MethodForPost(const std::string &method);

    /**
     * Sets the request time for the object.
     * @param time The request time to be set.
     */
    void SetRequestTime(const std::string &time);

    /**
     * Retrieves the request time from the object.
     * @return The request time.
     */
    const std::string &GetRequestTime() const;
    
    /**
     * Set the sslType for the HTTP request.
     * @param sslType The sslType value to be set.
     */
    void SetSslType(SslType sslType);

    /**
     * Retrieves the request time from the object.
     * @return The SslType of the request.
     */
    const SslType &GetSslType() const;

    /**
     * Set the clientEncCert for the HTTP request.
     * @param clientEncCert The clientEncCert value to be set.
     */
    void SetClientEncCert(const HttpClientCert &clientEncCert);

    /**
     * Get the clientEncCert for the HTTP request.
     * @param clientEncCert The clientEncCert value to be set.
     */
    [[nodiscard]] const HttpClientCert &GetClientEncCert() const;

    /**
     * Retrieves the request time from the object.
     * @return The request time.
     */
    uint32_t GetHttpVersion();

    /**
     * Set the Certificate pin the HTTP request.
     * @param certPIN The certPIN value to be set.
     */
    void SetCertificatePinning(const HttpClient::SecureData &certPIN);

    /**
     * Get the Certificate pin of the HTTP request.
     * @return The Certificate pin of the request.
     */
    const HttpClient::SecureData &GetCertificatePinning() const;
private:
    std::string url_;
    std::string method_;
    std::string body_;
    std::map<std::string, std::string> headers_;
    unsigned int timeout_;
    unsigned int connectTimeout_;
    HttpProtocol protocol_;
    HttpProxy proxy_;
    HttpProxyType proxyType_;
    std::string caPath_;
    CertsPath certsPath_;
    unsigned int priority_;
    std::string requestTime_;
    int64_t resumeFrom_;
    int64_t resumeTo_;
    HttpClientCert clientCert_;
    std::string addressFamily_;
    SslType sslType_;
    HttpClientCert clientEncCert_;
    uint32_t maxLimit_;
    bool usingCache_;
    std::string dnsOverHttps_;
    std::string remoteValidation_;
    bool canSkipCertVerify_ = false;
    TlsOption tlsOptions_;
    EscapedData extraData_;
    HttpDataType dataType_;
    std::vector<std::string> dnsServers_;
    std::vector<HttpMultiFormData> multiFormDataList_;
    HttpServerAuthentication serverAuth_;
    HttpClient::SecureData certificatePinning_;
};
} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATIONNETSTACK_HTTP_CLIENT_REQUEST_H
