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

#ifndef HTTP_ENTITY_NET_HTTP_REQUEST_H
#define HTTP_ENTITY_NET_HTTP_REQUEST_H

#include <map>
#include <string>
#include <vector>

#include "constant.h"
#include "net_http_utils.h"

namespace OHOS::NetStack::Http {

enum class HttpProtocol {
    HTTP1_1,
    HTTP2,
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

class HttpRequest final {
public:
    HttpRequest();

    void SetUrl(const std::string &url);

    void SetMethod(const std::string &method);

    void SetBody(const void *data, size_t length);

    void SetHeader(const std::string &key, const std::string &val);

    void SetReadTimeout(uint32_t readTimeout);

    void SetMaxLimit(uint32_t maxLimit);

    void SetConnectTimeout(uint32_t connectTimeout);

    void SetUsingProtocol(HttpProtocol httpProtocol);

    void SetHttpDataType(HttpDataType dataType);

    void SetUsingHttpProxyType(UsingHttpProxyType type);

    void SetSpecifiedHttpProxy(const std::string &host, int32_t port, const std::string &exclusionList);

    void SetCaPath(const std::string &path);

    void SetDnsServers(const std::vector<std::string> &dnsServers);

    void SetDohUrl(const std::string &dohUrl);

    void SetRangeNumber(int64_t resumeFromNumber, int64_t resumeToNumber);

    void SetClientCert(std::string &cert, std::string &certType, std::string &key, SecureChar &keyPasswd);

    void AddMultiFormData(const MultiFormData &multiFormData);

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

    void SetPriority(uint32_t priority);

    [[nodiscard]] uint32_t GetPriority() const;

    [[nodiscard]] UsingHttpProxyType GetUsingHttpProxyType() const;

    void GetSpecifiedHttpProxy(std::string &host, int32_t &port, std::string &exclusionList);

    [[nodiscard]] const std::string &GetCaPath() const;

    [[nodiscard]] const std::string &GetDohUrl() const;

    [[nodiscard]] std::string GetRangeString() const;

    [[nodiscard]] const std::vector<std::string> &GetDnsServers() const;

    void GetClientCert(std::string &cert, std::string &certType, std::string &key, SecureChar &keyPasswd);

    std::vector<MultiFormData> GetMultiPartDataList();
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

    UsingHttpProxyType usingHttpProxyType_;

    std::string httpProxyHost_;

    int32_t httpProxyPort_;

    std::string httpProxyExclusions_;

    std::string caPath_;

    std::string dohUrl_;

    std::vector<std::string> dnsServers_;

    int64_t resumeFromNumber_;

    int64_t resumeToNumber_;

    std::string cert_;

    std::string certType_;

    std::string key_;

    SecureChar keyPasswd_;

    std::vector<MultiFormData> multiFormDataList_;
};
} // namespace OHOS::NetStack::Http

#endif /* HTTP_ENTITY_NET_HTTP_REQUEST_H */
