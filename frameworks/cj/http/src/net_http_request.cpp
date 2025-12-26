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

#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "curl/curl.h"
#include "net_http_request.h"

namespace OHOS::NetStack::Http {

HttpRequest::HttpRequest()
    : method_(HTTP_METHOD_GET),
      readTimeout_(DEFAULT_READ_TIMEOUT),
      maxLimit_(DEFAULT_MAX_LIMIT),
      connectTimeout_(DEFAULT_CONNECT_TIMEOUT),
      usingProtocol_(HttpProtocol::HTTP_NONE),
      dataType_(HttpDataType::NO_DATA_TYPE),
      priority_(MIN_PRIORITY),
      usingHttpProxyType_(UsingHttpProxyType::USE_DEFAULT),
      httpProxyPort_(0),
      resumeFromNumber_(0),
      resumeToNumber_(0)
{}

void HttpRequest::SetUrl(const std::string &url)
{
    url_ = url;
}

void HttpRequest::SetMethod(const std::string &method)
{
    method_ = method;
}

void HttpRequest::SetBody(const void *data, size_t length)
{
    body_.append(static_cast<const char *>(data), length);
}

void HttpRequest::SetHeader(const std::string &key, const std::string &val)
{
    header_[key] = val;
}

void HttpRequest::SetReadTimeout(uint32_t readTimeout)
{
    readTimeout_ = readTimeout;
}

void HttpRequest::SetMaxLimit(uint32_t maxLimit)
{
    if (maxLimit > MAX_LIMIT) {
        NETSTACK_LOGI("maxLimit setting exceeds the maximum limit, use max limit");
        maxLimit_ = MAX_LIMIT;
        return;
    }
    maxLimit_ = maxLimit;
}

void HttpRequest::SetConnectTimeout(uint32_t connectTimeout)
{
    connectTimeout_ = connectTimeout;
}

const std::string &HttpRequest::GetUrl() const
{
    return url_;
}

const std::string &HttpRequest::GetMethod() const
{
    return method_;
}

const std::string &HttpRequest::GetBody() const
{
    return body_;
}

const std::map<std::string, std::string> &HttpRequest::GetHeader() const
{
    return header_;
}

uint32_t HttpRequest::GetReadTimeout() const
{
    return readTimeout_;
}

uint32_t HttpRequest::GetMaxLimit() const
{
    return maxLimit_;
}

uint32_t HttpRequest::GetConnectTimeout() const
{
    return connectTimeout_;
}

void HttpRequest::SetUsingProtocol(HttpProtocol httpProtocol)
{
    usingProtocol_ = httpProtocol;
}

uint32_t HttpRequest::GetHttpVersion() const
{
    if (usingProtocol_ == HttpProtocol::HTTP2) {
        NETSTACK_LOGI("CURL_HTTP_VERSION_2_0");
        return CURL_HTTP_VERSION_2_0;
    }
    if (usingProtocol_ == HttpProtocol::HTTP1_1) {
        NETSTACK_LOGI("CURL_HTTP_VERSION_1_1");
        return CURL_HTTP_VERSION_1_1;
    }
    return CURL_HTTP_VERSION_NONE;
}

void HttpRequest::SetRequestTime(const std::string &time)
{
    requestTime_ = time;
}

const std::string &HttpRequest::GetRequestTime() const
{
    return requestTime_;
}

void HttpRequest::SetHttpDataType(HttpDataType dataType)
{
    if (dataType != HttpDataType::STRING && dataType != HttpDataType::ARRAY_BUFFER &&
        dataType != HttpDataType::OBJECT) {
        return;
    }
    dataType_ = dataType;
}
HttpDataType HttpRequest::GetHttpDataType() const
{
    return dataType_;
}

void HttpRequest::SetPriority(uint32_t priority)
{
    if (priority < MIN_PRIORITY || priority > MAX_PRIORITY) {
        return;
    }
    priority_ = priority;
}

uint32_t HttpRequest::GetPriority() const
{
    return priority_;
}

void HttpRequest::SetUsingHttpProxyType(UsingHttpProxyType type)
{
    usingHttpProxyType_ = type;
}

UsingHttpProxyType HttpRequest::GetUsingHttpProxyType() const
{
    return usingHttpProxyType_;
}

void HttpRequest::SetSpecifiedHttpProxy(const std::string &host, int32_t port, const std::string &exclusionList)
{
    httpProxyHost_ = host;
    httpProxyPort_ = port;
    httpProxyExclusions_ = exclusionList;
}

void HttpRequest::GetSpecifiedHttpProxy(std::string &host, int32_t &port, std::string &exclusionList)
{
    host = httpProxyHost_;
    port = httpProxyPort_;
    exclusionList = httpProxyExclusions_;
}


void HttpRequest::SetClientCert(
    std::string &cert, std::string &certType, std::string &key, SecureChar &keyPasswd)
{
    cert_ = cert;
    certType_ = certType;
    key_ = key;
    keyPasswd_ = keyPasswd;
}

void HttpRequest::AddMultiFormData(const MultiFormData &multiFormData)
{
    multiFormDataList_.push_back(multiFormData);
}

void HttpRequest::GetClientCert(
    std::string &cert, std::string &certType, std::string &key, SecureChar &keyPasswd)
{
    cert = cert_;
    certType = certType_;
    key = key_;
    keyPasswd = keyPasswd_;
}

void HttpRequest::SetCaPath(const std::string &path)
{
    if (path.empty()) {
        return;
    }

    caPath_ = path;
}

const std::string &HttpRequest::GetCaPath() const
{
    return caPath_;
}


void HttpRequest::SetDohUrl(const std::string &dohUrl)
{
    if (dohUrl.empty()) {
        return;
    }
    dohUrl_ = dohUrl;
}

const std::string &HttpRequest::GetDohUrl() const
{
    return dohUrl_;
}

void HttpRequest::SetRangeNumber(int64_t resumeFromNumber, int64_t resumeToNumber)
{
    if (resumeFromNumber >= MIN_RESUM_NUMBER && resumeFromNumber <= MAX_RESUM_NUMBER) {
        resumeFromNumber_ = resumeFromNumber;
    }
    if (resumeToNumber >= MIN_RESUM_NUMBER && resumeToNumber <= MAX_RESUM_NUMBER) {
        resumeToNumber_ = resumeToNumber;
    }
}

std::string HttpRequest::GetRangeString() const
{
    bool isSetFrom = resumeFromNumber_ >= MIN_RESUM_NUMBER;
    bool isSetTo = resumeToNumber_ >= MIN_RESUM_NUMBER;
    if (!isSetTo && !isSetFrom) {
        return "";
    } else if (!isSetTo && isSetFrom) {
        return std::to_string(resumeFromNumber_) + '-';
    } else if (isSetTo && !isSetFrom) {
        return '-' + std::to_string(resumeToNumber_);
    } else if (resumeToNumber_ <= resumeFromNumber_) {
        return "";
    } else {
        return std::to_string(resumeFromNumber_) + '-' + std::to_string(resumeToNumber_);
    }
}

const std::vector<std::string> &HttpRequest::GetDnsServers() const
{
    return dnsServers_;
}

void HttpRequest::SetDnsServers(const std::vector<std::string> &dnsServers)
{
    dnsServers_ = dnsServers;
}

std::vector<MultiFormData> HttpRequest::GetMultiPartDataList()
{
    return multiFormDataList_;
}
} // namespace OHOS::NetStack::Http