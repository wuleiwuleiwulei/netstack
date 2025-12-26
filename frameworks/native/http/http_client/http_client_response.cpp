/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <iostream>
#include <vector>
#include <algorithm>

#include "http_client_response.h"
#include "http_client_constant.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"

namespace OHOS {
namespace NetStack {
namespace HttpClient {

void HttpClientResponse::SetResponseCode(ResponseCode code)
{
    responseCode_ = code;
}

ResponseCode HttpClientResponse::GetResponseCode() const
{
    return responseCode_;
}

void HttpClientResponse::AppendHeader(const char *data, size_t length)
{
    rawHeader_.append(static_cast<const char *>(data), length);
}

const std::string &HttpClientResponse::GetHeader() const
{
    return rawHeader_;
}

void HttpClientResponse::ParseHeaders()
{
    std::vector<std::string> vec = CommonUtils::Split(rawHeader_, HttpConstant::HTTP_LINE_SEPARATOR);
    for (const auto &header : vec) {
        if (CommonUtils::Strip(header).empty()) {
            continue;
        }
        auto index = header.find(HttpConstant::HTTP_HEADER_SEPARATOR);
        if (index == std::string::npos) {
            headers_[CommonUtils::Strip(header)] = "";
            NETSTACK_LOGD("HEAD: %{public}s", CommonUtils::Strip(header).c_str());
            continue;
        }
        if (CommonUtils::ToLower(CommonUtils::Strip(header.substr(0, index))) ==
            HttpConstant::RESPONSE_KEY_SET_COOKIE) {
            setCookie_.push_back(CommonUtils::Strip(header.substr(index + 1)));
            continue;
        }
        headers_[CommonUtils::ToLower(CommonUtils::Strip(header.substr(0, index)))] =
            CommonUtils::Strip(header.substr(index + 1));
    }
}

const std::map<std::string, std::string> &HttpClientResponse::GetHeaders() const
{
    return headers_;
}

void HttpClientResponse::AppendCookies(const char *data, size_t length)
{
    cookies_.append(static_cast<const char *>(data), length);
}

const std::vector<std::string> &HttpClientResponse::GetsetCookie() const
{
    return setCookie_;
}

const std::string &HttpClientResponse::GetCookies() const
{
    return cookies_;
}

void HttpClientResponse::SetRequestTime(const std::string &time)
{
    requestTime_ = time;
}

const std::string &HttpClientResponse::GetRequestTime() const
{
    return requestTime_;
}

void HttpClientResponse::SetResponseTime(const std::string &time)
{
    responseTime_ = time;
}

const std::string &HttpClientResponse::GetResponseTime() const
{
    return responseTime_;
}

void HttpClientResponse::SetWarning(const std::string &val)
{
    headers_[WARNING] = val;
}

void HttpClientResponse::SetRawHeader(const std::string &header)
{
    rawHeader_ = header;
}

const std::string &HttpClientResponse::GetRawHeader() const
{
    return rawHeader_;
}

void HttpClientResponse::SetCookies(const std::string &cookies)
{
    cookies_ = cookies;
}

void HttpClientResponse::AppendResult(const void *data, size_t length)
{
    result_.append(static_cast<const char *>(data), length);
}

void HttpClientResponse::SetResult(const std::string &res)
{
    result_ = res;
}

void HttpClientResponse::SetNetAddress(NetAddress &netAddress)
{
    httpStatistics_.serverIpAddress = netAddress;
}
 
HttpStatistics HttpClientResponse::GetHttpStatistics() const
{
    return httpStatistics_;
}

const std::string &HttpClientResponse::GetResult() const
{
    return result_;
}

PerformanceInfo HttpClientResponse::GetPerformanceTiming() const
{
    return performanceInfo_;
}

void HttpClientResponse::SetExpectDataType(const HttpDataType &type)
{
    dataType_ = type;
}

HttpDataType HttpClientResponse::GetExpectDataType() const
{
    return dataType_;
}
} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS