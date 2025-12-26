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


#include "i_network_message.h"

#include "netstack_common_utils.h"

namespace OHOS::NetStack {
namespace {
constexpr const size_t STATUS_LINE_SIZE = 3;
}

INetworkMessage::INetworkMessage(std::string requestId)
    : requestId_(std::move(requestId)),
      requestBeginTime_(0) {}

INetworkMessage::~INetworkMessage() = default;

void INetworkMessage::SetRequestBeginTime(uint64_t bootTime)
{
    requestBeginTime_ = bootTime;
}

#if HAS_NETMANAGER_BASE
uint32_t INetworkMessage::GetIpAddressFromCurlHandle(std::string &ip, CURL *handle)
{
    if (handle == nullptr) {
        return static_cast<uint32_t>(CURLE_FAILED_INIT);
    }
    char *tmp = nullptr;
    CURL_GET_INFO(handle, CURLINFO_PRIMARY_IP, &tmp);
    if (tmp != nullptr) {
        ip.append(tmp);
    }
    return static_cast<uint32_t>(CURLE_OK);
}

uint32_t INetworkMessage::GetEffectiveUrlFromCurlHandle(std::string &effectiveUrl, CURL *handle)
{
    if (handle == nullptr) {
        return static_cast<uint32_t>(CURLE_FAILED_INIT);
    }
    char *tmp = nullptr;
    CURL_GET_INFO(handle, CURLINFO_EFFECTIVE_URL, &tmp);
    if (tmp != nullptr) {
        effectiveUrl.append(tmp);
    }
    return static_cast<uint32_t>(CURLE_OK);
}

uint32_t INetworkMessage::GetHttpVersionFromCurlHandle(std::string &httpVersion, CURL *handle)
{
    if (handle == nullptr) {
        return static_cast<uint32_t>(CURLE_FAILED_INIT);
    }
    long tmp = CURL_HTTP_VERSION_1_1;
    CURL_GET_INFO(handle, CURLINFO_HTTP_VERSION, &tmp);
    httpVersion = GetHttpVersion(tmp);
    return static_cast<uint32_t>(CURLE_OK);
}

uint32_t INetworkMessage::GetTimeInfoFromCurlHandle(TimeInfo &timeInfo, CURL *handle)
{
    if (handle == nullptr) {
        return static_cast<uint32_t>(CURLE_FAILED_INIT);
    }
    curl_off_t dnsTime = 0;
    CURL_GET_TIME_INFO(handle, CURLINFO_NAMELOOKUP_TIME_T, dnsTime, timeInfo);
    curl_off_t tcpConnectTime = 0;
    CURL_GET_TIME_INFO(handle, CURLINFO_CONNECT_TIME_T, tcpConnectTime, timeInfo);
    curl_off_t tlsHandshakeTime = 0;
    CURL_GET_TIME_INFO(handle, CURLINFO_APPCONNECT_TIME_T, tlsHandshakeTime, timeInfo);
    curl_off_t firstSendTime = 0;
    CURL_GET_TIME_INFO(handle, CURLINFO_PRETRANSFER_TIME_T, firstSendTime, timeInfo);
    curl_off_t firstRecvTime = 0;
    CURL_GET_TIME_INFO(handle, CURLINFO_STARTTRANSFER_TIME_T, firstRecvTime, timeInfo);
    curl_off_t redirectTime = 0;
    CURL_GET_TIME_INFO(handle, CURLINFO_REDIRECT_TIME_T, redirectTime, timeInfo);
    curl_off_t totalTime = 0;
    CURL_GET_TIME_INFO(handle, CURLINFO_TOTAL_TIME_T, totalTime, timeInfo);
    return static_cast<uint32_t>(CURLE_OK);
}
#endif

std::string INetworkMessage::GetReasonParse(const std::string &rawHeader)
{
    std::vector<std::string> vec = CommonUtils::Split(rawHeader, "\r\n");
    if (vec.empty()) {
        return {};
    }
    std::vector<std::string> resVec;
    for (const auto &s: vec) {
        if (s.find(":") != std::string::npos) {
            continue;
        }
        auto temp = CommonUtils::Split(s, " ");
        if (temp.size() < STATUS_LINE_SIZE) {
            continue;
        }
        if (temp.size() == STATUS_LINE_SIZE) {
            resVec.emplace_back(temp[STATUS_LINE_SIZE - 1]);
        }
        std::string res;
        for (size_t i = STATUS_LINE_SIZE - 1; i < temp.size(); ++i) {
            res += temp[i] + " ";
        }
        if (!res.empty()) {
            res.pop_back();
        }
        resVec.emplace_back(res);
    }
    if (resVec.empty()) {
        return {};
    }
    return *(resVec.end() - 1);
}

std::string INetworkMessage::GetRawHeader(const std::map<std::string, std::string> &headers)
{
    std::string result;
    std::for_each(headers.begin(), headers.end(), [&result](const auto &item) {
        result += item.first + ":" + item.second + "\r\n";
    });
    return result;
}

std::string INetworkMessage::GetHttpVersion(long httpVersion)
{
#if HAS_NETMANAGER_BASE
    switch (httpVersion) {
        case CURL_HTTP_VERSION_1_0:
            return "1.0";
        case CURL_HTTP_VERSION_1_1:
            return "1.1";
        case CURL_HTTP_VERSION_2:
            return "2";
        case CURL_HTTP_VERSION_3:
            return "3";
        default:
            break;
    }
#endif
    return "unknown";
}
}