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

#ifndef NETSTACK_I_NETWORK_MESSAGE_H
#define NETSTACK_I_NETWORK_MESSAGE_H

#include <map>

#if HAS_NETMANAGER_BASE
#include "curl/curl.h"
#endif
#include "tlv_utils.h"

namespace OHOS::NetStack {
#if HAS_NETMANAGER_BASE
#define CURL_GET_INFO(curl, options, ptr)                           \
    do {                                                            \
        auto code = curl_easy_getinfo((curl), (options), (ptr));    \
        if (code != CURLE_OK) {                                     \
            return static_cast<uint32_t>(code);                     \
        }                                                           \
    } while (false)                                                 \

#define CURL_GET_TIME_INFO(curl, options, time, timeInfo)           \
    do {                                                            \
        CURL_GET_INFO((curl), (options), &(time));                  \
        (timeInfo).time = static_cast<uint64_t>(time);              \
    } while (false)                                                 \

#endif

struct TimeInfo {
    double dnsTime = 0;
    double tcpConnectTime = 0;
    double tlsHandshakeTime = 0;
    double firstSendTime = 0;
    double firstRecvTime = 0;
    double redirectTime = 0;
    double totalTime = 0;
};

class INetworkMessage {
public:
    INetworkMessage() = default;
    explicit INetworkMessage(std::string requestId);
    virtual ~INetworkMessage();
    virtual DfxMessage Parse() = 0;
    void SetRequestBeginTime(uint64_t bootTime);

protected:
#if HAS_NETMANAGER_BASE
    static uint32_t GetIpAddressFromCurlHandle(std::string &ip, CURL *handle);
    static uint32_t GetEffectiveUrlFromCurlHandle(std::string &effectiveUrl, CURL *handle);
    static uint32_t GetHttpVersionFromCurlHandle(std::string &httpVersion, CURL *handle);
    static uint32_t GetTimeInfoFromCurlHandle(TimeInfo &timeInfo, CURL *handle);
#endif
    static std::string GetReasonParse(const std::string &rawHeader);
    static std::string GetRawHeader(const std::map<std::string, std::string> &headers);

private:
    static std::string GetHttpVersion(long httpVersion);

protected:
    std::string requestId_;
    uint64_t requestBeginTime_ = 0;
};
}

#endif //NETSTACK_I_NETWORK_MESSAGE_H
