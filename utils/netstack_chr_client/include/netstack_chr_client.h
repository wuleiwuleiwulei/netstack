/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_NETSTACK_CHR_CLIENT_H
#define COMMUNICATIONNETSTACK_NETSTACK_CHR_CLIENT_H

#include <cstdint>
#include <string>
#include "curl/curl.h"
#include "netstack_chr_report.h"
#include "i_netstack_chr_client.h"

namespace OHOS::NetStack::ChrClient {

class NetStackChrClient {
public:
    static NetStackChrClient &GetInstance();
    void GetDfxInfoFromCurlHandleAndReport(CURL *handle, int32_t curlCode);

private:
    NetStackChrClient() = default;
    ~NetStackChrClient() = default;

    static int GetAddrFromSock(int sockfd, struct DataTransTcpInfo &httpTcpInfo);
    static int GetTcpInfoFromSock(const curl_socket_t sockfd, DataTransTcpInfo &httpTcpInfo);
    static void GetHttpInfoFromCurl(CURL *handle, DataTransHttpInfo &httpInfo);

    template <typename DataType>
    static DataType GetNumericAttributeFromCurl(CURL *handle, CURLINFO info);
    static std::string GetStringAttributeFromCurl(CURL *handle, CURLINFO info);
    static long GetRequestStartTime(curl_off_t totalTime);
    static int ShouldReportHttpAbnormalEvent(const DataTransHttpInfo &httpInfo);
    NetStackChrReport netstackChrReport_;
};

}  // namespace OHOS::NetStack::ChrClient

#endif  // COMMUNICATIONNETSTACK_NETSTACK_CHR_CLIENT_H