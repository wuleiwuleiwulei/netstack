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

#ifndef COMMUNICATIONNETSTACK_I_NETSTACK_CHR_CLIENT_H
#define COMMUNICATIONNETSTACK_I_NETSTACK_CHR_CLIENT_H

#include <cstdint>
#include <string>
#include "curl/curl.h"

namespace OHOS::NetStack::ChrClient {

typedef struct DataTransHttpInfo {
    int uid;
    long responseCode;
    curl_off_t totalTime;
    curl_off_t nameLookUpTime;
    curl_off_t connectTime;
    curl_off_t preTransferTime;
    curl_off_t sizeUpload;
    curl_off_t sizeDownload;
    curl_off_t speedDownload;
    curl_off_t speedUpload;
    std::string effectiveMethod;
    curl_off_t startTransferTime;
    std::string contentType;
    curl_off_t redirectTime;
    long redirectCount;
    long osError;
    long sslVerifyResult;
    curl_off_t appconnectTime;
    curl_off_t retryAfter;
    long proxyError;
    curl_off_t queueTime;
    long curlCode;
    long requestStartTime;
} DataTransHttpInfo;

typedef struct DataTransTcpInfo {
    uint32_t unacked;
    uint32_t lastDataSent;
    uint32_t lastAckSent;
    uint32_t lastDataRecv;
    uint32_t lastAckRecv;
    uint32_t rtt;
    uint32_t rttvar;
    uint16_t retransmits;
    uint32_t totalRetrans;
    int ipType;
    std::string srcIp;
    std::string dstIp;
    uint16_t srcPort;
    uint16_t dstPort;
} DataTransTcpInfo;

typedef struct DataTransChrStats {
    std::string processName;
    DataTransHttpInfo httpInfo;
    DataTransTcpInfo tcpInfo;
} DataTransChrStats;
}  // namespace OHOS::NetStack
#endif  // COMMUNICATIONNETSTACK_I_NETSTACK_CHR_CLIENT_H