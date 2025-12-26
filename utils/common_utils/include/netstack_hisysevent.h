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

#ifndef NETSTACK_INCLUDE_HISYSEVENT_H
#define NETSTACK_INCLUDE_HISYSEVENT_H

#include <string>
#include <map>
#include <mutex>
#include <queue>

namespace OHOS::NetStack {

struct EventInfo {
    std::string packageName;
    double totalTime;
    double totalRate;
    double totalDnsTime;
    double totalTlsTime;
    double totalTcpTime;
    double totalFirstRecvTime;
    uint32_t successCount;
    uint32_t totalCount;
    std::string version;
};

struct HttpPerfInfo {
    double totalTime = 0.0;
    double dnsTime = 0.0;
    double tlsTime = 0.0;
    double firstRecvTime = 0.0;
    double tcpTime = 0.0;
    int64_t size = 0;
    int64_t responseCode = 0;
    std::string version = "";
    int ipType = 0;
    int64_t osErr = 0;
    int32_t errCode = 0;
public:
    bool IsSuccess() const;
    bool IsError() const;
};

class EventReport {
public:
    void ProcessHttpPerfHiSysevent(const HttpPerfInfo &httpPerfInfo);
    void SendHttpPerfEvent(const EventInfo &eventInfo);
    static EventReport &GetInstance();
    bool IsValid();

private:
    EventReport();
    ~EventReport() = default;
    EventReport(const EventReport &eventReport) = delete;
    const EventReport &operator=(const EventReport &eventReport) = delete;
    void InitPackageName();
    void ResetCounters();
    std::string GetPackageName();
    std::string MapToJsonString(const std::map<std::string, uint32_t> mapPara);
    void HandleHttpPerfEvents(const HttpPerfInfo &httpPerfInfo);
    void HandleHttpResponseErrorEvents(const HttpPerfInfo &httpPerfInfo);
    void SendHttpResponseErrorEvent(const std::deque<HttpPerfInfo> &httpPerfInfoQueue_,
                                    const std::chrono::steady_clock::time_point now);
    void ReportHiSysEventWrite(const std::deque<HttpPerfInfo> &httpPerfInfoQueue_);

private:
    time_t reportTime = 0;
    std::chrono::steady_clock::time_point httpReponseRecordTime_ = std::chrono::steady_clock::time_point::min();
    std::chrono::steady_clock::time_point hiviewReportFirstTime_ = std::chrono::steady_clock::time_point::min();
    int sendHttpNetStackEventCount_ = 0;
    uint32_t totalErrorCount_ = 0;
    std::string packageName_;
    EventInfo eventInfo;
    std::map<std::string, uint32_t> versionMap;
    std::deque<HttpPerfInfo> httpPerfInfoQueue_;
    bool validFlag = true;
    std::recursive_mutex mutex;
};
}
#endif