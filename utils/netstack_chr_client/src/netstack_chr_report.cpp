/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <sstream>
#include "i_netstack_chr_client.h"
#include "netstack_chr_report.h"
#include "netstack_log.h"
#include "common_event_manager.h"

using namespace OHOS::NetStack::ChrClient;

static constexpr const char* REPORT_HTTP_EVENT_NAME = "custom.event.CHR_REPORT_HTTP";
static constexpr const std::int32_t CHR_UID = 1201;
static constexpr const int REPORT_TIME_LIMIT_MINUTE = 5;

static constexpr const int REPORT_CHR_RESULT_SUCCESS = 0;
static constexpr const int REPORT_CHR_RESULT_TIME_LIMIT_ERROR = 1;
static constexpr const int REPORT_CHR_RESULT_REPORT_FAIL = 2;

static std::map<int32_t, int32_t> ipTypeIgnores = {
    {AF_INET, 0}, // IPv4，value: 2
    {AF_INET6, 0} // IPv6，value: 10
};

static std::map<int32_t, std::chrono::system_clock::time_point> ipTypeLastReceiveTime = {
    {AF_INET, std::chrono::system_clock::time_point{}}, // IPv4
    {AF_INET6, std::chrono::system_clock::time_point{}} // IPv6
};

NetStackChrReport::NetStackChrReport()
{}

NetStackChrReport::~NetStackChrReport()
{}

int NetStackChrReport::ReportCommonEvent(DataTransChrStats chrStats)
{
#ifdef HTTP_STACK_NAME
    std::string stackName = HTTP_STACK_NAME;
#else
    std::string stackName = "undefine";
#endif
    std::lock_guard<std::mutex> lock(report_mutex_);
    int32_t ipType = chrStats.tcpInfo.ipType;
    auto currentTime = std::chrono::system_clock::now();
    auto timeDifference =
        std::chrono::duration_cast<std::chrono::minutes>(currentTime - ipTypeLastReceiveTime[ipType]);
    AAFwk::Want want;
    want.SetAction(REPORT_HTTP_EVENT_NAME);
    SetWantParam(want, chrStats);
    if (timeDifference.count() < REPORT_TIME_LIMIT_MINUTE) {
        ipTypeIgnores[ipType] += 1;
        NETSTACK_LOGE("Stack name: %{public}s, event report failed, iptype: %{public}d, ignores: %{public}d",
            stackName.c_str(), ipType, ipTypeIgnores[ipType]);
        return REPORT_CHR_RESULT_TIME_LIMIT_ERROR;
    }

    EventFwk::CommonEventData commonEventData;
    commonEventData.SetWant(want);
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberUid({CHR_UID});
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonEventData, publishInfo)) {
        NETSTACK_LOGE("Subscriber is nullptr, report to CHR failed.");
        return REPORT_CHR_RESULT_REPORT_FAIL;
    }
    NETSTACK_LOGI("Stack name: %{public}s, event report success iptype: %{public}d, %{public}d are ignores.",
        stackName.c_str(), ipType, ipTypeIgnores[ipType]);
    ipTypeLastReceiveTime[ipType] = currentTime;
    ipTypeIgnores[ipType] = 0;
    return REPORT_CHR_RESULT_SUCCESS;
}

void NetStackChrReport::SetWantParam(AAFwk::Want& want, DataTransChrStats chrStats)
{
    std::string httpInfoJsonStr;
    std::string tcpInfoJsonStr;
    SetHttpInfoJsonStr(chrStats.httpInfo, httpInfoJsonStr);
    SetTcpInfoJsonStr(chrStats.tcpInfo, tcpInfoJsonStr);

    want.SetParam("PROCESS_NAME", chrStats.processName);
    want.SetParam("DATA_TRANS_HTTP_INFO", httpInfoJsonStr);
    want.SetParam("DATA_TRANS_TCP_INFO", tcpInfoJsonStr);
    NETSTACK_LOGI("BUSSINESS_ISSUE_HTTP: {PROCESS_NAME: %{public}s, HTTP_INFO: %{public}s, TCP_INFO: %{public}s}",
        chrStats.processName.c_str(), httpInfoJsonStr.c_str(), tcpInfoJsonStr.c_str());
}

void NetStackChrReport::SetHttpInfoJsonStr(DataTransHttpInfo httpInfo, std::string& httpInfoJsonStr)
{
    std::stringstream ss;
    ss << "{\"uid\":" << httpInfo.uid
       << ",{\"response_code\":" << httpInfo.responseCode
       << ",{\"total_time\":" << httpInfo.totalTime
       << ",{\"namelookup_time\":" << httpInfo.nameLookUpTime
       << ",{\"connect_time\":" << httpInfo.connectTime
       << ",{\"pretransfer_time\":" << httpInfo.preTransferTime
       << ",{\"size_upload\":" << httpInfo.sizeUpload
       << ",{\"size_download\":" << httpInfo.sizeDownload
       << ",{\"speed_download\":" << httpInfo.speedDownload
       << ",{\"speed_upload\":" << httpInfo.speedUpload
       << ",{\"effective_method\":\"" << httpInfo.effectiveMethod
       << "\",{\"starttransfer_time\":" << httpInfo.startTransferTime
       << ",{\"content_type\":\"" << httpInfo.contentType
       << "\",{\"redirect_time\":" << httpInfo.redirectTime
       << ",{\"redirect_count\":" << httpInfo.redirectCount
       << ",{\"os_errno\":" << httpInfo.osError
       << ",{\"ssl_verifyresult\":" << httpInfo.sslVerifyResult
       << ",{\"appconnect_time\":" << httpInfo.appconnectTime
       << ",{\"retry_after\":" << httpInfo.uid
       << ",{\"proxy_error\":" << httpInfo.proxyError
       << ",{\"queue_time\":" << httpInfo.queueTime
       << ",{\"curl_code\":"<< httpInfo.curlCode
       << ",{\"request_start_time\":" << httpInfo.requestStartTime << "}";
    httpInfoJsonStr = ss.str();
}

void NetStackChrReport::SetTcpInfoJsonStr(DataTransTcpInfo tcpInfo, std::string& tcpInfoJsonStr)
{
    std::stringstream ss;
    ss << "{\"tcpi_unacked\":" << tcpInfo.unacked
       << ",{\"tcpi_last_data_sent\":" << tcpInfo.lastDataSent
       << ",{\"tcpi_last_ack_sent\":" << tcpInfo.lastAckSent
       << ",{\"tcpi_last_data_recv\":" << tcpInfo.lastDataRecv
       << ",{\"tcpi_last_ack_recv\":" << tcpInfo.lastAckRecv
       << ",{\"tcpi_rtt\":" << tcpInfo.rtt
       << ",{\"tcpi_rttvar\":" << tcpInfo.rttvar
       << ",\"ip_type\":" << tcpInfo.ipType
       << ",{\"tcpi_retransmits\":" << tcpInfo.retransmits
       << ",{\"tcpi_total_retrans\":" << tcpInfo.totalRetrans
       << ",{\"src_ip\":\"" << tcpInfo.srcIp
       << "\",{\"dst_ip\":\"" << tcpInfo.dstIp
       << "\",{\"src_port\":" << tcpInfo.srcPort
       << ",{\"dst_port\":" << tcpInfo.dstPort << "}";
    tcpInfoJsonStr = ss.str();
}