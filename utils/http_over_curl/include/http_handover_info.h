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

#ifndef COMMUNICATIONNETSTACK_HTTP_HANDOVER_INFO_H
#define COMMUNICATIONNETSTACK_HTTP_HANDOVER_INFO_H
struct HttpHandoverStackInfo {
    unsigned int taskId = 0;
    uint32_t readTimeout = 0;
    uint32_t connectTimeout = 0;
    std::string method = "init";
    std::string requestUrl = "init";
    bool isInStream = false;
    bool isSuccess = false;
};

struct HttpHandoverInfo {
    uint32_t handOverId = 0;
    uint32_t handOverNum = 0;  // 0 means no handover or query failed.
    int32_t handOverReason = 0;
    uint64_t startTime = 0;
    double flowControlTime = 0.0;
    int32_t readFlag = 0;
    int32_t inQueueFlag = 0;
    bool isHistory = false;
};

enum HandoverRequestType {
    OLD,  // old request before network change
    INCOMING,  // new request during network change
    NETWORKERROR,  // old request of network error
    UNDONE  // undone old request after network change
};
#endif  // COMMUNICATIONNETSTACK_HTTP_HANDOVER_INFO_H