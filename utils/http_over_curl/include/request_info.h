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

#ifndef COMMUNICATIONNETSTACK_REQUEST_INFO_H
#define COMMUNICATIONNETSTACK_REQUEST_INFO_H

#include "curl/curl.h"

#include "transfer_callbacks.h"

namespace OHOS::NetStack::HttpOverCurl {
struct TransferCallbacks {
    TransferStartedCallback startedCallback;
    TransferDoneCallback doneCallback;
#ifdef HTTP_HANDOVER_FEATURE
    TransferHandoverInfoCallback handoverInfoCallback;
    SetHandoverInfoCallback setHandoverInfoCallback;
#endif
};

struct RequestInfo {
    CURL *easyHandle;
    TransferCallbacks callbacks;
    void *opaqueData;
};

struct RedirectionInterceptorInfo {
    CURLMsg *message;
    std::shared_ptr<std::string> location;
};

} // namespace OHOS::NetStack::HttpOverCurl

#endif // COMMUNICATIONNETSTACK_REQUEST_INFO_H
