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

#ifndef COMMUNICATIONNETSTACK_TRANSFER_CALLBACKS_H
#define COMMUNICATIONNETSTACK_TRANSFER_CALLBACKS_H

#include <functional>

#include "curl/curl.h"
#ifdef HTTP_HANDOVER_FEATURE
#include "http_handover_info.h"
#endif

namespace OHOS::NetStack::HttpOverCurl {

using TransferDoneCallback = std::function<void(CURLMsg *curlMessage, void *opaqueData)>;
using TransferStartedCallback = std::function<void(CURL *easyHandle, void *opaqueData)>;
#ifdef HTTP_HANDOVER_FEATURE
using TransferHandoverInfoCallback = std::function<HttpHandoverStackInfo(void *opaqueData)>;
using SetHandoverInfoCallback = std::function<void(HttpHandoverInfo httpHandoverInfo, void *opaqueData)>;
#endif

} // namespace OHOS::NetStack::HttpOverCurl

#endif // COMMUNICATIONNETSTACK_TRANSFER_CALLBACKS_H
