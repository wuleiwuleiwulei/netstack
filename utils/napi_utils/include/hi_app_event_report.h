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

#ifndef HI_SDK_REPORT
#define HI_SDK_REPORT

#ifdef ENABLE_EVENT_HANDLER
#include "app_event.h"
#include "app_event_processor_mgr.h"
#endif

#include <vector>
#include <cstdint>
#include <string>

namespace OHOS {
namespace NetStack {
static constexpr int RESULT_SUCCESS = 0;
static constexpr int RESULT_FAIL = 1;
static constexpr int ERR_NONE = 0;

class HiAppEventReport {
public:
    HiAppEventReport(std::string sdk, std::string api);
    ~HiAppEventReport();
    void ReportSdkEvent(const int result, const int errCode);

#ifdef ENABLE_EVENT_HANDLER
private:
    int64_t AddProcessor();

    int64_t beginTime_ = 0;
    std::string transId_ = "";
    std::string apiName_ = "";
    std::string sdkName_ = "";
#endif
};
} // namespace NetStack
} // namespace OHOS
#endif //HI_SDK_REPORT
