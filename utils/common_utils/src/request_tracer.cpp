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

#include "request_tracer.h"
#include <atomic>
#if HAS_NETMANAGER_BASE
#include "hitrace_meter.h"
#endif

OHOS::NetStack::RequestTracer::Trace::~Trace() = default;


OHOS::NetStack::RequestTracer::Trace::Trace(const std::string &className, int32_t idNum)
    : className_(className),
      stageName_(std::nullopt),
      idNum_(idNum)
{
}

int32_t OHOS::NetStack::RequestTracer::Trace::GenerateId()
{
    static std::atomic_int32_t idNum = 0;
    return ++idNum;
}
OHOS::NetStack::RequestTracer::Trace::Trace(const std::string &className) : Trace(className, GenerateId())
{
}

void OHOS::NetStack::RequestTracer::Trace::Tracepoint(const std::string &stage)
{
    if (stage == stageName_) {
        return;
    }
    Finish();
    stageName_ = stage;
#if HAS_NETMANAGER_BASE
    StartAsyncTrace(HITRACE_TAG_NET, className_ + "$$" + *stageName_, idNum_);
#endif
}

void OHOS::NetStack::RequestTracer::Trace::Finish()
{
#if HAS_NETMANAGER_BASE
    if (stageName_) {
        FinishAsyncTrace(HITRACE_TAG_NET, className_ + "$$" + *stageName_, idNum_);
    }
#endif
}