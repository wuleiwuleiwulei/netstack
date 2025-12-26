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

#include "netstack_network_profiler.h"

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "network_profiler.h"
#include "time_service_client.h"
#endif

namespace OHOS::NetStack {
namespace {
constexpr const size_t BUFFER_MAX_SIZE = 256 * 1024;
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
constexpr const uint64_t NS_TO_MICRO = 1000;
#endif
}

NetworkProfilerUtils::NetworkProfilerUtils()
{
    if (!IsProfilerEnable()) {
        return;
    }
    enable_ = true;
    requestBeginTime_ = GetBootTime();
}

NetworkProfilerUtils::~NetworkProfilerUtils()
{
    if (data_ != nullptr) {
        free(data_);
        data_ = nullptr;
    }
}

void NetworkProfilerUtils::NetworkProfiling(INetworkMessage &networkMessage)
{
    if (!enable_) {
        return;
    }
    networkMessage.SetRequestBeginTime(requestBeginTime_);
    msg_ = networkMessage.Parse();
    if (data_ == nullptr) {
        data_ = malloc(BUFFER_MAX_SIZE);
        if (data_ == nullptr) {
            return;
        }
    }
    auto ret = TlvUtils::Encode(msg_, data_, dataSize_);
    if (ret != TLV_OK) {
        return;
    }
    SendNetworkProfiling();
}

bool NetworkProfilerUtils::IsProfilerEnable()
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    auto profiler = OHOS::Developtools::Profiler::NetworkProfiler::GetInstance();
    if (profiler->IsProfilerEnable()) {
        return true;
    }
    return false;
#else
    return false;
#endif
}

void NetworkProfilerUtils::SendNetworkProfiling()
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (data_ == nullptr || dataSize_ <= 0) {
        return;
    }
    auto profiler = OHOS::Developtools::Profiler::NetworkProfiler::GetInstance();
    profiler->NetworkProfiling(0, static_cast<char *>(data_), dataSize_);
#endif
}

uint64_t NetworkProfilerUtils::GetBootTime()
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    auto powerTime = MiscServices::TimeServiceClient::GetInstance()->GetBootTimeNs();
    if (powerTime < 0) {
        return 0;
    }
    return static_cast<uint64_t>(powerTime / NS_TO_MICRO);
#else
    return 0;
#endif
}
}
