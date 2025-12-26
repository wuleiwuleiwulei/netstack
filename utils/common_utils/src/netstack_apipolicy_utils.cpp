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

#include "netstack_apipolicy_utils.h"

#include <dlfcn.h>
#include <mutex>

#include "netstack_log.h"

namespace OHOS::NetStack::ApiPolicyUtils {
namespace {
constexpr const uint32_t RESULT_ACCEPT = 0;
}

#ifdef __LP64__
    const std::string APIPOLICY_SO_PATH = "libapipolicy_client.z.so";
#else
    const std::string APIPOLICY_SO_PATH = "libapipolicy_client.z.so";
#endif

bool IsAllowedHostname(const std::string &bundleName, const std::string &domainType, const std::string &hostname)
{
    void *libHandle = dlopen(APIPOLICY_SO_PATH.c_str(), RTLD_NOW);
    if (!libHandle) {
        const char *err = dlerror();
        NETSTACK_LOGE("apipolicy so dlopen failed: %{public}s", err ? err : "unknown");
        return true;
    }
    using CheckUrlFunc = int32_t (*)(std::string, std::string, std::string);
    auto func = reinterpret_cast<CheckUrlFunc>(dlsym(libHandle, "CheckUrl"));
    if (func == nullptr) {
        const char *err = dlerror();
        NETSTACK_LOGE("apipolicy dlsym CheckUrl failed: %{public}s", err ? err : "unknown");
        dlclose(libHandle);
        return true;
    }
    int32_t res = func(bundleName, domainType, hostname);
    NETSTACK_LOGD("ApiPolicy CheckHttpUrl result=%{public}d", res);
    dlclose(libHandle);
    return res == RESULT_ACCEPT;
}
};