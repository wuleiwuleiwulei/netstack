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

#include "netstack_bundle_utils.h"

#include <dlfcn.h>

#include "netstack_log.h"

namespace OHOS::NetStack::BundleUtils {

#ifdef __LP64__
    const std::string LIB_NET_BUNDL_UTILS_SO_PATH = "libnet_bundle_utils.z.so";
#else
    const std::string LIB_NET_BUNDL_UTILS_SO_PATH = "libnet_bundle_utils.z.so";
#endif

using IsAtomicServiceFunc = bool (*)(std::string&);

__attribute__((no_sanitize("cfi"))) bool IsAtomicService(std::string &bundleName)
{
    void *handler = dlopen(LIB_NET_BUNDL_UTILS_SO_PATH.c_str(), RTLD_NOW);
    if (handler == nullptr) {
        const char *err = dlerror();
        NETSTACK_LOGE("load failed, reason: %{public}s", err ? err : "unknown");
        return false;
    }
    IsAtomicServiceFunc func = (IsAtomicServiceFunc) dlsym(handler, "IsAtomicService");
    if (func == nullptr) {
        const char *err = dlerror();
        NETSTACK_LOGE("dlsym IsAtomicService failed, reason: %{public}s", err ? err : "unknown");
        dlclose(handler);
        return false;
    }
    auto ret = func(bundleName);
    NETSTACK_LOGD("netBundleUtils IsAtomicService result=%{public}d, bundle_name=%{public}s", ret, bundleName.c_str());
    dlclose(handler);
    return ret;
}
}