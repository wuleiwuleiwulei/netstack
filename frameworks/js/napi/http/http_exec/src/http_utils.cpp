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
 
#include "http_utils.h"

#if HAS_NETMANAGER_BASE
#include "bundle_mgr_interface.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "netstack_log.h"
#endif

namespace OHOS::NetStack::HttpUtils {

static std::string g_appMode = "";

bool IsDebugMode()
{
#if HAS_NETMANAGER_BASE
    if (!g_appMode.empty()) {
        return (g_appMode == "debug") ? true : false;
    }
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        NETSTACK_LOGE("IsDebugMode failed to get system ability mgr.");
        return false;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        NETSTACK_LOGE("IsDebugMode failed to get bundle manager proxy.");
        return false;
    }

    sptr<AppExecFwk::IBundleMgr> bundleMgrProxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (bundleMgrProxy == nullptr) {
        NETSTACK_LOGE("IsDebugMode failed to get bundle manager proxy.");
        return false;
    }

    AppExecFwk::BundleInfo bundleInfo;
    constexpr auto flag = static_cast<uint32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    const auto res = bundleMgrProxy->GetBundleInfoForSelf(flag, bundleInfo);
    NETSTACK_LOGD("IsDebugMode GetBundleInfoForSelf res = %{public}d", res);

    const auto appProvisionType = bundleInfo.applicationInfo.appProvisionType;
    g_appMode = appProvisionType;
    NETSTACK_LOGD("IsDebugMode appProvisionType = %{public}s", appProvisionType.c_str());
    return (appProvisionType == "debug") ? true : false;
#else
    return true;
#endif
}

std::string RemoveUrlParameters(const std::string& url)
{
    size_t questionMarkPos = url.find('?');
    if (questionMarkPos == std::string::npos) {
        return url;
    }
    return url.substr(0, questionMarkPos);
}
} // namespace OHOS::NetStack::HttpUtils