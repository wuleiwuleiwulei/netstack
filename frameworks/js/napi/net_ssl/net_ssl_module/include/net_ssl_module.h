/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_NET_SSL_MODULE_H
#define COMMUNICATIONNETSTACK_NET_SSL_MODULE_H

#include "napi/native_api.h"

namespace OHOS::NetStack::Ssl {
class NetSslModuleExports {
public:
    static napi_value VerifyCertification(napi_env env, napi_callback_info info);

    static napi_value VerifyCertificationSync(napi_env env, napi_callback_info info);

    static napi_value IsCleartextPermitted(napi_env env, napi_callback_info info);

    static napi_value IsCleartextPermittedByHostName(napi_env env, napi_callback_info info);

    static napi_value InitNetSslModule(napi_env env, napi_value exports);

    static void InitSslProperties(napi_env env, napi_value exports);

    static void InitCertType(napi_env env, napi_value exports);
};
} // namespace OHOS::NetStack::Ssl
#endif // COMMUNICATIONNETSTACK_NET_SSL_MODULE_H
