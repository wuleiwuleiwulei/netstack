/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNET_SSL_ASYNC_WORK_H
#define COMMUNICATIONNET_SSL_ASYNC_WORK_H

#include "cert_context.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS::NetStack::Ssl {
class NetSslAsyncWork final {
public:
    static void ExecVerify(napi_env env, void *data);

    static void VerifyCallback(napi_env env, napi_status status, void *data);
};
} // namespace OHOS::NetStack::Ssl

#endif /* COMMUNICATIONNET_SSL_ASYNC_WORK_H */
