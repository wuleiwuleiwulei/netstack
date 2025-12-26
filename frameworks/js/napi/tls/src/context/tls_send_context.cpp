/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "tls_send_context.h"

#include <cstdint>
#include <string_view>

#include "constant.h"
#include "napi_utils.h"
#include "netstack_log.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
static constexpr std::string_view PARSE_ERROR = "data is not string";

TLSSendContext::TLSSendContext(napi_env env, const std::shared_ptr<EventManager> &manager)
    : BaseContext(env, manager) {}

void TLSSendContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsType(params, paramsCount)) {
        return;
    }
    if (NapiUtils::GetValueType(GetEnv(), params[ARG_INDEX_0]) == napi_string) {
        data_ = NapiUtils::GetStringFromValueUtf8(GetEnv(), params[ARG_INDEX_0]);
        if (data_.empty()) {
            NETSTACK_LOGE("string data is empty");
            if (paramsCount == PARAM_OPTIONS_AND_CALLBACK && SetCallback(params[1]) != napi_ok) {
                NETSTACK_LOGE("failed to set callback");
            }
            return;
        }
    }

    if (NapiUtils::ValueIsArrayBuffer(GetEnv(), params[ARG_INDEX_0])) {
        size_t length = 0;
        void *data = NapiUtils::GetInfoFromArrayBufferValue(GetEnv(), params[ARG_INDEX_0], &length);
        if (data == nullptr || length == 0) {
            NETSTACK_LOGE("arraybuffer data is empty");
            if (paramsCount == PARAM_OPTIONS_AND_CALLBACK && SetCallback(params[1]) != napi_ok) {
                NETSTACK_LOGE("failed to set callback");
            }
            return;
        }
        data_.append(reinterpret_cast<char *>(data), length);
    }

    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        SetParseOK(SetCallback(params[ARG_INDEX_1]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

bool TLSSendContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_JUST_OPTIONS) {
        if (NapiUtils::GetValueType(GetEnv(), params[ARG_INDEX_0]) != napi_string &&
            !NapiUtils::ValueIsArrayBuffer(GetEnv(), params[ARG_INDEX_0])) {
            NETSTACK_LOGE("first param is not string or arraybuffer");
            SetNeedThrowException(true);
            SetError(PARSE_ERROR_CODE, PARSE_ERROR.data());
            return false;
        }
        return true;
    }

    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        if (NapiUtils::GetValueType(GetEnv(), params[ARG_INDEX_0]) != napi_string &&
            !NapiUtils::ValueIsArrayBuffer(GetEnv(), params[ARG_INDEX_0])) {
            NETSTACK_LOGE("first param is not string or arraybuffer");
            SetNeedThrowException(true);
            SetError(PARSE_ERROR_CODE, PARSE_ERROR.data());
            return false;
        }
        if (NapiUtils::GetValueType(GetEnv(), params[ARG_INDEX_1]) != napi_function) {
            NETSTACK_LOGE("second param is not function");
            return false;
        }
        return true;
    }
    return false;
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
