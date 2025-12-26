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

#include "tls_server_napi_context.h"

#include <cstdint>
#include <string_view>

#include "constant.h"
#include "napi_utils.h"
#include "netstack_log.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocketServer {
static constexpr std::string_view PARSE_ERROR = "data is not int";

TLSServerNapiContext::TLSServerNapiContext(napi_env env, const std::shared_ptr<EventManager> &manager)
    : BaseContext(env, manager)
{
    remoteCert_.encodingFormat = TlsSocket::EncodingFormat::DER;
}

void TLSServerNapiContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsType(params, paramsCount)) {
        return;
    }
    if (paramsCount == TlsSocket::PARAM_JUST_CALLBACK) {
        SetParseOK(SetCallback(params[TlsSocket::ARG_INDEX_0]) == napi_ok);
        return;
    }
    SetParseOK(true);

    return;
}

bool TLSServerNapiContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == TlsSocket::PARAM_NONE) {
        NETSTACK_LOGD("param is none");
        return true;
    }

    if (paramsCount == TlsSocket::PARAM_JUST_CALLBACK) {
        if (NapiUtils::GetValueType(GetEnv(), params[TlsSocket::ARG_INDEX_0]) != napi_function) {
            NETSTACK_LOGE("first param is not string");
            SetNeedThrowException(true);
            SetError(PARSE_ERROR_CODE, PARSE_ERROR.data());
            return false;
        }
        return true;
    }

    if (paramsCount == TlsSocket::PARAM_OPTIONS_AND_CALLBACK) {
        if (NapiUtils::GetValueType(GetEnv(), params[TlsSocket::ARG_INDEX_0]) != napi_number) {
            NETSTACK_LOGE("first param is not int");
            SetNeedThrowException(true);
            SetError(PARSE_ERROR_CODE, PARSE_ERROR.data());
            return false;
        }
        if (NapiUtils::GetValueType(GetEnv(), params[TlsSocket::ARG_INDEX_1]) != napi_function) {
            NETSTACK_LOGE("second param is not function");
            return false;
        }
        return true;
    }
    return false;
}
} // namespace TlsSocketServer
} // namespace NetStack
} // namespace OHOS
