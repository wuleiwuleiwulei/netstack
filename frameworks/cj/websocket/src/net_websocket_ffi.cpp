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

#include "net_websocket_ffi.h"

#include <vector>

#include "netstack_log.h"
#include "net_websocket_impl.h"
#include "cj_lambda.h"

using namespace OHOS::FFI;
namespace OHOS::NetStack::NetWebSocket {
EXTERN_C_START

    int64_t FfiOHOSWebSocketCreateWebSocket()
    {
        auto instance = FFI::FFIData::Create<CJWebsocketProxy>();
        if (!instance) {
            NETSTACK_LOGE("CJWebSocket Create CJWebsocketProxy failed.");
            return ERR_INVALID_INSTANCE_CODE;
        }
        return instance->GetID();
    }

    RetDataBool FfiOHOSWebSocketConnect(int64_t id, char* url, CWebSocketRequestOptions* opt)
    {
        RetDataBool ret = { .code = 0, .data = false };
        auto instance = FFIData::GetData<CJWebsocketProxy>(id);
        if (instance == nullptr) {
            // destroyed
            NETSTACK_LOGE("CJWebSocket FfiOHOSWebSocketConnect failed. instance is null.");
            ret.code = WEBSOCKET_UNKNOWN_OTHER_ERROR;
            return ret;
        }

        auto context = CJWebsocketImpl::Connect(std::string(url), opt, instance);
        if (context == nullptr) {
            // websocket initialize failed
            NETSTACK_LOGE("CJWebSocket FfiOHOSWebSocketConnect failed. context is null.");
            ret.code = WEBSOCKET_UNKNOWN_OTHER_ERROR;
            return ret;
        }
        if (context->IsPermissionDenied() || !context->IsParseOK()) {
            NETSTACK_LOGE("CJWebSocket FfiOHOSWebSocketConnect failed. Permission denied.");
            ret.code = context->GetErrorCode();
            delete context;
            return ret;
        }
        ret.data = true;
        delete context;
        return ret;
    }
    
    RetDataBool FfiOHOSWebSocketSend(int64_t id, CArrUI8 data, bool stringType)
    {
        RetDataBool ret = { .code = 0, .data = false };
        auto instance = FFIData::GetData<CJWebsocketProxy>(id);
        if (instance == nullptr) {
            // destroyed
            NETSTACK_LOGE("CJWebSocket FfiOHOSWebSocketSend failed. instance is null.");
            ret.code = WEBSOCKET_UNKNOWN_OTHER_ERROR;
            return ret;
        }
        if (data.size == 0) {
            ret.code = WEBSOCKET_PARSE_ERROR_CODE;
            return ret;
        }
        auto context = CJWebsocketImpl::Send(data, instance, stringType);
        if (context == nullptr) {
            // websocket initialize failed
            NETSTACK_LOGE("CJWebSocket FfiOHOSWebSocketSend failed. context is null.");
            ret.code = WEBSOCKET_UNKNOWN_OTHER_ERROR;
            return ret;
        }
        if (context->IsPermissionDenied() || !context->IsParseOK()) {
            ret.code = context->GetErrorCode();
            delete context;
            return ret;
        }
        ret.data = true;
        delete context;
        return ret;
    }
    
    RetDataBool FfiOHOSWebSocketClose(int64_t id, CWebSocketCloseOptions* opt)
    {
        RetDataBool ret = { .code = 0, .data = false };
        auto instance = FFIData::GetData<CJWebsocketProxy>(id);
        if (instance == nullptr) {
            // destroyed
            ret.code = WEBSOCKET_UNKNOWN_OTHER_ERROR;
            NETSTACK_LOGE("CJWebSocket FfiOHOSWebSocketClose failed. instance is null.");
            return ret;
        }
        auto context = CJWebsocketImpl::Close(opt, instance);
        if (context == nullptr) {
            // websocket initialize failed
            ret.code = WEBSOCKET_UNKNOWN_OTHER_ERROR;
            NETSTACK_LOGE("CJWebSocket FfiOHOSWebSocketClose failed. context is null.");
            return ret;
        }
        if (context->IsPermissionDenied() || !context->IsParseOK()) {
            ret.code = context->GetErrorCode();
            delete context;
            return ret;
        }
        ret.data = true;
        delete context;
        return ret;
    }

    int32_t FfiOHOSWebSocketOnController(int64_t id, int32_t typeId, void (*callback)(CWebSocketCallbackData *data))
    {
        int32_t ret = WEBSOCKET_UNKNOWN_OTHER_ERROR;
        auto instance = FFIData::GetData<CJWebsocketProxy>(id);
        if (instance == nullptr) {
            // destroyed
            NETSTACK_LOGE("CJWebSocket FfiOHOSWebSocketOnController failed. instance is null.");
            return ret;
        }
        if (CJWebsocketImpl::OnWithProxy(typeId, callback, instance)) {
            ret = 0;
        }
        return ret;
    }

    int32_t FfiOHOSWebSocketOffController(int64_t id, int32_t typeId)
    {
        int32_t ret = WEBSOCKET_UNKNOWN_OTHER_ERROR;
        auto instance = FFIData::GetData<CJWebsocketProxy>(id);
        if (instance == nullptr) {
            // destroyed
            NETSTACK_LOGE("CJWebSocket FfiOHOSWebSocketOffController failed. instance is null.");
            return ret;
        }
        if (CJWebsocketImpl::OffWithProxy(typeId, instance)) {
            ret = 0;
        }
        return ret;
    }
EXTERN_C_END
}