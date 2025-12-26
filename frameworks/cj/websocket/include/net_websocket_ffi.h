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

#ifndef NET_WEBSOCKET_FFI_H
#define NET_WEBSOCKET_FFI_H

#include "ffi_remote_data.h"
#include "ffi_structs.h"
#include "netstack_log.h"
#include "constant.h"
#include "net_websocket_impl.h"

EXTERN_C_START
    FFI_EXPORT int64_t FfiOHOSWebSocketCreateWebSocket();
    FFI_EXPORT RetDataBool FfiOHOSWebSocketSend(int64_t id, CArrUI8 data, bool stringType);
    FFI_EXPORT RetDataBool FfiOHOSWebSocketConnect(int64_t id, char* url, CWebSocketRequestOptions* opt);
    FFI_EXPORT RetDataBool FfiOHOSWebSocketClose(int64_t id, CWebSocketCloseOptions* opt);

    // callback events
    FFI_EXPORT int32_t FfiOHOSWebSocketOnController(int64_t id, int32_t typeId,
                                                    void (*callback)(CWebSocketCallbackData *data));
    FFI_EXPORT int32_t FfiOHOSWebSocketOffController(int64_t id, int32_t typeId);
EXTERN_C_END

#endif