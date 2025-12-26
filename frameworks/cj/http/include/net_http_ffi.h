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

#ifndef NET_HTTP_FFI_H
#define NET_HTTP_FFI_H

#include "ffi_remote_data.h"
#include "ffi_structs.h"
#include "netstack_log.h"

EXTERN_C_START
    FFI_EXPORT int32_t CJ_CreateHttpResponseCache(uint32_t cacheSize);
    FFI_EXPORT int32_t CJ_HttpResponseCacheFlush();
    FFI_EXPORT int32_t CJ_HttpResponseCacheDelete();
    FFI_EXPORT int64_t CJ_CreateHttp();
    FFI_EXPORT void CJ_DestroyRequest(int64_t id);
    FFI_EXPORT RetDataCString CJ_SendRequest(int64_t id, char* url,
        CHttpRequestOptions* opt, bool isInStream, void (*callback)(CHttpResponse));

    // callback events
    FFI_EXPORT void CJ_OnHeadersReceive(int64_t id, bool once, void (*callback)(CArrString));
    FFI_EXPORT void CJ_OffHeadersReceive(int64_t id);
    FFI_EXPORT void CJ_OnDataReceive(int64_t id, void (*callback)(CArrUI8));
    FFI_EXPORT void CJ_OffDataReceive(int64_t id);
    FFI_EXPORT void CJ_OnDataEnd(int64_t id, void (*callback)());
    FFI_EXPORT void CJ_OffDataEnd(int64_t id);
    FFI_EXPORT void CJ_OnDataReceiveProgress(int64_t id, void (*callback)(CDataReceiveProgressInfo));
    FFI_EXPORT void CJ_OffDataReceiveProgress(int64_t id);
    FFI_EXPORT void CJ_OnDataSendProgress(int64_t id, void (*callback)(CDataSendProgressInfo));
    FFI_EXPORT void CJ_OffDataSendProgress(int64_t id);

    // c free
    FFI_EXPORT void FFiOHOSNetHttpFreeCString(char* p);
    FFI_EXPORT void FFiOHOSNetHttpFreeCArrString(CArrString arr);
    FFI_EXPORT void FFiOHOSNetHttpFreeCArrUI8(CArrUI8 arr);
EXTERN_C_END

#endif