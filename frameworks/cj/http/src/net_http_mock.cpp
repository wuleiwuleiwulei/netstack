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

#include "cj_ffi/cj_common_ffi.h"

extern "C" {
FFI_EXPORT int CJ_CreateHttpResponseCache = 0;
FFI_EXPORT int CJ_HttpResponseCacheFlush = 0;
FFI_EXPORT int CJ_HttpResponseCacheDelete = 0;
FFI_EXPORT int CJ_CreateHttp = 0;
FFI_EXPORT int CJ_DestroyRequest = 0;
FFI_EXPORT int CJ_SendRequest = 0;

FFI_EXPORT int CJ_OnHeadersReceive = 0;
FFI_EXPORT int CJ_OffHeadersReceive = 0;
FFI_EXPORT int CJ_OnDataReceive = 0;
FFI_EXPORT int CJ_OffDataReceive = 0;
FFI_EXPORT int CJ_OnDataEnd = 0;
FFI_EXPORT int CJ_OffDataEnd = 0;
FFI_EXPORT int CJ_OnDataReceiveProgress = 0;
FFI_EXPORT int CJ_OffDataReceiveProgress = 0;
FFI_EXPORT int CJ_OnDataSendProgress = 0;
FFI_EXPORT int CJ_OffDataSendProgress = 0;

FFI_EXPORT int FFiOHOSNetHttpFreeCString = 0;
FFI_EXPORT int FFiOHOSNetHttpFreeCArrString = 0;
FFI_EXPORT int FFiOHOSNetHttpFreeCArrUI8 = 0;
}