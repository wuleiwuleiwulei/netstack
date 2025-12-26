/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NET_WEBSOCKET_FFI_STRUCTS_H
#define NET_WEBSOCKET_FFI_STRUCTS_H

#include <cstdint>

#include "cj_ffi/cj_common_ffi.h"

#ifdef __cplusplus
#define EXTERN_C_START extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_START
#define EXTERN_C_END
#endif

EXTERN_C_START
    struct CHttpProxy {
        char* host;
        uint16_t port;
        char** exclusionList;
        int64_t exclusionListSize;
    };

    struct CClientCert {
        char* certPath;
        char* keyPath;
        char* keyPassword;
    };

    struct CWebSocketRequestOptions {
        CArrString header;
        char* caPath;
        CClientCert* clientCert;
        char* protocol;
        bool usingSystemProxy;
        CHttpProxy* httpProxy;
        uint32_t pingInterval;
        uint32_t pongTimeout;
    };

    struct CWebSocketCloseOptions {
        uint32_t code;
        char* reason;
    };

    struct CWebSocketCallbackData {
        int32_t code;
        int32_t typeId;
        uint8_t* data;
        int32_t dataLen;
    };

    struct COpenResponse {
        uint32_t status;
        char* message;
    };

    struct CMessageResponse {
        CArrUI8 result;
        int32_t resultType;
    };

    struct CErrorResponse {
        int32_t code;
        uint32_t httpResponse;
    };

    struct CCloseResponse {
        uint32_t code;
        char* reason;
    };
    
    struct CReceiveResponse {
        CArrString header;
        int32_t headerType;
    };
EXTERN_C_END

#endif