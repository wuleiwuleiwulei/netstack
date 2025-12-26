/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef NET_HTTP_FFI_STRUCTS_H
#define NET_HTTP_FFI_STRUCTS_H

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

    struct CMultiFormData {
        char* name;
        char* contentType;
        char* remoteFileName;
        CArrUI8 data;
        char* filePath;
    };

    struct CArrMultiFormData {
        CMultiFormData* data;
        int64_t size;
    };

    struct CClientCert {
        char* certPath;
        char* keyPath;
        char* certType;
        char* keyPassword;
    };

    struct CPerformanceTiming {
        double dnsTiming;
        double tcpTiming;
        double tlsTiming;
        double firstSendTiming;
        double firstReceiveTiming;
        double totalFinishTiming;
        double redirectTiming;
        double responseHeaderTiming;
        double responseBodyTiming;
        double totalTiming;
    };

    struct CHttpRequestOptions {
        char* method;
        CArrUI8 extraData;
        int32_t expectDataType;
        bool usingCache;
        uint32_t priority;
        CArrString header;
        uint32_t readTimeout;
        uint32_t connectTimeout;
        int32_t usingProtocol;
        bool usingDefaultProxy;
        CHttpProxy* usingProxy;
        char* caPath;
        int64_t resumeFrom;
        int64_t resumeTo;
        CClientCert* clientCert;
        char* dnsOverHttps;
        CArrString dnsServer;
        uint32_t maxLimit;
        CArrMultiFormData multiFormDataList;
    };

    struct CHttpResponse {
        int32_t errCode;
        char* errMsg;
        CArrUI8 result;
        int32_t resultType;
        uint32_t responseCode;
        CArrString header;
        char* cookies;
        CArrString setCookie;
        CPerformanceTiming performanceTiming;
    };

    struct CDataReceiveProgressInfo {
        uint32_t receiveSize;
        uint32_t totalSize;
    };

    struct CDataSendProgressInfo {
        uint32_t sendSize;
        uint32_t totalSize;
    };
EXTERN_C_END

#endif