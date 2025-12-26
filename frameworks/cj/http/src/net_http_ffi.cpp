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
#include "net_http_ffi.h"
#include "net_http_request_context.h"
#include "net_http_cache_proxy.h"
#include "net_http_client_exec.h"
#include "cj_lambda.h"

#include <vector>

using namespace OHOS::FFI;
namespace OHOS::NetStack::Http {

void SetUnknowError(RetDataCString &ret)
{
    ret.code = static_cast<int32_t>(HttpErrorCode::HTTP_UNKNOWN_OTHER_ERROR);
    ret.data = MallocCString("Unknown Other Error.");
}

EXTERN_C_START
    int32_t CJ_CreateHttpResponseCache(uint32_t cacheSize)
    {
        CacheProxy::RunCacheWithSize(cacheSize);
        return 0;
    }

    int32_t CJ_HttpResponseCacheFlush()
    {
        CacheProxy::FlushCache();
        return 0;
    }

    int32_t CJ_HttpResponseCacheDelete()
    {
        CacheProxy::StopCacheAndDelete();
        return 0;
    }

    int64_t CJ_CreateHttp()
    {
        auto request = FFI::FFIData::Create<HttpRequestProxy>();
        if (!request) {
            return ERR_INVALID_INSTANCE_CODE;
        }
        return request->GetID();
    }

    void CJ_DestroyRequest(int64_t id)
    {
        auto req = FFIData::GetData<HttpRequestProxy>(id);
        if (req == nullptr) {
            NETSTACK_LOGE("Failed to get HttpRequestProxy.");
            return;
        }
        req->Destroy();
        FFI::FFIData::Release(id);
        return;
    }

    RetDataCString CJ_SendRequest(int64_t id, char* url,
        CHttpRequestOptions* opt, bool isInStream, void (*callback)(CHttpResponse))
    {
        NETSTACK_LOGI("request start");
        RetDataCString ret = { .code = 0, .data = nullptr};
        auto req = FFIData::GetData<HttpRequestProxy>(id);
        if (req == nullptr || req->isDestroyed) {
            // destroyed
            SetUnknowError(ret);
            return ret;
        }
        auto context = req->Request(std::string(url), opt, isInStream);
        if (context == nullptr) {
            // curl initialize failed
            SetUnknowError(ret);
            return ret;
        }
        if (isInStream) {
            context->streamingCallback = req->callbacks;
        }

        context->respCallback = CJLambda::Create(callback);
        
        if (context->IsPermissionDenied() || !context->IsParseOK()) {
            ret.code = context->GetErrorCode();
            ret.data = MallocCString(context->GetErrorMessage());
            delete context;
            return ret;
        }

        return ret;
    }

    void CJ_OnHeadersReceive(int64_t id, bool once, void (*callback)(CArrString))
    {
        auto req = FFIData::GetData<HttpRequestProxy>(id);
        if (req == nullptr) {
            NETSTACK_LOGE("Failed to get HttpRequestProxy.");
            return;
        }
        if (once) {
            req->callbacks->headersReceiveOnce.push_back(CJLambda::Create(callback));
        } else {
            req->callbacks->headersReceive.push_back(CJLambda::Create(callback));
        }
    }

    void CJ_OffHeadersReceive(int64_t id)
    {
        auto req = FFIData::GetData<HttpRequestProxy>(id);
        if (req == nullptr) {
            NETSTACK_LOGE("Failed to get HttpRequestProxy.");
            return;
        }
        req->callbacks->headersReceiveOnce.clear();
        req->callbacks->headersReceive.clear();
    }

    void CJ_OnDataReceive(int64_t id, void (*callback)(CArrUI8))
    {
        auto req = FFIData::GetData<HttpRequestProxy>(id);
        if (req == nullptr) {
            NETSTACK_LOGE("Failed to get HttpRequestProxy.");
            return;
        }
        req->callbacks->dataReceive.push_back(CJLambda::Create(callback));
    }

    void CJ_OffDataReceive(int64_t id)
    {
        auto req = FFIData::GetData<HttpRequestProxy>(id);
        if (req == nullptr) {
            NETSTACK_LOGE("Failed to get HttpRequestProxy.");
            return;
        }
        req->callbacks->dataReceive.clear();
    }

    void CJ_OnDataEnd(int64_t id, void (*callback)())
    {
        auto req = FFIData::GetData<HttpRequestProxy>(id);
        if (req == nullptr) {
            NETSTACK_LOGE("Failed to get HttpRequestProxy.");
            return;
        }
        req->callbacks->dataEnd.push_back(CJLambda::Create(callback));
    }

    void CJ_OffDataEnd(int64_t id)
    {
        auto req = FFIData::GetData<HttpRequestProxy>(id);
        if (req == nullptr) {
            NETSTACK_LOGE("Failed to get HttpRequestProxy.");
            return;
        }
        req->callbacks->dataEnd.clear();
    }

    void CJ_OnDataReceiveProgress(int64_t id, void (*callback)(CDataReceiveProgressInfo))
    {
        auto req = FFIData::GetData<HttpRequestProxy>(id);
        if (req == nullptr) {
            NETSTACK_LOGE("Failed to get HttpRequestProxy.");
            return;
        }
        req->callbacks->dataReceiveProgress.push_back(CJLambda::Create(callback));
    }

    void CJ_OffDataReceiveProgress(int64_t id)
    {
        auto req = FFIData::GetData<HttpRequestProxy>(id);
        if (req == nullptr) {
            NETSTACK_LOGE("Failed to get HttpRequestProxy.");
            return;
        }
        req->callbacks->dataReceiveProgress.clear();
    }

    void CJ_OnDataSendProgress(int64_t id, void (*callback)(CDataSendProgressInfo))
    {
        auto req = FFIData::GetData<HttpRequestProxy>(id);
        if (req == nullptr) {
            NETSTACK_LOGE("Failed to get HttpRequestProxy.");
            return;
        }
        req->callbacks->dataSendProgress.push_back(CJLambda::Create(callback));
    }

    void CJ_OffDataSendProgress(int64_t id)
    {
        auto req = FFIData::GetData<HttpRequestProxy>(id);
        if (req == nullptr) {
            NETSTACK_LOGE("Failed to get HttpRequestProxy.");
            return;
        }
        req->callbacks->dataSendProgress.clear();
    }

    void FFiOHOSNetHttpFreeCString(char* p)
    {
        free(p);
    }

    void FFiOHOSNetHttpFreeCArrString(CArrString arr)
    {
        if (arr.head == nullptr) {
            return;
        }
        for (auto i = 0; i < arr.size; i++) {
            free(arr.head[i]);
        }
        free(arr.head);
    }

    void FFiOHOSNetHttpFreeCArrUI8(CArrUI8 arr)
    {
        free(arr.head);
    }
EXTERN_C_END
}

