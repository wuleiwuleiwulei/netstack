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

 #include <cstring>
 #include <iostream>
 #include <vector>
 #include <string>

 #include "net_http.h"
 #include "netstack_hash_map.h"
 #include "netstack_log.h"
 #include "net_http_inner_types.h"
 #include "http_client_request.h"
 #include "http_client.h"
 #include "http_client_constant.h"
 #include "netstack_common_utils.h"

using namespace OHOS::NetStack::HttpClient;

std::mutex requestMutex;
static std::unordered_map<uint32_t, std::shared_ptr<HttpClientTask>> cppRequestTask;

Http_Headers *OH_Http_CreateHeaders(void)
{
    Http_Headers *headers = (Http_Headers *)malloc(sizeof(Http_Headers));
    if (headers == nullptr) {
        NETSTACK_LOGE("failed to alloc for headers");
        return nullptr;
    }
    headers->fields = CreateMap();
    if (headers->fields == nullptr) {
        NETSTACK_LOGE("failed to alloc memory for headerMap");
        free(headers);
        headers = nullptr;
    }

    return headers;
}

static void OH_Http_DestroyHeaderValue(void *value)
{
    Http_HeaderValue *headerValue = (Http_HeaderValue *)value;
    Http_HeaderValue *next;
    while (headerValue != nullptr) {
        next = headerValue->next;
        free(headerValue->value);
        headerValue->value = nullptr;
        free(headerValue);
        headerValue = next;
    }
}

void OH_Http_DestroyHeaders(Http_Headers **headers)
{
    if (headers == nullptr) {
        return;
    }
    if (*headers == nullptr) {
        return;
    }
    if ((*headers)->fields != nullptr) {
        Netstack_DestroyMapWithValue((*headers)->fields, OH_Http_DestroyHeaderValue);
        (*headers)->fields = nullptr;
    }
    free(*headers);
}

static char *OH_Http_ToLowerCase(const char *str)
{
    if (str == nullptr) {
        return nullptr;
    }
    char *lowerStr = strdup(str);
    if (lowerStr == nullptr) {
        NETSTACK_LOGE("failed to alloc memory for string");
        return nullptr;
    }
    for (size_t i = 0; i < strlen(lowerStr); i++) {
        lowerStr[i] = static_cast<char>(tolower(static_cast<int>(lowerStr[i])));
    }
    return lowerStr;
}

// copy both name and value
uint32_t OH_Http_SetHeaderValue(Http_Headers *headers, const char *name, const char *value)
{
    if (headers == nullptr || headers->fields == nullptr || name == nullptr || value == nullptr) {
        return OH_HTTP_PARAMETER_ERROR;
    }
 
    char *lowerName = OH_Http_ToLowerCase(name);
    if (lowerName == nullptr) {
        return OH_HTTP_OUT_OF_MEMORY;
    }
    Http_HeaderValue *existValue = (Http_HeaderValue *)Netstack_GetMapEntry(headers->fields, lowerName);
    Http_HeaderValue *previous = existValue;
    while (existValue != nullptr) {
        if (strcmp(existValue->value, value) == 0) {
            free(lowerName);
            return OH_HTTP_RESULT_OK;
        }
        previous = existValue;
        existValue = existValue->next;
    }

    Http_HeaderValue *headerValue = (Http_HeaderValue *)calloc(1, sizeof(Http_HeaderValue));
    if (headerValue == nullptr) {
        NETSTACK_LOGE("failed to alloc memory for header value");
        free(lowerName);
        return OH_HTTP_OUT_OF_MEMORY;
    }
    headerValue->value = strdup(value);
    if (headerValue->value == nullptr) {
        free(headerValue);
        free(lowerName);
        return OH_HTTP_OUT_OF_MEMORY;
    }
 
    if (previous == nullptr) {
        uint32_t res = Netstack_PutMapEntry(headers->fields, lowerName, headerValue);
        if (res != OH_HTTP_RESULT_OK) {
            free(headerValue->value);
            free(headerValue);
        }
        free(lowerName);
        return res;
    }
    previous->next = headerValue;
    free(lowerName);
    return OH_HTTP_RESULT_OK;
}

Http_HeaderValue *OH_Http_GetHeaderValue(Http_Headers *headers, const char *name)
{
    if (headers == nullptr || headers->fields == nullptr || name == nullptr) {
        return nullptr;
    }
    char *lowerName = OH_Http_ToLowerCase(name);
    if (lowerName == nullptr) {
        return nullptr;
    }
    Http_HeaderValue *value = (Http_HeaderValue *)Netstack_GetMapEntry(headers->fields, lowerName);
    free(lowerName);
    return value;
}

Http_HeaderEntry *OH_Http_GetHeaderEntries(Http_Headers *headers)
{
    if (headers == nullptr || headers->fields == nullptr) {
        NETSTACK_LOGE("OH_Http_GetHeaderEntries headers or headers->fields is null");
        return nullptr;
    }
    Netstack_MapIterator *ite = Netstack_CreateMapIterator(headers->fields);
    if (ite == nullptr) {
        NETSTACK_LOGE("OH_Http_GetHeaderEntries ite is null");
        return nullptr;
    }
    Http_HeaderEntry *entry = (Http_HeaderEntry *)calloc(1, sizeof(Http_HeaderEntry));
    if (entry == nullptr) {
        Netstack_DestroyMapIterator(ite);
        return nullptr;
    }
    Http_HeaderEntry *head = entry;

    while (ite->currentEntry != nullptr) {
        entry->key = ite->currentEntry->key;
        entry->value = (Http_HeaderValue *)ite->currentEntry->value;

        Netstack_MapIterateNext(ite);
        if (ite->currentEntry != nullptr) {
            entry->next = (Http_HeaderEntry *)calloc(1, sizeof(Http_HeaderEntry));
            if (entry->next == nullptr) {
                OH_Http_DestroyHeaderEntries(&head);
                head = nullptr;
                break;
            }
            entry = entry->next;
        }
    }
    Netstack_DestroyMapIterator(ite);
    return head;
}

void OH_Http_DestroyHeaderEntries(Http_HeaderEntry **entry)
{
    if (entry == nullptr || *entry == nullptr) {
        NETSTACK_LOGE("OH_Http_DestroyHeaderEntries entry or *entry is null");
        return;
    }
    Http_HeaderEntry *next;
    while (*entry != nullptr) {
        next = (*entry)->next;
        free(*entry);
        *entry = next;
    }
}

Http_Request *OH_Http_CreateRequest(const char *url)
{
    NETSTACK_LOGD("liuleimin OH_Http_CreateRequest enter");
    if (url == nullptr) {
        NETSTACK_LOGE("create request failed: invalid url");
        return nullptr;
    }
    Http_Request *request = (Http_Request *)calloc(1, sizeof(Http_Request));
    if (request == nullptr) {
        NETSTACK_LOGE("failed to alloc memory for request");
        return nullptr;
    }
    request->url = strdup(url);
    if (request->url == nullptr) {
        NETSTACK_LOGE("failed strdup url");
        free(request);
        return nullptr;
    }
    return request;
}

Http_Headers *OH_Http_ToCHeaders(std::map<std::string, std::string> &map)
{
    Http_Headers *cHeaders = OH_Http_CreateHeaders();
    if (cHeaders == nullptr) {
        return nullptr;
    }
    for (auto it = map.begin(); it != map.end(); ++it) {
           if (!it->first.empty() && !it->second.empty()) {
               (void)OH_Http_SetHeaderValue(cHeaders, it->first.c_str(), it->second.c_str());
           }
    }
    return cHeaders;
}

void OH_Http_SetHeaderData(Http_Headers *headers, HttpClientRequest *httpReq)
{
    if (headers == nullptr || httpReq == nullptr) {
        return;
    }
    Http_HeaderEntry *entries = OH_Http_GetHeaderEntries(headers);
    Http_HeaderValue *headerValue;
    Http_HeaderEntry *delEntries = entries;
    while (entries != nullptr) {
        headerValue = entries->value;
        while (headerValue != nullptr && entries->key != nullptr) {
            httpReq->SetHeader(entries->key, headerValue->value);
            headerValue = headerValue->next;
        }
        entries = entries->next;
    }
    OH_Http_DestroyHeaderEntries(&delEntries);
}

static void OH_Http_DestroyResponse(Http_Response **response)
{
    NETSTACK_LOGE("OH_Http_DestroyResponse enter");
    if (response == nullptr || *response == nullptr) {
        NETSTACK_LOGE("OH_Http_DestroyResponse response is nullptr");
        return;
    }
    if ((*response)->headers != nullptr) {
        OH_Http_DestroyHeaders(&(*response)->headers);
    }
    if ((*response)->cookies != nullptr) {
        free((*response)->cookies);
        (*response)->cookies = nullptr;
    }
    if ((*response)->performanceTiming != nullptr) {
        free((*response)->performanceTiming);
        (*response)->performanceTiming = nullptr;
    }

    free((*response));
    (*response) = nullptr;
}

void OH_Http_SetOtherOption(HttpClientRequest *httpReq, Http_Request *request)
{
    //clientCert
    if (request->options->clientCert != nullptr) {
        HttpClientCert clientCert;
        if (request->options->clientCert->certPath != nullptr) {
            clientCert.certPath = request->options->clientCert->certPath;
        }
        if (request->options->clientCert->keyPassword != nullptr) {
            clientCert.keyPassword = request->options->clientCert->keyPassword;
        }
        if (request->options->clientCert->keyPath != nullptr) {
            clientCert.keyPath = request->options->clientCert->keyPath;
        }
        if (request->options->clientCert->type == Http_CertType::OH_HTTP_PEM) {
            clientCert.certType = "PEM";
        }
        if (request->options->clientCert->type == Http_CertType::OH_HTTP_DER) {
            clientCert.certType = "DER";
        }
        if (request->options->clientCert->type == Http_CertType::OH_HTTP_P12) {
            clientCert.certType = "P12";
        }
        httpReq->SetClientCert(clientCert);
    }
    //Http_AddressFamilyType
    if (request->options->addressFamily == Http_AddressFamilyType::HTTP_ADDRESS_FAMILY_ONLY_V4) {
        httpReq->SetAddressFamily("ONLY_V4");
    }
    if (request->options->addressFamily == Http_AddressFamilyType::HTTP_ADDRESS_FAMILY_ONLY_V6) {
        httpReq->SetAddressFamily("ONLY_V6");
    }
    if (request->options->addressFamily == Http_AddressFamilyType::HTTP_ADDRESS_FAMILY_DEFAULT) {
        httpReq->SetAddressFamily("DEFAULT");
    }
}

void OH_Http_SetOption(HttpClientRequest *httpReq, Http_Request *request)
{
    if (request->options->method != nullptr) {
        httpReq->SetMethod(request->options->method);
    }
    httpReq->SetPriority(request->options->priority);
    if (request->options->readTimeout != 0) {
        httpReq->SetTimeout(request->options->readTimeout);
    }
    if (request->options->connectTimeout != 0) {
        httpReq->SetConnectTimeout(request->options->connectTimeout);
    }
    if (request->options->headers != nullptr) {
        OH_Http_SetHeaderData(request->options->headers, httpReq);
    }
    if (request->options->httpProxy != nullptr) {
        httpReq->SetHttpProxyType(static_cast<HttpProxyType>(request->options->httpProxy->proxyType));
        if (request->options->httpProxy->customProxy.host != nullptr &&
            request->options->httpProxy->customProxy.exclusionLists != nullptr) {
            HttpProxy httpProxy;
            httpProxy.host = request->options->httpProxy->customProxy.host;
            httpProxy.port = request->options->httpProxy->customProxy.port;
            httpProxy.exclusions = request->options->httpProxy->customProxy.exclusionLists;
            httpReq->SetHttpProxy(httpProxy);
        }
    }
    //httpProtocol
    httpReq->SetHttpProtocol(static_cast<HttpProtocol>(request->options->httpProtocol));
    // caPath
    if (request->options->caPath != nullptr) {
        httpReq->SetCaPath((std::string)request->options->caPath);
    }
    // resumeFrom  resumeTo
    if ((request->options->method != nullptr && strcmp(request->options->method, HttpConstant::HTTP_METHOD_GET) == 0) ||
        request->options->method == nullptr) {
        httpReq->SetResumeFrom(request->options->resumeFrom);
        httpReq->SetResumeTo(request->options->resumeTo);
    }
    OH_Http_SetOtherOption(httpReq, request);
}

void OH_Http_RequestOnSuccess(std::shared_ptr<HttpClientTask> httpClientTask,
    Http_ResponseCallback callback, Http_EventsHandler handler)
{
    if (httpClientTask == nullptr) {
        NETSTACK_LOGE("OH_Http_RequestOnSuccess httpClientTask is nullptr");
        return;
    }
    httpClientTask->OnSuccess([callback, handler] (const HttpClientRequest &request,
        const HttpClientResponse &response) {
        NETSTACK_LOGI("OnSuccess. code=%{public}d", response.GetResponseCode());
        Http_Response *resp = (Http_Response *)calloc(1, sizeof(Http_Response));
        if (resp == nullptr) {
           callback(nullptr, OH_HTTP_OUT_OF_MEMORY);
           return OH_HTTP_OUT_OF_MEMORY;
        }
        resp->responseCode =  static_cast<Http_ResponseCode>(response.GetResponseCode());
        resp->cookies = const_cast<char*>(response.GetCookies().data());
        resp->body.buffer = response.GetResult().data();
        resp->body.length = response.GetResult().size();
        Http_PerformanceTiming *performanceTiming = (Http_PerformanceTiming *)calloc(1,
            sizeof(Http_PerformanceTiming));
        if (performanceTiming == nullptr) {
           callback(nullptr, OH_HTTP_OUT_OF_MEMORY);
           free(resp);
           return OH_HTTP_OUT_OF_MEMORY;
        }
        performanceTiming->dnsTiming = response.GetPerformanceTiming().dnsTiming;
        performanceTiming->tcpTiming = response.GetPerformanceTiming().connectTiming;
        performanceTiming->tlsTiming = response.GetPerformanceTiming().tlsTiming;
        performanceTiming->firstSendTiming = response.GetPerformanceTiming().firstSendTiming;
        performanceTiming->firstReceiveTiming = response.GetPerformanceTiming().firstReceiveTiming;
        performanceTiming->totalFinishTiming = response.GetPerformanceTiming().totalTiming;
        performanceTiming->redirectTiming = response.GetPerformanceTiming().redirectTiming;
        resp->performanceTiming = performanceTiming;

        std::map<std::string, std::string> map = response.GetHeaders();
        Http_Headers *headers = OH_Http_ToCHeaders(map);
        resp->headers = headers;
        resp->destroyResponse = OH_Http_DestroyResponse;
        callback(resp, 0);
        if (handler.onDataEnd != nullptr) {
            handler.onDataEnd();
        }
        return OH_HTTP_RESULT_OK;
    });
}

void OH_Http_RequestOnCancel(std::shared_ptr<HttpClientTask> httpClientTask, Http_EventsHandler handler)
{
    if (httpClientTask == nullptr) {
        NETSTACK_LOGE("OH_Http_RequestOnCancel httpClientTask is nullptr");
        return;
    }
    httpClientTask->OnCancel([handler] (const HttpClientRequest &request,
        const HttpClientResponse &response) {
        NETSTACK_LOGI("OnCancel. code=%{public}d", response.GetResponseCode());
        if (handler.onCanceled != nullptr) {
            handler.onCanceled();
        }
        return OH_HTTP_RESULT_OK;
    });
}

void OH_Http_RequestOnFail(std::shared_ptr<HttpClientTask> httpClientTask,
    Http_ResponseCallback callback, Http_EventsHandler handler)
{
    if (httpClientTask == nullptr) {
        NETSTACK_LOGE("OH_Http_RequestOnFail httpClientTask is nullptr");
        return;
    }
    httpClientTask->OnFail([callback, handler] (const HttpClientRequest &request,
        const HttpClientResponse &response, const HttpClientError &error) {
        NETSTACK_LOGE("OnFail. responseCode=%{public}d error=%{public}d",
            response.GetResponseCode(), error.GetErrorCode());
        Http_Response *resp = (Http_Response *)calloc(1, sizeof(Http_Response));
        if (resp == nullptr) {
           callback(nullptr, OH_HTTP_OUT_OF_MEMORY);
           return OH_HTTP_OUT_OF_MEMORY;
        }
        resp->responseCode =  static_cast<Http_ResponseCode>(response.GetResponseCode());
        resp->destroyResponse = OH_Http_DestroyResponse;
        callback(resp, static_cast<uint32_t>(error.GetErrorCode()));
        if (handler.onDataEnd != nullptr) {
            handler.onDataEnd();
        }
        return OH_HTTP_RESULT_OK;
    });
}

void OH_Http_RequestOnDataReceive(std::shared_ptr<HttpClientTask> httpClientTask, Http_EventsHandler handler)
{
    if (httpClientTask == nullptr) {
        NETSTACK_LOGE("OH_Http_RequestOnDataReceive httpClientTask is nullptr");
        return;
    }
    httpClientTask->OnDataReceive([handler] (const HttpClientRequest &request,
        const uint8_t *data, size_t length) {
        if (handler.onDataReceive != nullptr) {
            handler.onDataReceive(reinterpret_cast<const char *>(data), length);
        }
        return OH_HTTP_RESULT_OK;
    });
}

void OH_Http_RequestOnHeadersReceive(std::shared_ptr<HttpClientTask> httpClientTask, Http_EventsHandler handler)
{
    if (httpClientTask == nullptr) {
        NETSTACK_LOGE("OH_Http_RequestOnHeadersReceive httpClientTask is nullptr");
        return;
    }
    httpClientTask->OnHeadersReceive([handler] (const HttpClientRequest &request,
        std::map<std::string, std::string> headerWithSetCookie) {
        if (handler.onHeadersReceive != nullptr) {
            Http_Headers *headers = OH_Http_ToCHeaders(headerWithSetCookie);
            handler.onHeadersReceive(headers);
        }
        return OH_HTTP_RESULT_OK;
    });
}

void OH_Http_RequestOnProgress(std::shared_ptr<HttpClientTask> httpClientTask, Http_EventsHandler handler)
{
    if (httpClientTask == nullptr) {
        NETSTACK_LOGE("OH_Http_RequestOnProgress httpClientTask is nullptr");
        return;
    }
    httpClientTask->OnProgress([handler] (const HttpClientRequest &request,
        u_long dlTotal, u_long dlNow, u_long ulTotal, u_long ulNow) {
        if (ulTotal != 0 && ulTotal >= ulNow) {
            if (handler.onUploadProgress != nullptr) {
                handler.onUploadProgress(ulTotal, ulNow);
            }
        }
        if (dlTotal != 0) {
            if (handler.onDownloadProgress != nullptr) {
                handler.onDownloadProgress(dlTotal, dlNow);
            }
        }
        return OH_HTTP_RESULT_OK;
    });
}

int OH_Http_Request(Http_Request *request, Http_ResponseCallback callback, Http_EventsHandler handler)
{
    NETSTACK_LOGI("OH_Http_Request enter");
    if (request == nullptr || callback == nullptr) {
        NETSTACK_LOGE("OH_Http_Request request or callback is nullptr");
        return OH_HTTP_OUT_OF_MEMORY;
    }
    HttpClientRequest httpReq;
    httpReq.SetURL(request->url);
    if (request->options != nullptr) {
        OH_Http_SetOption(&httpReq, request);
    }
    HttpSession &session = HttpSession::GetInstance();
    auto httpClientTask = session.CreateTask(httpReq);
    if (httpClientTask == nullptr) {
        NETSTACK_LOGE("OH_Http_Request httpClientTask is nullptr");
        return OH_HTTP_OUT_OF_MEMORY;
    }
    OH_Http_RequestOnSuccess(httpClientTask, callback, handler);
    OH_Http_RequestOnCancel(httpClientTask, handler);
    OH_Http_RequestOnFail(httpClientTask, callback, handler);
    OH_Http_RequestOnDataReceive(httpClientTask, handler);
    OH_Http_RequestOnHeadersReceive(httpClientTask, handler);
    OH_Http_RequestOnProgress(httpClientTask, handler);
    if (!httpClientTask->Start()) {
        HttpErrorCode error = httpClientTask->GetError().GetErrorCode();
        NETSTACK_LOGE("OH_Http_Request error:%{public}d", error);
        return httpClientTask->GetError().GetErrorCode();
    }
    request->requestId = httpClientTask->GetTaskId();
    std::lock_guard<std::mutex> lock(requestMutex);
    cppRequestTask[request->requestId] = std::move(httpClientTask);
    return 0;
}

void OH_Http_Destroy(struct Http_Request **request)
{
    NETSTACK_LOGI("OH_Http_Destroy enter");
    if (request == nullptr) {
        NETSTACK_LOGE("OH_Http_Destroy request is nullptr");
        return;
    }
    if (*request == nullptr) {
        NETSTACK_LOGE("OH_Http_Destroy *request is nullptr");
        return;
    }
    std::lock_guard<std::mutex> lock(requestMutex);
    if (cppRequestTask.find((*request)->requestId) != cppRequestTask.end()) {
        auto httpClientTask = cppRequestTask[(*request)->requestId];
        if (httpClientTask != nullptr) {
            httpClientTask->Cancel();
            NETSTACK_LOGD("OH_Http_Destroy request->requestId:%{public}d", (*request)->requestId);
        }
        cppRequestTask.erase((*request)->requestId);
    }
    if ((*request)->url != nullptr) {
        free((*request)->url);
        (*request)->url = nullptr;
    }
    free(*request);
    *request = nullptr;
}