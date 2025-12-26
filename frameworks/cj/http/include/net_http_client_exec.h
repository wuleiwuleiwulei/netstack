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

#ifndef NET_HTTP_CLIENT_EXEC_H
#define NET_HTTP_CLIENT_EXEC_H

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <utility>
#include <vector>
#include <set>

#include "curl/curl.h"
#include "net_http_request_context.h"

namespace OHOS::NetStack::Http {
class NetHttpClientExec final {
public:
    NetHttpClientExec() = default;

    ~NetHttpClientExec() = default;

    static bool RequestWithoutCache(RequestContext *context);

    static void ExecRequest(RequestContext *context);

    static std::string MakeUrl(const std::string &url, std::string param, const std::string &extraParam);

    static bool MethodForGet(const std::string &method);

    static bool MethodForPost(const std::string &method);

    static bool EncodeUrlParam(std::string &str);

    static bool Initialize();

    static bool IsInitialized();

    static void DeInitialize();

    struct StaticContextVec {
        StaticContextVec() = default;
        ~StaticContextVec() = default;
        std::mutex mutexForContextVec;
        std::set<RequestContext *> contextSet;
    };
    static StaticContextVec staticContextSet_;

private:
    static bool SetOption(CURL *curl, RequestContext *context, struct curl_slist *requestHeader);

    static bool SetOtherOption(CURL *curl, RequestContext *context);

    static bool SetRequestOption(CURL *curl, RequestContext *context);

    static bool SetServerSSLCertOption(CURL *curl, OHOS::NetStack::Http::RequestContext *context);

    static bool SetSSLCertOption(CURL *curl, RequestContext *context);

    static bool SetDnsOption(CURL *curl, RequestContext *context);

    static size_t OnWritingMemoryBody(const void *data, size_t size, size_t memBytes, void *userData);

    static size_t OnWritingMemoryHeader(const void *data, size_t size, size_t memBytes, void *userData);

    static struct curl_slist *MakeHeaders(const std::vector<std::string> &vec);

    static bool IsUnReserved(unsigned char in);

    static bool AddCurlHandle(CURL *handle, RequestContext *context);

    static void HandleCurlData(CURLMsg *msg);

    static bool GetCurlDataFromHandle(CURL *handle, RequestContext *context, CURLMSG curlMsg, CURLcode result);

    static double GetTimingFromCurl(CURL *handle, CURLINFO info);

    static void CacheCurlPerformanceTiming(CURL *handle, RequestContext *context);

    static void RunThread();

    static void SendRequest();

    static void ReadResponse();

    static void GetGlobalHttpProxyInfo(std::string &host, int32_t &port, std::string &exclusions);

    static void GetHttpProxyInfo(RequestContext *context, std::string &host, int32_t &port, std::string &exclusions);

    static int ProgressCallback(void *userData, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal,
                                curl_off_t ulnow);

    static bool SetMultiPartOption(CURL *curl, RequestContext *context);

    static void SetFormDataOption(MultiFormData &multiFormData, curl_mimepart *part,
                                  CURL *curl, RequestContext *context);

    static void AddRequestInfo();

    static bool IsContextDeleted(RequestContext *context);

    struct RequestInfo {
        RequestInfo() = delete;
        ~RequestInfo() = default;

        RequestInfo(RequestContext *c, CURL *h) : context(c), handle(h) {};

        RequestContext *context;
        CURL *handle;

        bool operator<(const RequestInfo &info) const
        {
            return context->options.GetPriority() < info.context->options.GetPriority();
        }

        bool operator>(const RequestInfo &info) const
        {
            return context->options.GetPriority() > info.context->options.GetPriority();
        }
    };

    struct StaticVariable {
        StaticVariable() : curlMulti(nullptr), initialized(false), runThread(true) {}

        ~StaticVariable()
        {
            if (NetHttpClientExec::IsInitialized()) {
                NetHttpClientExec::DeInitialize();
            }
        }

        std::mutex curlMultiMutex;
        std::mutex mutexForInitialize;
        CURLM *curlMulti;
        std::map<CURL *, RequestContext *> contextMap;
        std::thread workThread;
        std::condition_variable conditionVariable;
        std::priority_queue<RequestInfo> infoQueue;

#ifndef MAC_PLATFORM
        std::atomic_bool initialized;
        std::atomic_bool runThread;
#else
        bool initialized;
        bool runThread;
#endif
    };
    static StaticVariable staticVariable_;
};
}
#endif