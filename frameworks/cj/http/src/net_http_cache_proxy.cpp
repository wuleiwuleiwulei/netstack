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

#include "net_http_cache_proxy.h"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <array>

#include "netstack_log.h"
#include "netstack_common_utils.h"

static constexpr const char *CACHE_FILE = "/data/storage/el2/base/cache/cache.json";
static constexpr int32_t WRITE_INTERVAL = 60;

namespace OHOS::NetStack::Http {
std::mutex cj_diskCacheMutex;
std::mutex cj_cacheNeedRunMutex;
std::atomic_bool cj_cacheNeedRun(false);
std::atomic_bool cj_cacheIsRunning(false);
std::condition_variable cj_cacheThreadCondition;
std::condition_variable cj_cacheNeedRunCondition;
static LRUCacheDiskHandler g_cjDiskLruCache(CACHE_FILE, 0); // NOLINT(cert-err58-cpp)

CacheProxy::CacheProxy(HttpRequest &requestOptions) : strategy_(requestOptions)
{
    std::string str = requestOptions.GetUrl() + HTTP_LINE_SEPARATOR +
                      CommonUtils::ToLower(requestOptions.GetMethod()) + HTTP_LINE_SEPARATOR;
    for (const auto &p : requestOptions.GetHeader()) {
        str += p.first + HTTP_HEADER_SEPARATOR + p.second + HTTP_LINE_SEPARATOR;
    }
    str += std::to_string(requestOptions.GetHttpVersion());
    key_ = Encode(str);
}

bool CacheProxy::ReadResponseFromCache(RequestContext *context)
{
    if (!cj_cacheIsRunning.load()) {
        return false;
    }

    if (!strategy_.CouldUseCache()) {
        NETSTACK_LOGI("only GET/HEAD method or header has [Range] can use cache");
        return false;
    }

    auto responseFromCache = g_cjDiskLruCache.Get(key_);
    if (responseFromCache.empty()) {
        NETSTACK_LOGI("no cache with this request");
        return false;
    }
    HttpResponse cachedResponse;
    cachedResponse.SetRawHeader(Decode(responseFromCache[RESPONSE_KEY_HEADER]));
    cachedResponse.SetResult(Decode(responseFromCache[RESPONSE_KEY_RESULT]));
    cachedResponse.SetCookies(Decode(responseFromCache[RESPONSE_KEY_COOKIES]));
    cachedResponse.SetResponseTime(Decode(responseFromCache[RESPONSE_TIME]));
    cachedResponse.SetRequestTime(Decode(responseFromCache[REQUEST_TIME]));
    cachedResponse.SetResponseCode(static_cast<uint32_t>(ResponseCode::OK));
    cachedResponse.ParseHeaders();

    CacheStatus status = strategy_.RunStrategy(cachedResponse);
    if (status == CacheStatus::FRESH) {
        context->response = cachedResponse;
        NETSTACK_LOGI("cache is FRESH");
        return true;
    }
    if (status == CacheStatus::STALE) {
        NETSTACK_LOGI("cache is STATE, we try to talk to the server");
        context->SetCacheResponse(cachedResponse);
        return false;
    }
    NETSTACK_LOGI("cache should not be used");
    return false;
}

void CacheProxy::WriteResponseToCache(const HttpResponse &response)
{
    if (!cj_cacheIsRunning.load()) {
        return;
    }

    if (!strategy_.IsCacheable(response)) {
        NETSTACK_LOGE("do not cache this response");
        return;
    }
    std::unordered_map<std::string, std::string> cacheResponse;
    cacheResponse[RESPONSE_KEY_HEADER] = Encode(response.GetRawHeader());
    cacheResponse[RESPONSE_KEY_RESULT] = Encode(response.GetResult());
    cacheResponse[RESPONSE_KEY_COOKIES] = Encode(response.GetCookies());
    cacheResponse[RESPONSE_TIME] = Encode(response.GetResponseTime());
    cacheResponse[REQUEST_TIME] = Encode(response.GetRequestTime());

    g_cjDiskLruCache.Put(key_, cacheResponse);
}

void CacheProxy::RunCache()
{
    RunCacheWithSize(MAX_DISK_CACHE_SIZE);
}

void CacheProxy::RunCacheWithSize(size_t capacity)
{
    if (cj_cacheIsRunning.load()) {
        return;
    }
    g_cjDiskLruCache.SetCapacity(capacity);

    cj_cacheNeedRun.store(true);

    g_cjDiskLruCache.ReadCacheFromJsonFile();

    std::thread([]() {
        cj_cacheIsRunning.store(true);
        while (cj_cacheNeedRun.load()) {
            std::unique_lock<std::mutex> lock(cj_cacheNeedRunMutex);
            cj_cacheNeedRunCondition.wait_for(lock, std::chrono::seconds(WRITE_INTERVAL),
                [] { return !cj_cacheNeedRun.load(); });

            g_cjDiskLruCache.WriteCacheToJsonFile();
        }

        cj_cacheIsRunning.store(false);
        cj_cacheThreadCondition.notify_all();
    }).detach();
}

void CacheProxy::FlushCache()
{
    if (!cj_cacheIsRunning.load()) {
        return;
    }
    g_cjDiskLruCache.WriteCacheToJsonFile();
}

void CacheProxy::StopCacheAndDelete()
{
    if (!cj_cacheIsRunning.load()) {
        return;
    }
    cj_cacheNeedRun.store(false);
    cj_cacheNeedRunCondition.notify_all();

    std::unique_lock<std::mutex> lock(cj_diskCacheMutex);
    cj_cacheThreadCondition.wait(lock, [] { return !cj_cacheIsRunning.load(); });
    g_cjDiskLruCache.Delete();
}
} // namespace OHOS::NetStack::Http
