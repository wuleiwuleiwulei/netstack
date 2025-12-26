/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef HTTP_CLIENT_CACHE_STRATEGY_H
#define HTTP_CLIENT_CACHE_STRATEGY_H

#include <cstring>
#include <iostream>
#include <tuple>

#include "http_cache_request.h"
#include "http_cache_response.h"
#include "http_client_request.h"
#include "http_client_response.h"

namespace OHOS::NetStack::HttpClient {
enum CacheStatus {
    FRESH,
    STALE,
    DENY
};

class HttpCacheStrategy {
public:
    HttpCacheStrategy() = delete;

    explicit HttpCacheStrategy(HttpClientRequest &requestOptions);

    CacheStatus RunStrategy(HttpClientResponse &response);

    bool IsCacheable(const HttpClientResponse &response);

    bool CouldUseCache();

private:
    CacheStatus RunStrategyInternal(HttpClientResponse &response);

    bool IsCacheable(const HttpCacheResponse &cacheResponse);

    int64_t CacheResponseAgeMillis();

    std::tuple<int64_t, int64_t, int64_t, int64_t> GetFreshness();

    int64_t ComputeFreshnessLifetimeMillis();

    int64_t ComputeFreshnessLifetimeSecondsInternal();

    void UpdateRequestHeader(const std::string &etag, const std::string &lastModified, const std::string &date);

    HttpClientRequest &requestOptions_;

    HttpCacheResponse cacheResponse_;

    HttpCacheRequest cacheRequest_;
};
} // namespace OHOS::NetStack::HttpClient
#endif /* HTTP_CLIENT_CACHE_STRATEGY_H */
