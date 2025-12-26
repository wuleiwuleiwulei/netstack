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

#ifndef NET_HTTP_CACHE_REQUEST_H
#define NET_HTTP_CACHE_REQUEST_H

#include <cstring>
#include <iostream>
#include <map>

#include "constant.h"
#include "net_http_utils.h"

namespace OHOS::NetStack::Http {
class HttpCacheRequest {
public:
    HttpCacheRequest();

    ~HttpCacheRequest();

    void ParseRequestHeader(const std::map<std::string, std::string> &requestHeader);

    void SetRequestTime(const std::string &requestTime);

    [[nodiscard]] time_t GetIfModifiedSince() const;

    [[nodiscard]] time_t GetRequestTime() const;

    [[nodiscard]] time_t GetMaxAgeSeconds() const;

    [[nodiscard]] time_t GetMaxStaleSeconds() const;

    [[nodiscard]] time_t GetMinFreshSeconds() const;

    [[nodiscard]] bool IsNoCache() const;

    [[nodiscard]] bool IsNoStore() const;

    [[nodiscard]] bool IsNoTransform() const;

    [[nodiscard]] bool IsOnlyIfCached() const;

    [[nodiscard]] std::string GetIfNoneMatch() const;

private:
    void ParseCacheControl(const std::string &cacheControl);

private:
    std::string requestTime_;
    std::string ifModifiedSince_;
    std::string ifNoneMatch_;

    std::string maxAge_;
    std::string maxStale_;
    std::string minFresh_;

    bool noCache_ = false;
    bool noStore_ = false;
    bool noTransform_ = false;
    bool onlyIfCached_ = false;
};


class HttpCacheResponse {
public:
    HttpCacheResponse();

    ~HttpCacheResponse();

    void ParseCacheResponseHeader(const std::map<std::string, std::string> &cacheResponseHeader);

    [[nodiscard]] time_t GetDate() const;

    [[nodiscard]] time_t GetExpires() const;

    [[nodiscard]] time_t GetLastModified() const;

    [[nodiscard]] std::string GetLastModifiedStr() const;

    [[nodiscard]] std::string GetDateStr() const;

    [[nodiscard]] std::string GetEtag() const;

    [[nodiscard]] std::string GetAge() const;

    [[nodiscard]] time_t GetAgeSeconds() const;

    [[nodiscard]] time_t GetResponseTime() const;

    [[nodiscard]] bool IsMustRevalidate() const;

    [[nodiscard]] bool IsNoCache() const;

    [[nodiscard]] bool IsNoStore() const;

    [[nodiscard]] bool IsPublicCache() const;

    [[nodiscard]] bool IsPrivateCache() const;

    [[nodiscard]] bool IsProxyRevalidate() const;

    [[nodiscard]] bool IsNoTransform() const;

    [[nodiscard]] time_t GetMaxAgeSeconds() const;

    [[nodiscard]] time_t GetSMaxAgeSeconds() const;

    [[nodiscard]] ResponseCode GetRespCode() const;

    void SetRespCode(ResponseCode respCode);

    void SetResponseTime(const std::string &responseTime);

    void SetRequestTime(const std::string &requestTime);

    [[nodiscard]] time_t GetRequestTime() const;

private:
    void ParseCacheControl(const std::string &cacheControl);

    std::string date_;
    std::string expires_;
    std::string lastModified_;
    std::string etag_;
    std::string age_;
    std::string responseTime_;
    std::string requestTime_;

    bool mustRevalidate_;
    bool noCache_;
    bool noStore_;
    bool publicCache_;
    bool privateCache_;
    bool proxyRevalidate_;
    bool noTransform_;

    std::string maxAge_;
    std::string sMaxAge_;

    ResponseCode respCode_;
};
} // namespace OHOS::NetStack::Http
#endif // NET_HTTP_CACHE_REQUEST_H
