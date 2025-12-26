/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_REQUEST_CONTEXT_H
#define COMMUNICATIONNETSTACK_REQUEST_CONTEXT_H

#include <queue>
#include <mutex>
#include <map>
#include "curl/curl.h"
#include "base_context.h"
#include "http_request_options.h"
#include "http_response.h"
#include "hi_app_event_report.h"
#include "timing.h"
#if HAS_NETMANAGER_BASE
#include "netstack_network_profiler.h"
#endif
#include "request_tracer.h"
#if ENABLE_HTTP_INTERCEPT
#include "http_interceptor.h"
#endif
#ifdef HTTP_HANDOVER_FEATURE
struct HttpHandoverInfo;
#endif

namespace OHOS::NetStack::Http {
static constexpr const uint32_t MAGIC_NUMBER = 0x86161616;
struct LoadBytes {
    LoadBytes() : nLen(0), tLen(0){};
    LoadBytes(curl_off_t nowLen, curl_off_t totalLen)
    {
        nLen = nowLen;
        tLen = totalLen;
    };
    ~LoadBytes() = default;
    curl_off_t nLen;
    curl_off_t tLen;
};

struct CertsPath {
    CertsPath() = default;
    ~CertsPath() = default;
    std::vector<std::string> certPathList;
    std::string certFile;
};

#if ENABLE_HTTP_INTERCEPT
class HttpInterceptor;
#endif

class RequestContext final : public BaseContext {
public:
    friend class HttpExec;

    RequestContext() = delete;

    RequestContext(napi_env env, const std::shared_ptr<EventManager> &manager);

    ~RequestContext() override;

    void StartTiming();

    void ParseParams(napi_value *params, size_t paramsCount) override;

#if ENABLE_HTTP_INTERCEPT
    void SetInterceptorRefs(const std::map<std::string, napi_ref> &interceptorRefs);

    HttpInterceptor *GetInterceptor();
#endif

    HttpRequestOptions options;

    HttpResponse response;

    [[nodiscard]] bool IsUsingCache() const;

    void SetCurlHeaderList(curl_slist *curlHeaderList);

    curl_slist *GetCurlHeaderList();

    void SetCacheResponse(const HttpResponse &cacheResponse);

    void SetResponseByCache();

    [[nodiscard]] int32_t GetErrorCode() const override;

    [[nodiscard]] std::string GetErrorMessage() const override;

    void EnableRequestInStream();

    [[nodiscard]] bool IsRequestInStream() const;

    void SetDlLen(curl_off_t nowLen, curl_off_t totalLen);

    LoadBytes GetDlLen();

    void SetUlLen(curl_off_t nowLen, curl_off_t totalLen);

    LoadBytes GetUlLen();

    bool CompareWithLastElement(curl_off_t nowLen, curl_off_t totalLen);

    void SetTempData(const void *data, size_t size);

    std::string GetTempData();

    void PopTempData();

    void ParseClientCert(napi_value optionsValue);

    void ParseRemoteValidationMode(napi_value optionsValue);

    void ParseTlsOption(napi_value optionsValue);

    void ParseServerAuthentication(napi_value optionsValue);

    void CachePerformanceTimingItem(const std::string &key, double value);

    void StopAndCacheNapiPerformanceTiming(const char *key);

    void SetPerformanceTimingToResult(napi_value result);

    void SetMultipart(curl_mime *multipart);

    void SetCertsPath(std::vector<std::string> &&certPathList, const std::string &certFile);

    const CertsPath &GetCertsPath();

    [[nodiscard]] int32_t GetTaskId() const;

    void SetModuleId(uint64_t moduleId);

    uint64_t GetModuleId() const;

    void SetCurlHostList(curl_slist *curlHostList);

    [[nodiscard]] curl_slist *GetCurlHostList();

    void SetAtomicService(bool isAtomicService);

    [[nodiscard]] bool IsAtomicService() const;

    void SetBundleName(const std::string &bundleName);

    [[nodiscard]] std::string GetBundleName() const;

    void SetCurlHandle(CURL *handle);

    CURL *GetCurlHandle();

    void SendNetworkProfiler();

    RequestTracer::Trace &GetTrace();

    bool IsRootCaVerified() const;

    void SetRootCaVerified();

    bool IsRootCaVerifiedOk() const;

    void SetRootCaVerifiedOk(bool ok);

    void SetPinnedPubkey(std::string &pubkey);

    std::string GetPinnedPubkey() const;

    void IncreaseRedirectCount();

    [[nodiscard]] bool IsReachRedirectLimit();

    std::map<std::string, napi_ref> interceptorRefs_;

#ifdef HTTP_HANDOVER_FEATURE
    void SetRequestHandoverInfo(const HttpHandoverInfo &httpHandoverInfo);
 
    std::string GetRequestHandoverInfo();
#endif
private:
    uint32_t magicNumber_ = MAGIC_NUMBER;
    int32_t taskId_ = -1;
    bool usingCache_ = true;
    bool requestInStream_ = false;
    std::mutex dlLenLock_;
    std::mutex ulLenLock_;
    std::mutex tempDataLock_;
    std::queue<std::string> tempData_;
    HttpResponse cacheResponse_;
    std::queue<LoadBytes> dlBytes_;
    std::queue<LoadBytes> ulBytes_;
    curl_slist *curlHeaderList_ = nullptr;
    Timing::TimerMap timerMap_;
    std::map<std::string, double> performanceTimingMap_;
    curl_mime *multipart_ = nullptr;
    CertsPath certsPath_;
    uint64_t moduleId_ = 0;
    curl_slist *curlHostList_ = nullptr;
    bool isAtomicService_ = false;
    std::string bundleName_;
    bool isRootCaVerified_ = false;
    bool isRootCaVerifiedOk_ = false;
    std::string pinnedPubkey_;
    uint32_t redirects_ = 0;
#if HAS_NETMANAGER_BASE
    std::unique_ptr<NetworkProfilerUtils> networkProfilerUtils_;
#endif
    CURL *curlHandle_ = nullptr;
#ifdef HTTP_HANDOVER_FEATURE
    std::string httpHandoverInfoStr_ = "no handover";
#endif
#if ENABLE_HTTP_INTERCEPT
    std::unique_ptr<HttpInterceptor> interceptor_ = nullptr;
#endif

    RequestTracer::Trace trace_;

    bool CheckParamsType(napi_value *params, size_t paramsCount);

    void ParseNumberOptions(napi_value optionsValue);

    void ParseHeader(napi_value optionsValue);

    bool ParseExtraData(napi_value optionsValue);

    void ParseUsingHttpProxy(napi_value optionsValue);

    void ParseCaPath(napi_value optionsValue);

    void ParseCaData(napi_value optionsValue);

    void ParseDnsServers(napi_value optionsValue);

    void ParseMultiFormData(napi_value optionsValue);

    void ParseDohUrl(napi_value optionsValue);

    void ParseResumeFromToNumber(napi_value optionsValue);

    void ParseCertificatePinning(napi_value optionsValue);

    bool GetRequestBody(napi_value extraData);

    void UrlAndOptions(napi_value urlValue, napi_value optionsValue);

    bool HandleMethodForGet(napi_value extraData);

    MultiFormData NapiValue2FormData(napi_value formDataValue);

    CertificatePinning NapiValue2CertPinning(napi_value certPIN);

    void SaveFormData(napi_env env, napi_value dataValue, MultiFormData &multiFormData);

    void ParseAddressFamily(napi_value optionsValue);

    void ParseSslType(napi_value optionsValue);

    void ParseClientEncCert(napi_value optionsValue);

    void ParseMaxRedirects(napi_value optionsValue);
};
} // namespace OHOS::NetStack::Http

#endif /* COMMUNICATIONNETSTACK_REQUEST_CONTEXT_H */
