/*
* Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef REQUEST_PRE_DOWNLOAD_WRAPPER_H
#define REQUEST_PRE_DOWNLOAD_WRAPPER_H

#include <memory>

#include "cxx.h"
#include "http_client.h"
#include "http_client_request.h"
#include "http_client_response.h"
#include "http_client_task.h"
namespace OHOS::Request {
using namespace OHOS::NetStack::HttpClient;
struct CallbackWrapper;
struct PerformanceInfoRust;
struct ClientCert;
struct EscapedDataRust;
struct MultiFormDataRust;
struct ServerAuthentication;
struct TlsConfigRust;
struct HttpProxyRust;

void OnCallback(const std::shared_ptr<HttpClientTask> &task, rust::Box<CallbackWrapper> callback);

inline std::unique_ptr<HttpClientRequest> NewHttpClientRequest()
{
    return std::make_unique<HttpClientRequest>();
}

inline void SetBody(HttpClientRequest &request, const uint8_t *data, size_t size)
{
    request.SetBody(data, size);
}

inline void SetHttpProtocol(HttpClientRequest &request, int32_t protocol)
{
    request.SetHttpProtocol(static_cast<HttpProtocol>(protocol));
}

void SetUsingHttpProxyType(HttpClientRequest &request, int32_t type);
void SetSpecifiedHttpProxy(HttpClientRequest &request, const HttpProxyRust& proxy);
void SetAddressFamily(HttpClientRequest &request, int32_t address_family);
void SetExtraData(HttpClientRequest &request, const EscapedDataRust& extraData);
void SetExpectDataType(HttpClientRequest &request, int32_t expect_data_type);

void SetClientCert(HttpClientRequest &request, const ClientCert& cert);

void SetDNSServers(HttpClientRequest &request, const rust::vec<rust::string>& cert);

void AddMultiFormData(HttpClientRequest &request, const MultiFormDataRust &data);

void SetServerAuthentication(HttpClientRequest &request, const ServerAuthentication& server_auth);

void SetTLSOptions(HttpClientRequest &request, const TlsConfigRust &tls_options);

inline std::shared_ptr<HttpClientTask> NewHttpClientTask(const HttpClientRequest &request)
{
    auto &session = NetStack::HttpClient::HttpSession::GetInstance();
    return session.CreateTask(request);
}

rust::vec<rust::string> GetHeaders(HttpClientResponse &response);

PerformanceInfoRust GetPerformanceTiming(HttpClientResponse &response);

void SetHeaderExt(HttpClientRequest &request, const EscapedDataRust& extraData);

void SetCertificatePinning(HttpClientRequest &request, const std::string& certPIN);

} // namespace OHOS::Request

#endif