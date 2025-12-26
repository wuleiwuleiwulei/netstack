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

#include "wrapper.h"

#include <memory>
#include <sstream>
#include "cJSON.h"
#include "http_client_error.h"
#include "wrapper.rs.h"
#include "http_client_request.h"
#include "http_client_constant.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"

namespace OHOS::Request {
using namespace OHOS::NetStack::HttpClient;
static const int32_t ADDRESS_FAMILY_DEFAULT = 0;
static const int32_t ADDRESS_FAMILY_ONLY_V4 = 1;
static const int32_t ADDRESS_FAMILY_ONLY_V6 = 2;

void OnRequestStyleCallback(const std::shared_ptr<HttpClientTask> &task, const std::shared_ptr<CallbackWrapper> &shared)
{
    if (task == nullptr || shared == nullptr) {
        return;
    }
    auto weak = task->weak_from_this();
    task->OnSuccess([shared, weak](const HttpClientRequest &request, const HttpClientResponse &response) {
        bool isRequestInStream = false;
        auto httpTask = weak.lock();
        if (httpTask != nullptr) {
            isRequestInStream = httpTask->IsRequestInStream();
        }
        shared->on_success(request, response, isRequestInStream);
    });
    task->OnFail([shared, weak](const HttpClientRequest &request, const HttpClientResponse &response,
                     const HttpClientError &error) {
        bool isRequestInStream = false;
        auto httpTask = weak.lock();
        if (httpTask != nullptr) {
            isRequestInStream = httpTask->IsRequestInStream();
        }
        shared->on_fail(request, response, error, isRequestInStream);
    });
    task->OnCancel([shared, weak](const HttpClientRequest &request, const HttpClientResponse &response) {
        bool isRequestInStream = false;
        auto httpTask = weak.lock();
        if (httpTask != nullptr) {
            isRequestInStream = httpTask->IsRequestInStream();
        }
        shared->on_cancel(request, response, isRequestInStream);
    });
}

void OnCallback(const std::shared_ptr<HttpClientTask> &task, rust::Box<CallbackWrapper> callback)
{
    if (task == nullptr) {
        return;
    }
    auto weak = task->weak_from_this();
    CallbackWrapper *raw_ptr = callback.into_raw();
    auto shared = std::shared_ptr<CallbackWrapper>(
        raw_ptr, [](CallbackWrapper *ptr) { rust::Box<CallbackWrapper>::from_raw(ptr); });
    OnRequestStyleCallback(task, shared);
    task->OnDataReceive([shared, weak](const HttpClientRequest &, const uint8_t *data, size_t size) {
        auto httpTask = weak.lock();
        if (httpTask != nullptr) {
            shared->on_data_receive(httpTask, data, size);
        }
    });
    task->OnProgress([shared](const HttpClientRequest &, u_long dlTotal, u_long dlNow, u_long ulTotal, u_long ulNow) {
        shared->on_progress(dlTotal, dlNow, ulTotal, ulNow);
    });
    task->OnHeadersReceive([shared](const HttpClientRequest &, std::map<std::string, std::string> headers) {
        if (shared == nullptr || headers.empty()) {
            return;
        }
        rust::vec<rust::string> ret;
        for (auto header : headers) {
            if (header.first.empty() || header.second.empty()) {
                continue;
            }
            ret.emplace_back(header.first);
            ret.emplace_back(header.second);
        }
        shared->on_headers_receive(ret);
    });
    task->OnHeaderReceive([shared](const HttpClientRequest &, const std::string &header) {
        if (shared == nullptr || header.empty()) {
            return;
        }
        shared->on_header_receive(header);
    });
};

rust::vec<rust::string> GetHeaders(HttpClientResponse &response)
{
    rust::vec<rust::string> ret;

    if (response.GetHeaders().empty()) {
        response.ParseHeaders();
    }
    std::map<std::string, std::string> headers = response.GetHeaders();
    for (auto header : headers) {
        ret.emplace_back(header.first);
        ret.emplace_back(header.second);
    }
    return ret;
};

PerformanceInfoRust GetPerformanceTiming(HttpClientResponse &response)
{
    PerformanceInfoRust info = {
        .dns_timing = response.GetPerformanceTiming().dnsTiming,
        .tcp_timing = response.GetPerformanceTiming().connectTiming,
        .tls_timing = response.GetPerformanceTiming().tlsTiming,
        .first_send_timing = response.GetPerformanceTiming().firstSendTiming,
        .first_receive_timing = response.GetPerformanceTiming().firstReceiveTiming,
        .total_timing = response.GetPerformanceTiming().totalTiming,
        .redirect_timing = response.GetPerformanceTiming().redirectTiming,
    };
    return info;
}

void SetAddressFamily(HttpClientRequest &request, int32_t addressFamily)
{
    switch (addressFamily) {
        case ADDRESS_FAMILY_DEFAULT:
            request.SetAddressFamily("DEFAULT");
            break;
        case ADDRESS_FAMILY_ONLY_V4:
            request.SetAddressFamily("ONLY_V4");
            break;
        case ADDRESS_FAMILY_ONLY_V6:
            request.SetAddressFamily("ONLY_V6");
            break;
        default:
            break;
    }
}

void SetExtraData(HttpClientRequest &request, const EscapedDataRust& extraData)
{
    EscapedData nativeValue = {
        .dataType = extraData.data_type,
        .data = std::string(extraData.data.data(), extraData.data.size()),
    };
    request.SetExtraData(nativeValue);
}

void SetExpectDataType(HttpClientRequest &request, int32_t type)
{
    request.SetExpectDataType(static_cast<HttpDataType>(type));
}

void SetClientCert(HttpClientRequest &request, const ClientCert& cert)
{
    HttpClientCert clientCert;

    clientCert.certPath = std::string(cert.cert_path.data(), cert.cert_path.size());
    clientCert.keyPath = std::string(cert.key_path.data(), cert.key_path.size());
    clientCert.keyPassword = std::string(cert.key_password.data(), cert.key_password.size());
    
    switch (cert.cert_type) {
        case CertType::Pem:
            clientCert.certType = "Pem";
            break;
        case CertType::Der:
            clientCert.certType = "Der";
            break;
        case CertType::P12:
            clientCert.certType = "P12";
            break;
    }
    request.SetClientCert(clientCert);
}

void SetDNSServers(HttpClientRequest &request, const rust::vec<rust::string>& servers)
{
    std::vector<std::string> dnsServers;

    dnsServers.reserve(servers.size());
    for (const auto& s : servers) {
        dnsServers.push_back(std::string(s.data(), s.size()));
    }
    request.SetDNSServers(dnsServers);
}

void AddMultiFormData(HttpClientRequest &request, const MultiFormDataRust &item)
{
    HttpMultiFormData nativeValue = {
        .name = std::string(item.name.data(), item.name.size()),
        .contentType = std::string(item.content_type.data(), item.content_type.size()),
        .remoteFileName = std::string(item.remote_file_name.data(), item.remote_file_name.size()),
        .data = std::string(item.data.data(), item.data.size()),
        .filePath = std::string(item.file_path.data(), item.file_path.size())
    };
    request.AddMultiFormData(nativeValue);
}

void SetServerAuthentication(HttpClientRequest &request, const ServerAuthentication& server_auth)
{
    HttpServerAuthentication serverAuth;
    serverAuth.credential.username.append(server_auth.username.data(), server_auth.username.size());
    serverAuth.credential.password.append(server_auth.password.data(), server_auth.password.size());
    auto authenticationType =
        std::string(server_auth.authentication_type.data(), server_auth.authentication_type.size());
    if (authenticationType == "basic") {
        serverAuth.authenticationType = HttpAuthenticationType::BASIC;
    } else if (authenticationType == "ntlm") {
        serverAuth.authenticationType = HttpAuthenticationType::NTLM;
    } else if (authenticationType == "digest") {
        serverAuth.authenticationType = HttpAuthenticationType::DIGEST;
    }
    request.SetServerAuthentication(serverAuth);
}

void SetTLSOptions(HttpClientRequest &request, const TlsConfigRust &tls_options)
{
    TlsOption tlsOption;
    tlsOption.tlsVersionMin = static_cast<TlsVersion>(tls_options.tls_version_min);
    tlsOption.tlsVersionMax = static_cast<TlsVersion>(tls_options.tls_version_max);
    for (const auto &element : tls_options.cipher_suites) {
        std::string nativeValue(element.data(), element.size());
        auto cipherSuite = GetTlsCipherSuiteFromStandardName(nativeValue);
        if (cipherSuite != CipherSuite::INVALID) {
            tlsOption.cipherSuite.emplace(cipherSuite);
        }
    }
    request.SetTLSOptions(tlsOption);
}

void SetUsingHttpProxyType(HttpClientRequest &request, int32_t type)
{
    if (type < HttpProxyType::NOT_USE || type > HttpProxyType::PROXY_TYPE_MAX) {
        return;
    }
    request.SetHttpProxyType(static_cast<HttpProxyType>(type));
}

void SetSpecifiedHttpProxy(HttpClientRequest &request, const HttpProxyRust& proxy)
{
    HttpProxy nativeValue;
    nativeValue.host = std::string(proxy.host.data(), proxy.host.size());
    nativeValue.port = proxy.port;
    nativeValue.exclusions = std::string(proxy.exclusions.data(), proxy.exclusions.size());
    request.SetHttpProxy(nativeValue);
}

std::string GetJsonFieldValue(const cJSON* item)
{
    std::string result;
    if (item == nullptr) {
        return result;
    }
    std::stringstream ss;
    switch (item->type) {
        case cJSON_String:
            ss << item->valuestring;
            break;
        case cJSON_Number:
            ss << item->valuedouble;
            break;
        case cJSON_True:
            ss << "true";
            break;
        case cJSON_False:
            ss << "false";
            break;
        case cJSON_NULL:
            ss << "null";
            break;
        default:
            NETSTACK_LOGE("unknown type");
    }
    result = ss.str();
    return result;
}

void ParseHeaderItems(const cJSON *item, HttpClientRequest &request)
{
    if (item == nullptr) {
        return;
    }
    if (item->type == cJSON_Object) {
        cJSON *child = item->child;
        while (child != nullptr) {
            if (child->type == cJSON_Object || child->type == cJSON_Array) {
                ParseHeaderItems(child, request);
            }
            std::string key(child->string);
            std::string value = GetJsonFieldValue(child);
            if (!key.empty() && !value.empty()) {
                request.SetHeader(NetStack::CommonUtils::ToLower(key), value);
            }
            child = child->next;
        }
    } else if (item->type == cJSON_Array) {
        auto size = cJSON_GetArraySize(item);
        for (int i = 0; i < size; ++i) {
            cJSON *arrayItem = cJSON_GetArrayItem(item, i);
            ParseHeaderItems(arrayItem, request);
        }
    }
}

void SetHeaderExt(HttpClientRequest &request, const EscapedDataRust& headersObj)
{
    if (request.MethodForPost(request.GetMethod())) {
        request.SetHeader(NetStack::CommonUtils::ToLower(HttpConstant::HTTP_CONTENT_TYPE),
            HttpConstant::HTTP_CONTENT_TYPE_JSON);
    }
    if (headersObj.data_type != HttpDataType::OBJECT) {
        return;
    }
    auto jsonStr = std::string(headersObj.data.data(), headersObj.data.size());
    cJSON *root = cJSON_Parse(jsonStr.c_str());
    if (root == nullptr) {
        NETSTACK_LOGE("json parse failed");
        return;
    }
    ParseHeaderItems(root, request);
    cJSON_Delete(root);
}

void SetCertificatePinning(HttpClientRequest &request, const std::string& certPIN)
{
    if (certPIN.empty()) {
        return;
    }

    SecureData certificatePinningNative;
    certificatePinningNative.append(certPIN.c_str());
    request.SetCertificatePinning(certificatePinningNative);
}
} // namespace OHOS::Request
