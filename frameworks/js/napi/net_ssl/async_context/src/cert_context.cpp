/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "cert_context.h"

#include <map>
#include <node_api.h>
#include <openssl/ssl.h>

#include "napi_utils.h"
#include "net_ssl_exec.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "net_ssl_verify_cert.h"
#if HAS_NETMANAGER_BASE
#include "net_conn_client.h"
#endif // HAS_NETMANAGER_BASE

static constexpr const int PARAM_JUST_CERT = 1;

static constexpr const int PARAM_CERT_AND_CACERT = 2;

namespace OHOS::NetStack::Ssl {

static const std::map<int32_t, const char *> SSL_ERR_MAP = {
    {SslErrorCode::SSL_NONE_ERR, "Verify success."},
    {SslErrorCode::SSL_X509_V_ERR_UNSPECIFIED, "Unspecified error."},
    {SslErrorCode::SSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT, "Unable to get issuer certificate."},
    {SslErrorCode::SSL_X509_V_ERR_UNABLE_TO_GET_CRL, "Unable to get certificate revocation list (CRL)."},
    {SslErrorCode::SSL_X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE, "Unable to decrypt certificate signature."},
    {SslErrorCode::SSL_X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE, "Unable to decrypt CRL signature."},
    {SslErrorCode::SSL_X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY, "Unable to decode issuer public key."},
    {SslErrorCode::SSL_X509_V_ERR_CERT_SIGNATURE_FAILURE, "Certificate signature failure."},
    {SslErrorCode::SSL_X509_V_ERR_CRL_SIGNATURE_FAILURE, "CRL signature failure."},
    {SslErrorCode::SSL_X509_V_ERR_CERT_NOT_YET_VALID, "Certificate is not yet valid."},
    {SslErrorCode::SSL_X509_V_ERR_CERT_HAS_EXPIRED, "Certificate has expired."},
    {SslErrorCode::SSL_X509_V_ERR_CRL_NOT_YET_VALID, "CRL is not yet valid."},
    {SslErrorCode::SSL_X509_V_ERR_CRL_HAS_EXPIRED, "CRL has expired."},
    {SslErrorCode::SSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, "unable to get local issuer certificate."},
    {SslErrorCode::SSL_X509_V_ERR_CERT_REVOKED, "Certificate has been revoked."},
    {SslErrorCode::SSL_X509_V_ERR_INVALID_CA, "Invalid certificate authority (CA)."},
    {SslErrorCode::SSL_X509_V_ERR_CERT_UNTRUSTED, "Certificate is untrusted."},
    {SslErrorCode::SSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, "self-signed certificate."},
    {SslErrorCode::SSL_X509_V_ERR_INVALID_CALL, "invalid certificate verification context."}
};

CertContext::CertContext(napi_env env, const std::shared_ptr<EventManager> &manager)
    : BaseContext(env, manager), certBlob_(nullptr), certBlobClient_(nullptr) {}

void CertContext::ParseParams(napi_value *params, size_t paramsCount)
{
    bool valid = CheckParamsType(params, paramsCount);
    if (valid) {
        if (paramsCount == PARAM_JUST_CERT) {
            certBlob_ = ParseCertBlobFromValue(GetEnv(), params[0]);
            SetParseOK(certBlob_ != nullptr);
        } else if (paramsCount == PARAM_CERT_AND_CACERT) {
            certBlob_ = ParseCertBlobFromValue(GetEnv(), params[0]);
            certBlobClient_ = ParseCertBlobFromValue(GetEnv(), params[1]);
            SetParseOK(certBlob_ != nullptr && certBlobClient_ != nullptr);
        }
    } else {
        SetErrorCode(PARSE_ERROR_CODE);
    }
}

bool CertContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_JUST_CERT) {
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_object;
    } else if (paramsCount == PARAM_CERT_AND_CACERT) {
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_object &&
               NapiUtils::GetValueType(GetEnv(), params[1]) == napi_object;
    }
    return false;
}

CertBlob *CertContext::ParseCertBlobFromValue(napi_env env, napi_value value)
{
    napi_value typeValue = nullptr;
    napi_value dataValue = nullptr;
    napi_get_named_property(env, value, "type", &typeValue);
    napi_get_named_property(env, value, "data", &dataValue);
    if (typeValue == nullptr || dataValue == nullptr) {
        SetErrorCode(PARSE_ERROR_CODE);
        return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
    }
    return ParseCertBlobFromData(env, value, typeValue, dataValue);
}

CertBlob *CertContext::ParseCertBlobFromData(napi_env env, napi_value value, napi_value typeValue, napi_value dataValue)
{
    size_t dataSize = 0;
    uint32_t type;
    uint32_t size = 0;
    uint8_t *data = nullptr;
    napi_get_value_uint32(env, typeValue, &type);
    CertType certType = static_cast<CertType>(type);
    if (certType == CERT_TYPE_PEM) {
        NETSTACK_LOGD("CERT_TYPE_PEM\n");
        napi_valuetype valueType;
        napi_typeof(env, dataValue, &valueType);
        if (valueType != napi_string) {
            NETSTACK_LOGE("pem but not string\n");
            return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
        }
        napi_get_value_string_utf8(env, dataValue, nullptr, 0, &dataSize);
        if (dataSize + 1 < SIZE_MAX / sizeof(uint8_t)) {
            data = new uint8_t[dataSize + 1];
            napi_get_value_string_utf8(env, dataValue, reinterpret_cast<char *>(data), dataSize + 1, &dataSize);
            size = static_cast<uint32_t>(dataSize);
        } else {
            return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
        }
    } else if (certType == CERT_TYPE_DER) {
        NETSTACK_LOGD("CERT_TYPE_DER\n");
        bool isArrayBuffer = false;
        napi_is_buffer(env, dataValue, &isArrayBuffer);
        if (!isArrayBuffer) {
            NETSTACK_LOGE("der but bot arraybuffer\n");
            return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
        }
        void *dataArray = nullptr;
        napi_get_arraybuffer_info(env, dataValue, &dataArray, &dataSize);
        if (dataSize < SIZE_MAX / sizeof(uint8_t)) {
            data = new uint8_t[dataSize];
            std::copy(static_cast<uint8_t *>(dataArray), static_cast<uint8_t *>(dataArray) + dataSize, data);
            size = static_cast<uint32_t>(dataSize);
        } else {
            return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
        }
    } else {
        return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
    }
    return new CertBlob{static_cast<CertType>(type), static_cast<uint32_t>(size), static_cast<uint8_t *>(data)};
}

CertBlob *CertContext::GetCertBlob()
{
    return certBlob_;
}

CertBlob *CertContext::GetCertBlobClient()
{
    return certBlobClient_;
}

int32_t CertContext::GetErrorCode() const
{
    auto errorCode = BaseContext::GetErrorCode();
    if (errorCode == PARSE_ERROR_CODE) {
        return PARSE_ERROR_CODE;
    }
#if HAS_NETMANAGER_BASE
    const auto &errorCodeSet =
        OHOS::NetManagerStandard::NetConnClient::IsAPIVersionSupported(CommonUtils::SdkVersion::TWELVE)
            ? SslErrorCodeSetSinceAPI12
            : SslErrorCodeSetBase;
#else
    const auto &errorCodeSet = SslErrorCodeSetSinceAPI12;
#endif
    if (errorCodeSet.find(errorCode) == errorCodeSet.end()) {
        errorCode = SSL_X509_V_ERR_UNSPECIFIED;
    }
    return errorCode;
}

std::string CertContext::GetErrorMessage() const
{
    auto err = BaseContext::GetErrorCode();
    if (err == PARSE_ERROR_CODE) {
        return PARSE_ERROR_MSG;
    }

    auto pos = SSL_ERR_MAP.find(err);
    if (pos != SSL_ERR_MAP.end()) {
        return pos->second;
    }
    return SSL_ERR_MAP.at(SslErrorCode::SSL_X509_V_ERR_CERT_UNTRUSTED);
}

CertContext::~CertContext()
{
    if (certBlob_ != nullptr) {
        if (certBlob_->data != nullptr) {
            delete[] certBlob_->data;
            certBlob_->data = nullptr;
        }
        delete certBlob_;
        certBlob_ = nullptr;
    }

    if (certBlobClient_ != nullptr) {
        if (certBlobClient_->data != nullptr) {
            delete[] certBlobClient_->data;
            certBlobClient_->data = nullptr;
        }
        delete certBlobClient_;
        certBlobClient_ = nullptr;
    }
    NETSTACK_LOGD("CertContext is destructed by the destructor");
}
} // namespace OHOS::NetStack::Ssl
