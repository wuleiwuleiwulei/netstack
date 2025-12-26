/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "tls_connect_context.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "constant.h"
#include "napi_utils.h"
#include "netstack_log.h"
#include "socket_constant.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
namespace {
constexpr const char *ALPN_PROTOCOLS = "ALPNProtocols";
constexpr const char *SECURE_OPTIONS = "secureOptions";
constexpr const char *CA_NAME = "ca";
constexpr const char *CERT_NAME = "cert";
constexpr const char *KEY_NAME = "key";
constexpr const char *PASSWD_NAME = "passwd";
constexpr const char *PROTOCOLS_NAME = "protocols";
constexpr const char *SIGNATURE_ALGORITHMS = "signatureAlgorithms";
constexpr const char *USE_REMOTE_CIPHER_PREFER = "useRemoteCipherPrefer";
constexpr const char *CIPHER_SUITE = "cipherSuite";
constexpr const char *ADDRESS_NAME = "address";
constexpr const char *FAMILY_NAME = "family";
constexpr const char *PORT_NAME = "port";
constexpr const char *VERIFY_MODE_NAME = "isBidirectionalAuthentication";
constexpr const char *SKIP_REMOTE_VALIDATION = "skipRemoteValidation";
constexpr const char *KEY_PROXY = "proxy";
constexpr const char *TIMEOUT = "timeout";
constexpr uint32_t CA_CHAIN_LENGTH = 1000;
constexpr uint32_t PROTOCOLS_SIZE = 10;
constexpr uint32_t CERT_CHAIN_LENGTH = 1000;
constexpr std::string_view PARSE_ERROR = "options is not type of TLSConnectOptions";

bool ReadCertOptions(napi_env &env, napi_value &secureOptions, TLSSecureOptions &secureOption)
{
    if (NapiUtils::HasNamedProperty(env, secureOptions, CERT_NAME)) {
        napi_value cert = NapiUtils::GetNamedProperty(env, secureOptions, CERT_NAME);
        std::vector<std::string> certVec;
        if (NapiUtils::GetValueType(env, cert) == napi_string) {
            std::string certificate = NapiUtils::GetStringPropertyUtf8(env, secureOptions, CERT_NAME);
            certVec.push_back(certificate);
        }
        if (NapiUtils::GetValueType(env, cert) == napi_object) {
            uint32_t arrayLength = NapiUtils::GetArrayLength(env, cert);
            if (arrayLength > CERT_CHAIN_LENGTH) {
                NETSTACK_LOGE("The length of the certificate array is too long");
                return false;
            }
            napi_value element = nullptr;
            for (uint32_t i = 0; i < arrayLength; i++) {
                element = NapiUtils::GetArrayElement(env, cert, i);
                std::string certificate = NapiUtils::GetStringFromValueUtf8(env, element);
                certVec.push_back(certificate);
            }
        }
        secureOption.SetCertChain(certVec);
    }
    return true;
}

bool ReadNecessaryOptions(napi_env env, napi_value secureOptions, TLSSecureOptions &secureOption)
{
    if (!NapiUtils::HasNamedProperty(env, secureOptions, CA_NAME)) {
        NETSTACK_LOGD("use default ca certification");
    }
    napi_value caCert = NapiUtils::GetNamedProperty(env, secureOptions, CA_NAME);
    std::vector<std::string> caVec;
    if (NapiUtils::GetValueType(env, caCert) == napi_string) {
        std::string ca = NapiUtils::GetStringPropertyUtf8(env, secureOptions, CA_NAME);
        caVec.push_back(ca);
    }
    if (NapiUtils::GetValueType(env, caCert) == napi_object) {
        uint32_t arrayLong = NapiUtils::GetArrayLength(env, caCert);
        if (arrayLong > CA_CHAIN_LENGTH) {
            return false;
        }
        napi_value element = nullptr;
        for (uint32_t i = 0; i < arrayLong; i++) {
            element = NapiUtils::GetArrayElement(env, caCert, i);
            std::string ca = NapiUtils::GetStringFromValueUtf8(env, element);
            caVec.push_back(ca);
        }
    }
    secureOption.SetCaChain(caVec);

    if (NapiUtils::HasNamedProperty(env, secureOptions, KEY_NAME)) {
        secureOption.SetKey(SecureData(NapiUtils::GetStringPropertyUtf8(env, secureOptions, KEY_NAME)));
    }

    if (!ReadCertOptions(env, secureOptions, secureOption)) {
        return false;
    }

    if (NapiUtils::HasNamedProperty(env, secureOptions, VERIFY_MODE_NAME)) {
        VerifyMode tempVerifyMode = !NapiUtils::GetBooleanProperty(env, secureOptions, VERIFY_MODE_NAME)
                                        ? VerifyMode::ONE_WAY_MODE
                                        : VerifyMode::TWO_WAY_MODE;
        secureOption.SetVerifyMode(tempVerifyMode);
    } else {
        secureOption.SetVerifyMode(VerifyMode::ONE_WAY_MODE);
    }
    return true;
}
} // namespace

TLSConnectContext::TLSConnectContext(napi_env env, const std::shared_ptr<EventManager> &manager)
    : BaseContext(env, manager) {}

void TLSConnectContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsType(params, paramsCount)) {
        return;
    }
    connectOptions_ = ReadTLSConnectOptions(GetEnv(), params);

    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        SetParseOK(SetCallback(params[ARG_INDEX_1]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

int32_t TLSConnectContext::GetErrorCode() const
{
    auto err = BaseContext::GetErrorCode();
    if (proxyOptions_ != nullptr) {
        err += Socket::SOCKET_ERROR_CODE_BASE;
    }
    return err;
}

std::shared_ptr<Socket::ProxyOptions> TLSConnectContext::ReadTLSProxyOptions(napi_env env, napi_value *params)
{
    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_PROXY)) {
        NETSTACK_LOGD("handle proxy options");
        auto opts = std::make_shared<Socket::ProxyOptions>();
        if (opts->ParseOptions(GetEnv(), params[0]) != 0) {
            NETSTACK_LOGE("parse proxy options failed");
            return nullptr;
        }
        if (opts->type_ != Socket::ProxyType::NONE) {
            proxyOptions_ = opts;
        }
    }
    return proxyOptions_;
}

bool TLSConnectContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_JUST_OPTIONS) {
        if (NapiUtils::GetValueType(GetEnv(), params[ARG_INDEX_0]) != napi_object) {
            NETSTACK_LOGE("tlsConnectContext first param is not object");
            SetNeedThrowException(true);
            SetError(PARSE_ERROR_CODE, PARSE_ERROR.data());
            return false;
        }
        return true;
    }

    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        if (NapiUtils::GetValueType(GetEnv(), params[ARG_INDEX_0]) != napi_object) {
            NETSTACK_LOGE("tls ConnectContext first param is not object");
            SetNeedThrowException(true);
            SetError(PARSE_ERROR_CODE, PARSE_ERROR.data());
            return false;
        }
        if (NapiUtils::GetValueType(GetEnv(), params[ARG_INDEX_1]) != napi_function) {
            NETSTACK_LOGE("tls ConnectContext second param is not function");
            return false;
        }
        return true;
    }
    return false;
}

TLSConnectOptions TLSConnectContext::ReadTLSConnectOptions(napi_env env, napi_value *params)
{
    TLSConnectOptions options;
    Socket::NetAddress address = ReadNetAddress(GetEnv(), params);
    TLSSecureOptions secureOption = ReadTLSSecureOptions(GetEnv(), params);
    uint32_t timeout = ReadTimeout(GetEnv(), params);
    options.SetHostName(address.GetAddress());
    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);
    options.SetTimeout(timeout);
    options.proxyOptions_ = ReadTLSProxyOptions(GetEnv(), params);
    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], ALPN_PROTOCOLS)) {
        napi_value alpnProtocols = NapiUtils::GetNamedProperty(GetEnv(), params[0], ALPN_PROTOCOLS);
        uint32_t arrayLength = NapiUtils::GetArrayLength(GetEnv(), alpnProtocols);
        arrayLength = arrayLength > PROTOCOLS_SIZE ? PROTOCOLS_SIZE : arrayLength;
        napi_value elementValue = nullptr;
        std::vector<std::string> alpnProtocolVec;
        for (uint32_t i = 0; i < arrayLength; i++) {
            elementValue = NapiUtils::GetArrayElement(GetEnv(), alpnProtocols, i);
            std::string alpnProtocol = NapiUtils::GetStringFromValueUtf8(GetEnv(), elementValue);
            alpnProtocolVec.push_back(alpnProtocol);
        }
        options.SetAlpnProtocols(alpnProtocolVec);
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], SKIP_REMOTE_VALIDATION)) {
        bool whetherToSkip = NapiUtils::GetBooleanProperty(GetEnv(), params[0], SKIP_REMOTE_VALIDATION);
        options.SetSkipRemoteValidation(whetherToSkip);
    }

    return options;
}

TLSSecureOptions TLSConnectContext::ReadTLSSecureOptions(napi_env env, napi_value *params)
{
    TLSSecureOptions secureOption;

    if (!NapiUtils::HasNamedProperty(GetEnv(), params[ARG_INDEX_0], SECURE_OPTIONS)) {
        return secureOption;
    }
    napi_value secureOptions = NapiUtils::GetNamedProperty(GetEnv(), params[ARG_INDEX_0], SECURE_OPTIONS);
    if (!ReadNecessaryOptions(env, secureOptions, secureOption)) {
        return secureOption;
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), secureOptions, PASSWD_NAME)) {
        secureOption.SetKeyPass(SecureData(NapiUtils::GetStringPropertyUtf8(env, secureOptions, PASSWD_NAME)));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), secureOptions, PROTOCOLS_NAME)) {
        napi_value protocolValue = NapiUtils::GetNamedProperty(env, secureOptions, PROTOCOLS_NAME);
        std::vector<std::string> protocolVec;
        if (NapiUtils::GetValueType(env, protocolValue) == napi_string) {
            std::string protocolStr = NapiUtils::GetStringFromValueUtf8(env, protocolValue);
            protocolVec.push_back(std::move(protocolStr));
        } else if (NapiUtils::IsArray(env, protocolValue)) {
            uint32_t num = NapiUtils::GetArrayLength(GetEnv(), protocolValue);
            num = num > PROTOCOLS_SIZE ? PROTOCOLS_SIZE : num;
            protocolVec.reserve(num);
            napi_value element = nullptr;
            for (uint32_t i = 0; i < num; i++) {
                element = NapiUtils::GetArrayElement(GetEnv(), protocolValue, i);
                std::string protocol = NapiUtils::GetStringFromValueUtf8(GetEnv(), element);
                protocolVec.push_back(std::move(protocol));
            }
        }
        secureOption.SetProtocolChain(protocolVec);
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), secureOptions, SIGNATURE_ALGORITHMS)) {
        std::string signatureAlgorithms = NapiUtils::GetStringPropertyUtf8(env, secureOptions, SIGNATURE_ALGORITHMS);
        secureOption.SetSignatureAlgorithms(signatureAlgorithms);
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), secureOptions, USE_REMOTE_CIPHER_PREFER)) {
        bool useRemoteCipherPrefer = NapiUtils::GetBooleanProperty(env, secureOptions, USE_REMOTE_CIPHER_PREFER);
        secureOption.SetUseRemoteCipherPrefer(useRemoteCipherPrefer);
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), secureOptions, CIPHER_SUITE)) {
        std::string cipherSuite = NapiUtils::GetStringPropertyUtf8(env, secureOptions, CIPHER_SUITE);
        secureOption.SetCipherSuite(cipherSuite);
    }

    return secureOption;
}

Socket::NetAddress TLSConnectContext::ReadNetAddress(napi_env env, napi_value *params)
{
    Socket::NetAddress address;
    napi_value netAddress = NapiUtils::GetNamedProperty(GetEnv(), params[0], ADDRESS_NAME);
    if (NapiUtils::HasNamedProperty(GetEnv(), netAddress, FAMILY_NAME)) {
        uint32_t family = NapiUtils::GetUint32Property(GetEnv(), netAddress, FAMILY_NAME);
        address.SetFamilyByJsValue(family);
    }
    if (NapiUtils::HasNamedProperty(GetEnv(), netAddress, ADDRESS_NAME)) {
        std::string addr = NapiUtils::GetStringPropertyUtf8(GetEnv(), netAddress, ADDRESS_NAME);
        address.SetRawAddress(addr);
    }
    if (NapiUtils::HasNamedProperty(GetEnv(), netAddress, PORT_NAME)) {
        uint16_t port = static_cast<uint16_t>(NapiUtils::GetUint32Property(GetEnv(), netAddress, PORT_NAME));
        address.SetPort(port);
    }
    return address;
}

uint32_t TLSConnectContext::ReadTimeout(napi_env env, napi_value *params)
{
    uint32_t timeout;
    if (!NapiUtils::HasNamedProperty(GetEnv(), params[0], TIMEOUT)) {
        NETSTACK_LOGI("Context TIMEOUT not found");
        return DEFAULT_TIMEOUT_TLS;
    }
    napi_value jsTimeout = NapiUtils::GetNamedProperty(GetEnv(), params[0], TIMEOUT);
    if (NapiUtils::GetValueType(GetEnv(), jsTimeout) != napi_number) {
        NETSTACK_LOGI("Context TIMEOUT is not napi_number");
        return DEFAULT_TIMEOUT_TLS;
    }
    timeout = NapiUtils::GetUint32FromValue(GetEnv(), jsTimeout);
    return timeout;
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
