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

#include "tlssocketserver_exec.h"

#include <string>
#include <vector>

#include <napi/native_api.h>
#include <securec.h>

#include "context_key.h"
#include "event_list.h"
#include "napi_utils.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "socket_error.h"
#include "tls_socket_server.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocketServer {
namespace {
constexpr const char *CERTIFICATA_DATA = "data";
constexpr const char *CERTIFICATA_ENCODING_FORMAT = "encodingFormat";
constexpr const int SYSTEM_INTERNAL_ERROR_CODE = 2300002;
const std::string SYSTEM_INTERNAL_ERROR_MESSAGE = "system internal error";
} // namespace
bool TLSSocketServerExec::ExecGetCertificate(TlsSocket::GetCertificateContext *context)
{
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("ExecGetCertificate tlsSocketServer is null");
        context->SetError(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND,
                          TlsSocket::MakeErrorMessage(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND));
        return false;
    }
    tlsSocketServer->GetCertificate([&context](int32_t errorNumber, const TlsSocket::X509CertRawData &cert) {
        context->localCert_ = cert;
        context->errorNumber_ = errorNumber;
        if (errorNumber != TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, TlsSocket::MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

bool TLSSocketServerExec::ExecTLSConnectionGetSocketFd(TLSServerGetSocketFdContext *context)
{
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetError(PERMISSION_DENIED_CODE,
                          TlsSocket::MakeErrorMessage(PERMISSION_DENIED_CODE));
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("ExecTLSConnectionGetSocketFd TLSSocketServer is null");
        return false;
    }
    int32_t socketFd = tlsSocketServer->GetClientSocketFd(context->clientId_);
    context->socketFd_ = socketFd;
    if (socketFd == -1) {
        NETSTACK_LOGE("socket = %{public}d The connection has been disconnected", context->clientId_);
    } else {
        NETSTACK_LOGI("get TLS client socketfd success: %d for clientId: %d", socketFd, context->clientId_);
    }
    return true;
}

bool TLSSocketServerExec::ExecListen(TlsSocket::TLSListenContext *context)
{
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    std::unique_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager->GetData());
    if (tlsSocketServer == nullptr) {
        tlsSocketServer = new TLSSocketServer();
    }
    if (manager->GetData() == nullptr) {
        manager->SetData(tlsSocketServer);
    }
    lock.unlock();
    tlsSocketServer->Listen(context->connectOptions_, [&context](int32_t errorNumber) {
        context->errorNumber_ = errorNumber;
        if (errorNumber != TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, TlsSocket::MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

bool TLSSocketServerExec::ExecGetCipherSuites(ServerGetCipherSuitesContext *context)
{
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("ExecGetCipherSuites tlsSocketServer is null");
        context->SetError(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND,
                          MakeErrorMessage(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND));
        return false;
    }
    tlsSocketServer->GetCipherSuite(context->clientId_,
                                    [&context](int32_t errorNumber, const std::vector<std::string> &suite) {
                                        context->cipherSuites_ = suite;
                                        context->errorNumber_ = errorNumber;
                                        if (errorNumber != TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS) {
                                            context->SetError(errorNumber, TlsSocket::MakeErrorMessage(errorNumber));
                                        }
                                    });
    return context->errorNumber_ == TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

bool TLSSocketServerExec::ExecGetRemoteCertificate(ServerGetRemoteCertificateContext *context)
{
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("ExecGetRemoteCertificate tlsSocketServer is null");
        context->SetError(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND,
                          TlsSocket::MakeErrorMessage(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND));
        return false;
    }
    tlsSocketServer->GetRemoteCertificate(
        context->clientId_, [&context](int32_t errorNumber, const TlsSocket::X509CertRawData &cert) {
            context->remoteCert_ = cert;
            context->errorNumber_ = errorNumber;
            if (errorNumber != TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS) {
                context->SetError(errorNumber, TlsSocket::MakeErrorMessage(errorNumber));
            }
        });
    return context->errorNumber_ == TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

bool TLSSocketServerExec::ExecGetProtocol(TlsSocket::GetProtocolContext *context)
{
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("ExecGetProtocol tlsSocketServer is null");
        context->SetError(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND,
                          TlsSocket::MakeErrorMessage(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND));
        return false;
    }
    tlsSocketServer->GetProtocol([&context](int32_t errorNumber, const std::string &protocol) {
        context->protocol_ = protocol;
        context->errorNumber_ = errorNumber;
        if (errorNumber != TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, TlsSocket::MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

bool TLSSocketServerExec::ExecGetSignatureAlgorithms(ServerGetSignatureAlgorithmsContext *context)
{
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("ExecGetSignatureAlgorithms tlsSocketServer is null");
        context->SetError(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND,
                          TlsSocket::MakeErrorMessage(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND));
        return false;
    }
    tlsSocketServer->GetSignatureAlgorithms(
        context->clientId_, [&context](int32_t errorNumber, const std::vector<std::string> &algorithms) {
            context->signatureAlgorithms_ = algorithms;
            context->errorNumber_ = errorNumber;
            if (errorNumber != TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS) {
                context->SetError(errorNumber, TlsSocket::MakeErrorMessage(errorNumber));
            }
        });
    return context->errorNumber_ == TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

bool TLSSocketServerExec::ExecSend(TLSServerSendContext *context)
{
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("ExecSend tlsSocketServer is null");
        context->SetError(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND,
                          TlsSocket::MakeErrorMessage(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND));
        return false;
    }
    TLSServerSendOptions tcpSendOptions;
    int client_id = context->clientId_;
    tcpSendOptions.SetSocket(client_id);
    tcpSendOptions.SetSendData(context->m_sendData);
    tlsSocketServer->Send(tcpSendOptions, [&context](int32_t errorNumber) {
        context->errorNumber_ = errorNumber;
        if (errorNumber != TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, TlsSocket::MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

bool TLSSocketServerExec::ExecClose(TLSServerCloseContext *context)
{
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("ExecClose tlsSocketServer is null");
        context->SetError(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND,
                          TlsSocket::MakeErrorMessage(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND));
        return false;
    }
    tlsSocketServer->Close(context->clientId_, [&context](int32_t errorNumber) {
        context->errorNumber_ = errorNumber;
        if (errorNumber != TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, TlsSocket::MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

bool TLSSocketServerExec::ExecStop(TlsSocket::TLSNapiContext *context)
{
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetError(PERMISSION_DENIED_CODE,
                          TlsSocket::MakeErrorMessage(PERMISSION_DENIED_CODE));
        return false;
    }
    std::unique_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("ExecClose tlsSocketServer is null");
        context->SetError(TlsSocket::TlsSocketError::SYSTEM_INTERNAL_ERROR,
                          TlsSocket::MakeErrorMessage(TlsSocket::TlsSocketError::SYSTEM_INTERNAL_ERROR));
        return false;
    }
    tlsSocketServer->Stop([&context](int32_t errorNumber) {
        context->errorNumber_ = errorNumber;
        if (errorNumber != TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, TlsSocket::MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

bool TLSSocketServerExec::ExecGetRemoteAddress(ServerTLSGetRemoteAddressContext *context)
{
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("ExecGetRemoteAddress tlsSocketServer is null");
        context->SetError(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND,
                          TlsSocket::MakeErrorMessage(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND));
        return false;
    }
    tlsSocketServer->GetRemoteAddress(context->clientId_,
                                      [&context](int32_t errorNumber, const Socket::NetAddress address) {
                                          context->address_ = address;
                                          context->errorNumber_ = errorNumber;
                                          if (errorNumber != TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS) {
                                              context->SetError(errorNumber, TlsSocket::MakeErrorMessage(errorNumber));
                                          }
                                      });
    return context->errorNumber_ == TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

bool TLSSocketServerExec::ExecGetLocalAddress(TLSServerGetLocalAddressContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        context->SetNeedThrowException(true);
        context->SetError(SYSTEM_INTERNAL_ERROR_CODE, SYSTEM_INTERNAL_ERROR_MESSAGE);
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("ExecGetRemoteAddress tlsSocketServer is null");
        context->SetError(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND,
                          TlsSocket::MakeErrorMessage(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND));
        return false;
    }
    struct sockaddr_storage addr{};
    socklen_t addrLen = sizeof(addr);
    if (getsockname(tlsSocketServer->GetListenSocketFd(), (struct sockaddr *)&addr, &addrLen) < 0) {
        context->SetErrorCode(errno);
        return false;
    }

    char ipStr[INET6_ADDRSTRLEN] = {0};
    Socket::NetAddress localAddress;
    if (addr.ss_family == AF_INET) {
        auto *addr_in = (struct sockaddr_in *)&addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, ipStr, sizeof(ipStr));
        localAddress.SetFamilyBySaFamily(AF_INET);
        localAddress.SetRawAddress(ipStr);
        localAddress.SetPort(ntohs(addr_in->sin_port));
        tlsSocketServer->SetLocalAddress(localAddress);
    } else if (addr.ss_family == AF_INET6) {
        auto *addr_in6 = (struct sockaddr_in6 *)&addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ipStr, sizeof(ipStr));
        localAddress.SetFamilyBySaFamily(AF_INET6);
        localAddress.SetRawAddress(ipStr);
        localAddress.SetPort(ntohs(addr_in6->sin6_port));
        tlsSocketServer->SetLocalAddress(localAddress);
    }
    return true;
}

bool TLSSocketServerExec::ExecConnectionGetLocalAddress(TLSConnectionGetLocalAddressContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        context->SetNeedThrowException(true);
        context->SetError(SYSTEM_INTERNAL_ERROR_CODE, SYSTEM_INTERNAL_ERROR_MESSAGE);
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("ExecGetRemoteAddress tlsSocketServer is null");
        context->SetError(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND,
                          TlsSocket::MakeErrorMessage(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND));
        return false;
    }
    tlsSocketServer->GetLocalAddress(context->clientId_,
                                     [&context](int32_t errorNumber, const Socket::NetAddress address) {
                                         context->localAddress_ = address;
                                         context->errorNumber_ = errorNumber;
                                         if (errorNumber != TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS) {
                                             context->SetError(errorNumber, TlsSocket::MakeErrorMessage(errorNumber));
                                         }
                                     });
    return context->errorNumber_ == TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

bool TLSSocketServerExec::ExecGetState(TlsSocket::TLSGetStateContext *context)
{
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        context->state_.SetIsClose(true);
        return true;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("ExecGetState tlsSocketServer is null");
        return true;
    }
    tlsSocketServer->GetState([&context](int32_t errorNumber, const Socket::SocketStateBase state) {
        context->state_ = state;
        context->errorNumber_ = errorNumber;
        if (errorNumber != TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, TlsSocket::MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

bool TLSSocketServerExec::ExecSetExtraOptions(TlsSocket::TLSSetExtraOptionsContext *context)
{
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("ExecSetExtraOptions tlsSocketServer is null");
        context->SetError(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND,
                          TlsSocket::MakeErrorMessage(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND));
        return false;
    }
    tlsSocketServer->SetExtraOptions(context->options_, [&context](int32_t errorNumber) {
        context->errorNumber_ = errorNumber;
        if (errorNumber != TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, TlsSocket::MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

bool TLSSocketServerExec::ExecGetSocketFd(TlsSocket::TLSGetSocketFdContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetError(PERMISSION_DENIED_CODE,
                          TlsSocket::MakeErrorMessage(PERMISSION_DENIED_CODE));
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("ExecGetSocketFd TLSSocketServer is null");
        context->sockFd_= -1;
        return false;
    }
    context->sockFd_= tlsSocketServer->GetListenSocketFd();
    return true;
}

napi_value TLSSocketServerExec::GetCertificateCallback(TlsSocket::GetCertificateContext *context)
{
    void *data = nullptr;
    napi_value arrayBuffer = NapiUtils::CreateArrayBuffer(context->GetEnv(), context->localCert_.data.Length(), &data);
    if (data != nullptr && arrayBuffer != nullptr) {
        if (memcpy_s(data, context->localCert_.data.Length(),
                     reinterpret_cast<const uint8_t *>(context->localCert_.data.Data()),
                     context->localCert_.data.Length()) != EOK) {
            NETSTACK_LOGE("memcpy_s failed!");
            return NapiUtils::GetUndefined(context->GetEnv());
        }
    }
    napi_value outData = nullptr;
    napi_create_typedarray(context->GetEnv(), napi_uint8_array, context->localCert_.data.Length(), arrayBuffer, 0,
                           &outData);
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    NapiUtils::SetNamedProperty(context->GetEnv(), obj, CERTIFICATA_DATA, outData);
    NapiUtils::SetInt32Property(context->GetEnv(), obj, CERTIFICATA_ENCODING_FORMAT,
                                context->localCert_.encodingFormat);
    return obj;
}

napi_value TLSSocketServerExec::TLSConnectionGetSocketFdCallback(TLSServerGetSocketFdContext *context)
{
    return NapiUtils::CreateInt32(context->GetEnv(), context->socketFd_);
}

napi_value TLSSocketServerExec::ListenCallback(TlsSocket::TLSListenContext *context)
{
    context->EmitSharedManager(EVENT_LISTENING, std::make_pair(NapiUtils::GetUndefined(context->GetEnv()),
        NapiUtils::GetUndefined(context->GetEnv())));
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TLSSocketServerExec::GetCipherSuitesCallback(ServerGetCipherSuitesContext *context)
{
    napi_value cipherSuites = NapiUtils::CreateArray(context->GetEnv(), 0);
    int index = 0;
    for (const auto &cipher : context->cipherSuites_) {
        napi_value cipherSuite = NapiUtils::CreateStringUtf8(context->GetEnv(), cipher);
        NapiUtils::SetArrayElement(context->GetEnv(), cipherSuites, index++, cipherSuite);
    }
    return cipherSuites;
}

napi_value TLSSocketServerExec::GetRemoteCertificateCallback(ServerGetRemoteCertificateContext *context)
{
    napi_value obj = nullptr;
    if (context->remoteCert_.data.Length() > 0 && context->remoteCert_.data.Data() != nullptr) {
        void *data = nullptr;
        napi_value arrayBuffer =
            NapiUtils::CreateArrayBuffer(context->GetEnv(), context->remoteCert_.data.Length(), &data);
        if (data != nullptr && arrayBuffer != nullptr) {
            if (memcpy_s(data, context->remoteCert_.data.Length(),
                         reinterpret_cast<const uint8_t *>(context->remoteCert_.data.Data()),
                         context->remoteCert_.data.Length()) != EOK) {
                NETSTACK_LOGE("memcpy_s failed!");
                return NapiUtils::GetUndefined(context->GetEnv());
            }
        }
        napi_value outData = nullptr;
        napi_create_typedarray(context->GetEnv(), napi_uint8_array, context->remoteCert_.data.Length(), arrayBuffer, 0,
                               &outData);
        obj = NapiUtils::CreateObject(context->GetEnv());
        if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
            return NapiUtils::GetUndefined(context->GetEnv());
        }
        NapiUtils::SetNamedProperty(context->GetEnv(), obj, CERTIFICATA_DATA, outData);
        NapiUtils::SetInt32Property(context->GetEnv(), obj, CERTIFICATA_ENCODING_FORMAT,
                                    context->remoteCert_.encodingFormat);
    }
    return obj;
}

napi_value TLSSocketServerExec::GetProtocolCallback(TlsSocket::GetProtocolContext *context)
{
    return NapiUtils::CreateStringUtf8(context->GetEnv(), context->protocol_);
}

napi_value TLSSocketServerExec::GetSignatureAlgorithmsCallback(ServerGetSignatureAlgorithmsContext *context)
{
    napi_value signatureAlgorithms = NapiUtils::CreateArray(context->GetEnv(), 0);
    int index = 0;
    for (const auto &algorithm : context->signatureAlgorithms_) {
        napi_value signatureAlgorithm = NapiUtils::CreateStringUtf8(context->GetEnv(), algorithm);
        NapiUtils::SetArrayElement(context->GetEnv(), signatureAlgorithms, index++, signatureAlgorithm);
    }
    return signatureAlgorithms;
}

napi_value TLSSocketServerExec::SendCallback(TLSServerSendContext *context)
{
    context->EmitSharedManager(EVENT_LISTENING, std::make_pair(NapiUtils::GetUndefined(context->GetEnv()),
        NapiUtils::GetUndefined(context->GetEnv())));
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TLSSocketServerExec::CloseCallback(TLSServerCloseContext *context)
{
    context->EmitSharedManager(EVENT_CLOSE, std::make_pair(NapiUtils::GetUndefined(context->GetEnv()),
        NapiUtils::GetUndefined(context->GetEnv())));
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TLSSocketServerExec::StopCallback(TlsSocket::TLSNapiContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TLSSocketServerExec::GetStateCallback(TlsSocket::TLSGetStateContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_BOUND, context->state_.IsBound());
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_CLOSE, context->state_.IsClose());
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_CONNECTED, context->state_.IsConnected());
    return obj;
}

napi_value TLSSocketServerExec::GetRemoteAddressCallback(ServerTLSGetRemoteAddressContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    NapiUtils::SetStringPropertyUtf8(context->GetEnv(), obj, KEY_ADDRESS, context->address_.GetAddress());
    NapiUtils::SetUint32Property(context->GetEnv(), obj, KEY_FAMILY, context->address_.GetJsValueFamily());
    NapiUtils::SetUint32Property(context->GetEnv(), obj, KEY_PORT, context->address_.GetPort());
    return obj;
}

napi_value TLSSocketServerExec::GetLocalAddressCallback(TLSServerGetLocalAddressContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return obj;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("get localAddress callback tlsSocketServer is null");
        return obj;
    }
    auto env = context->GetEnv();
    NapiUtils::SetStringPropertyUtf8(env, obj, KEY_ADDRESS, tlsSocketServer->GetLocalAddress().GetAddress());
    NapiUtils::SetUint32Property(env, obj, KEY_FAMILY, tlsSocketServer->GetLocalAddress().GetJsValueFamily());
    NapiUtils::SetUint32Property(env, obj, KEY_PORT, tlsSocketServer->GetLocalAddress().GetPort());
    return obj;
}

napi_value TLSSocketServerExec::GetConnectionLocalAddressCallback(TLSConnectionGetLocalAddressContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    auto env = context->GetEnv();
    NapiUtils::SetStringPropertyUtf8(env, obj, KEY_ADDRESS, context->localAddress_.GetAddress());
    NapiUtils::SetUint32Property(env, obj, KEY_FAMILY, context->localAddress_.GetJsValueFamily());
    NapiUtils::SetUint32Property(env, obj, KEY_PORT, context->localAddress_.GetPort());
    return obj;
}

napi_value TLSSocketServerExec::SetExtraOptionsCallback(TlsSocket::TLSSetExtraOptionsContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TLSSocketServerExec::TLSSocketServerGetSocketFdCallback(TlsSocket::TLSGetSocketFdContext *context)
{
    return NapiUtils::CreateInt32(context->GetEnv(), context->sockFd_);
}

bool TLSSocketServerExec::ExecConnectionSend(TLSServerSendContext *context)
{
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("ExecSend tlsSocketServer is null");
        context->SetError(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND,
                          TlsSocket::MakeErrorMessage(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND));
        return false;
    }
    TLSServerSendOptions tcpSendOptions;
    int client_id = context->clientId_;

    tcpSendOptions.SetSocket(client_id);
    tcpSendOptions.SetSendData(context->m_sendData);
    tlsSocketServer->Send(tcpSendOptions, [&context](int32_t errorNumber) {
        context->errorNumber_ = errorNumber;
        if (errorNumber != TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, TlsSocket::MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

napi_value TLSSocketServerExec::ConnectionSendCallback(TLSServerSendContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}
} // namespace TlsSocketServer
} // namespace NetStack
} // namespace OHOS
