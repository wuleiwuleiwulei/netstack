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

#include "tls_socket_server.h"

#include <chrono>
#include <memory>
#include <netinet/tcp.h>
#include <numeric>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <regex>
#include <securec.h>
#include <sys/ioctl.h>

#include "base_context.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "tls.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocketServer {
#if UNITTEST
#else
namespace {
#endif // UNITTEST
constexpr size_t MAX_ERR_LENGTH = 1024;

constexpr int SSL_RET_CODE = 0;

constexpr int BUF_SIZE = 2048;
constexpr int POLL_WAIT_TIME = 2000;
constexpr int OFFSET = 2;
constexpr int SSL_ERROR_RETURN = -1;
constexpr int REMOTE_CERT_LEN = 8192;
constexpr int COMMON_NAME_BUF_SIZE = 256;
constexpr int LISETEN_COUNT = 516;
constexpr const char *SPLIT_HOST_NAME = ".";
constexpr const char *SPLIT_ALT_NAMES = ",";
constexpr const char *DNS = "DNS:";
constexpr const char *HOST_NAME = "hostname: ";
constexpr const char *IP_ADDRESS = "IP Address:";
constexpr const char *SIGN_NID_RSA = "RSA+";
constexpr const char *SIGN_NID_RSA_PSS = "RSA-PSS+";
constexpr const char *SIGN_NID_DSA = "DSA+";
constexpr const char *SIGN_NID_ECDSA = "ECDSA+";
constexpr const char *SIGN_NID_ED = "Ed25519+";
constexpr const char *SIGN_NID_ED_FOUR_FOUR_EIGHT = "Ed448+";
constexpr const char *SIGN_NID_UNDEF_ADD = "UNDEF+";
constexpr const char *PROTOCOL_UNKNOW = "UNKNOW_PROTOCOL";
constexpr const char *SIGN_NID_UNDEF = "UNDEF";
constexpr const char *OPERATOR_PLUS_SIGN = "+";
constexpr const char *UNKNOW_REASON = "Unknown reason";
constexpr const char *IP = "IP: ";
static constexpr const char *TLS_SOCKET_SERVER_READ = "OS_NET_TSAccRD";
const std::regex JSON_STRING_PATTERN{R"(/^"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/)"};
const std::regex PATTERN{
    "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|"
    "2[0-4][0-9]|[01]?[0-9][0-9]?)"};
int g_userCounter = 0;

bool IsIP(const std::string &ip)
{
    std::regex pattern(PATTERN);
    std::smatch res;
    return regex_match(ip, res, pattern);
}

std::vector<std::string> SplitHostName(std::string &hostName)
{
    transform(hostName.begin(), hostName.end(), hostName.begin(), ::tolower);
    return CommonUtils::Split(hostName, SPLIT_HOST_NAME);
}

bool SeekIntersection(std::vector<std::string> &vecA, std::vector<std::string> &vecB)
{
    std::vector<std::string> result;
    set_intersection(vecA.begin(), vecA.end(), vecB.begin(), vecB.end(), inserter(result, result.begin()));
    return !result.empty();
}

int ConvertErrno()
{
    return TlsSocket::TlsSocketError::TLS_ERR_SYS_BASE + errno;
}

int ConvertSSLError(ssl_st *ssl)
{
    if (!ssl) {
        return TlsSocket::TLS_ERR_SSL_NULL;
    }
    return TlsSocket::TlsSocketError::TLS_ERR_SSL_BASE + SSL_get_error(ssl, SSL_RET_CODE);
}

std::string MakeErrnoString()
{
    return strerror(errno);
}

std::string MakeSSLErrorString(int error)
{
    char err[MAX_ERR_LENGTH] = {0};
    ERR_error_string_n(error - TlsSocket::TlsSocketError::TLS_ERR_SYS_BASE, err, sizeof(err));
    return err;
}
std::vector<std::string> SplitEscapedAltNames(std::string &altNames)
{
    std::vector<std::string> result;
    std::string currentToken;
    size_t offset = 0;
    while (offset != altNames.length()) {
        auto nextSep = altNames.find_first_of(", ");
        auto nextQuote = altNames.find_first_of('\"');
        if (nextQuote != std::string::npos && (nextSep != std::string::npos || nextQuote < nextSep)) {
            currentToken += altNames.substr(offset, nextQuote);
            std::regex jsonStringPattern(JSON_STRING_PATTERN);
            std::smatch match;
            std::string altNameSubStr = altNames.substr(nextQuote);
            bool ret = regex_match(altNameSubStr, match, jsonStringPattern);
            if (!ret) {
                return {""};
            }
            currentToken += result[0];
            offset = nextQuote + result[0].length();
        } else if (nextSep != std::string::npos) {
            currentToken += altNames.substr(offset, nextSep);
            result.push_back(currentToken);
            currentToken = "";
            offset = nextSep + OFFSET;
        } else {
            currentToken += altNames.substr(offset);
            offset = altNames.length();
        }
    }
    result.push_back(currentToken);
    return result;
}
#if UNITTEST
#else
} // namespace
#endif

void TLSServerSendOptions::SetSocket(const int &socketFd)
{
    socketFd_ = socketFd;
}

void TLSServerSendOptions::SetSendData(const std::string &data)
{
    data_ = data;
}

const int &TLSServerSendOptions::GetSocket() const
{
    return socketFd_;
}

const std::string &TLSServerSendOptions::GetSendData() const
{
    return data_;
}

TLSSocketServer::~TLSSocketServer()
{
    isRunning_ = false;
    clientIdConnections_.clear();

    if (listenSocketFd_ != -1) {
        shutdown(listenSocketFd_, SHUT_RDWR);
        close(listenSocketFd_);
        listenSocketFd_ = -1;
    }
}

void TLSSocketServer::Listen(const TlsSocket::TLSConnectOptions &tlsListenOptions, const ListenCallback &callback)
{
    if (!CommonUtils::HasInternetPermission()) {
        CallListenCallback(PERMISSION_DENIED_CODE, callback);
        return;
    }
    NETSTACK_LOGE("Listen 1 %{public}d", listenSocketFd_);
    if (listenSocketFd_ >= 0) {
        CallListenCallback(TlsSocket::TLSSOCKET_SUCCESS, callback);
        return;
    }
    NETSTACK_LOGE("Listen 2 %{public}d, %{public}d", listenSocketFd_, g_userCounter);
    if (ExecBind(tlsListenOptions.GetNetAddress(), callback)) {
        NETSTACK_LOGE("Listen 3 %{public}d", listenSocketFd_);
        ExecAccept(tlsListenOptions, callback);
    } else {
        shutdown(listenSocketFd_, SHUT_RDWR);
        close(listenSocketFd_);
        listenSocketFd_ = -1;
    }
    if (isRunning_) {
        isRunning_ = false;
        WaitForRcvThdExit();
    }
    PollThread(tlsListenOptions);
}

bool TLSSocketServer::ExecBind(const Socket::NetAddress &address, const ListenCallback &callback)
{
    MakeIpSocket(address.GetSaFamily());
    if (listenSocketFd_ < 0) {
        int resErr = ConvertErrno();
        NETSTACK_LOGE("make tcp socket failed errno is %{public}d %{public}s", errno, MakeErrnoString().c_str());
        CallOnErrorCallback(resErr, MakeErrnoString());
        CallListenCallback(resErr, callback);
        return false;
    }
    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len;
    GetAddr(address, &addr4, &addr6, &addr, &len);
    if (addr == nullptr) {
        NETSTACK_LOGE("TLSSocket::Bind Address Is Invalid");
        CallOnErrorCallback(-1, "Address Is Invalid");
        CallListenCallback(ConvertErrno(), callback);
        return false;
    }
    int reuse = 1; // 1 means enable reuseaddr feature
    if (setsockopt(listenSocketFd_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<void *>(&reuse), sizeof(reuse)) < 0) {
        NETSTACK_LOGE("failed to set tls server listen socket reuseaddr on, sockfd: %{public}d", listenSocketFd_);
    }
    if (bind(listenSocketFd_, addr, len) < 0) {
        if (errno != EADDRINUSE) {
            NETSTACK_LOGE("bind error is %{public}s %{public}d", strerror(errno), errno);
            CallOnErrorCallback(-1, "Address binding failed");
            CallListenCallback(ConvertErrno(), callback);
            return false;
        }
        if (addr->sa_family == AF_INET) {
            NETSTACK_LOGI("distribute a random port");
            addr4.sin_port = 0; /* distribute a random port */
        } else if (addr->sa_family == AF_INET6) {
            NETSTACK_LOGI("distribute a random port");
            addr6.sin6_port = 0; /* distribute a random port */
        }
        if (bind(listenSocketFd_, addr, len) < 0) {
            NETSTACK_LOGE("rebind error is %{public}s %{public}d", strerror(errno), errno);
            CallOnErrorCallback(-1, "Duplicate binding address failed");
            CallListenCallback(ConvertErrno(), callback);
            return false;
        }
        NETSTACK_LOGI("rebind success");
    }
    NETSTACK_LOGI("bind success");
    address_ = address;
    return true;
}

void TLSSocketServer::ExecAccept(const TlsSocket::TLSConnectOptions &tlsAcceptOptions, const ListenCallback &callback)
{
    if (listenSocketFd_ < 0) {
        int resErr = ConvertErrno();
        NETSTACK_LOGE("accept error is %{public}s %{public}d", MakeErrnoString().c_str(), errno);
        CallOnErrorCallback(resErr, MakeErrnoString());
        callback(resErr);
        return;
    }
    SetLocalTlsConfiguration(tlsAcceptOptions);
    int ret = 0;
    ret = listen(listenSocketFd_, LISETEN_COUNT);
    if (ret < 0) {
        int resErr = ConvertErrno();
        NETSTACK_LOGE("tcp server listen error");
        CallOnErrorCallback(resErr, MakeErrnoString());
        callback(resErr);
        return;
    }
    CallListenCallback(TlsSocket::TLSSOCKET_SUCCESS, callback);
}

bool TLSSocketServer::Send(const TLSServerSendOptions &data, const TlsSocket::SendCallback &callback)
{
    int socketFd = data.GetSocket();
    std::string info = data.GetSendData();

    auto connect_iterator = clientIdConnections_.find(socketFd);
    if (connect_iterator == clientIdConnections_.end()) {
        NETSTACK_LOGE("socket = %{public}d The connection has been disconnected", socketFd);
        CallOnErrorCallback(TlsSocket::TLS_ERR_SYS_EINVAL, "The send failed with no corresponding socketFd");
        return false;
    }
    auto connect = connect_iterator->second;
    auto res = connect->Send(info);
    if (!res) {
        int resErr = ConvertSSLError(connect->GetSSL());
        NETSTACK_LOGE("send error is %{public}d %{public}d", resErr, errno);
        CallOnErrorCallback(resErr, MakeSSLErrorString(resErr));
        CallSendCallback(resErr, callback);
        return false;
    }
    CallSendCallback(TlsSocket::TLSSOCKET_SUCCESS, callback);
    return res;
}

void TLSSocketServer::CallSendCallback(int32_t err, TlsSocket::SendCallback callback)
{
    if (callback) {
        callback(err);
    }
}

void TLSSocketServer::Close(const int socketFd, const TlsSocket::CloseCallback &callback)
{
    {
        std::shared_lock<std::shared_mutex> its_lock(connectMutex_);
        for (auto it = clientIdConnections_.begin(); it != clientIdConnections_.end();) {
            if (it->first == socketFd) {
                auto res = it->second->Close();
                if (!res) {
                    int resErr = ConvertSSLError(it->second->GetSSL());
                    NETSTACK_LOGE("close error is %{public}d %{public}d", resErr, errno);
                    CallOnErrorCallback(resErr, MakeSSLErrorString(resErr));
                    callback(resErr);
                    return;
                }
                callback(TlsSocket::TLSSOCKET_SUCCESS);
                return;
            } else {
                ++it;
            }
        }
    }
    NETSTACK_LOGE("socket = %{public}d There is no corresponding socketFd", socketFd);
    CallOnErrorCallback(-1, "The send failed with no corresponding socketFd");
    callback(TlsSocket::TLS_ERR_SYS_EINVAL);
}

void TLSSocketServer::Stop(const TlsSocket::CloseCallback &callback)
{
    if (!CommonUtils::HasInternetPermission()) {
        callback(PERMISSION_DENIED_CODE);
    }
    close(listenSocketFd_);
    listenSocketFd_ = -1;
    NETSTACK_LOGE("g_userCounter = %{public}d", g_userCounter);
    callback(TlsSocket::TLSSOCKET_SUCCESS);
}

void TLSSocketServer::GetRemoteAddress(const int socketFd, const TlsSocket::GetRemoteAddressCallback &callback)
{
    auto connect_iterator = clientIdConnections_.find(socketFd);
    if (connect_iterator == clientIdConnections_.end()) {
        NETSTACK_LOGE("socket = %{public}d The connection has been disconnected", socketFd);
        CallOnErrorCallback(TlsSocket::TLS_ERR_SYS_EINVAL, "The send failed with no corresponding socketFd");
        callback(TlsSocket::TLS_ERR_SYS_EINVAL, {});
        return;
    }
    auto connect = connect_iterator->second;
    auto address = connect->GetAddress();
    callback(TlsSocket::TLSSOCKET_SUCCESS, address);
}

void TLSSocketServer::GetLocalAddress(const int socketFd, const TlsSocket::GetLocalAddressCallback &callback)
{
    auto connect_iterator = clientIdConnections_.find(socketFd);
    if (connect_iterator == clientIdConnections_.end()) {
        NETSTACK_LOGE("socket = %{public}d The connection has been disconnected", socketFd);
        CallOnErrorCallback(TlsSocket::TLS_ERR_SYS_EINVAL, "The send failed with no corresponding socketFd");
        callback(TlsSocket::TLS_ERR_SYS_EINVAL, {});
        return;
    }
    auto connect = connect_iterator->second;
    auto localAddress = connect->GetLocalAddress();
    callback(TlsSocket::TLSSOCKET_SUCCESS, localAddress);
}

int32_t TLSSocketServer::GetClientSocketFd(int32_t clientId)
{
    std::shared_lock<std::shared_mutex> its_lock(connectMutex_);
    auto connect_iterator = clientIdConnections_.find(clientId);
    if (connect_iterator == clientIdConnections_.end()) {
        NETSTACK_LOGE("getClientSocketFd: clientId = %{public}d, connection not found", clientId);
        return -1;
    }
    auto connection = connect_iterator->second;
    return connection->GetSocketFd();
}

void TLSSocketServer::GetState(const TlsSocket::GetStateCallback &callback)
{
    int opt;
    socklen_t optLen = sizeof(int);
    int r = getsockopt(listenSocketFd_, SOL_SOCKET, SO_TYPE, &opt, &optLen);
    if (r < 0) {
        Socket::SocketStateBase state;
        state.SetIsClose(true);
        CallGetStateCallback(ConvertErrno(), state, callback);
        return;
    }
    sockaddr sockAddr = {0};
    socklen_t len = sizeof(sockaddr);
    Socket::SocketStateBase state;
    int ret = getsockname(listenSocketFd_, &sockAddr, &len);
    state.SetIsBound(ret == 0);
    ret = getpeername(listenSocketFd_, &sockAddr, &len);
    if (ret != 0) {
        NETSTACK_LOGE("getpeername failed");
    }
    state.SetIsConnected(GetConnectionClientCount() > 0);
    CallGetStateCallback(TlsSocket::TLSSOCKET_SUCCESS, state, callback);
}

void TLSSocketServer::CallGetStateCallback(int32_t err, const Socket::SocketStateBase &state,
                                           TlsSocket::GetStateCallback callback)
{
    if (callback) {
        callback(err, state);
    }
}
bool TLSSocketServer::SetExtraOptions(const Socket::TCPExtraOptions &tcpExtraOptions,
                                      const TlsSocket::SetExtraOptionsCallback &callback)
{
    if (tcpExtraOptions.IsKeepAlive()) {
        int keepalive = 1;
        if (setsockopt(listenSocketFd_, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0) {
            return false;
        }
    }

    if (tcpExtraOptions.IsOOBInline()) {
        int oobInline = 1;
        if (setsockopt(listenSocketFd_, SOL_SOCKET, SO_OOBINLINE, &oobInline, sizeof(oobInline)) < 0) {
            return false;
        }
    }

    if (tcpExtraOptions.IsTCPNoDelay()) {
        int tcpNoDelay = 1;
        if (setsockopt(listenSocketFd_, IPPROTO_TCP, TCP_NODELAY, &tcpNoDelay, sizeof(tcpNoDelay)) < 0) {
            return false;
        }
    }

    linger soLinger = {0};
    soLinger.l_onoff = tcpExtraOptions.socketLinger.IsOn();
    soLinger.l_linger = (int)tcpExtraOptions.socketLinger.GetLinger();
    if (setsockopt(listenSocketFd_, SOL_SOCKET, SO_LINGER, &soLinger, sizeof(soLinger)) < 0) {
        return false;
    }

    return true;
}

void TLSSocketServer::SetLocalTlsConfiguration(const TlsSocket::TLSConnectOptions &config)
{
    TLSServerConfiguration_.SetPrivateKey(config.GetTlsSecureOptions().GetKey(),
                                          config.GetTlsSecureOptions().GetKeyPass());
    TLSServerConfiguration_.SetLocalCertificate(config.GetTlsSecureOptions().GetCertChain());
    TLSServerConfiguration_.SetCaCertificate(config.GetTlsSecureOptions().GetCaChain());

    TLSServerConfiguration_.SetVerifyMode(config.GetTlsSecureOptions().GetVerifyMode());

    const auto protocolVec = config.GetTlsSecureOptions().GetProtocolChain();
    if (!protocolVec.empty()) {
        TLSServerConfiguration_.SetProtocol(protocolVec);
    }
}

void TLSSocketServer::GetCertificate(const TlsSocket::GetCertificateCallback &callback)
{
    const auto &cert = TLSServerConfiguration_.GetCertificate();
    NETSTACK_LOGI("cert der is %{public}d", cert.encodingFormat);
    if (!cert.data.Length()) {
        CallOnErrorCallback(-1, "cert not data Length");
        callback(-1, {});
        return;
    }
    callback(TlsSocket::TLSSOCKET_SUCCESS, cert);
}

void TLSSocketServer::GetRemoteCertificate(const int socketFd, const TlsSocket::GetRemoteCertificateCallback &callback)
{
    auto connect_iterator = clientIdConnections_.find(socketFd);
    if (connect_iterator == clientIdConnections_.end()) {
        NETSTACK_LOGE("socket = %{public}d The connection has been disconnected", socketFd);
        CallOnErrorCallback(TlsSocket::TLS_ERR_SYS_EINVAL, "The send failed with no corresponding socketFd");
        callback(TlsSocket::TLS_ERR_SYS_EINVAL, {});
        return;
    }
    auto connect = connect_iterator->second;
    const auto &remoteCert = connect->GetRemoteCertRawData();
    if (!remoteCert.data.Length()) {
        int resErr = ConvertSSLError(connect->GetSSL());
        NETSTACK_LOGE("GetRemoteCertificate error is %{public}d %{public}d", resErr, errno);
        CallOnErrorCallback(resErr, MakeSSLErrorString(resErr));
        callback(resErr, {});
        return;
    }
    callback(TlsSocket::TLSSOCKET_SUCCESS, remoteCert);
}

void TLSSocketServer::GetProtocol(const TlsSocket::GetProtocolCallback &callback)
{
    if (TLSServerConfiguration_.GetProtocol() == TlsSocket::TLS_V1_3) {
        callback(TlsSocket::TLSSOCKET_SUCCESS, TlsSocket::PROTOCOL_TLS_V13);
        return;
    }
    callback(TlsSocket::TLSSOCKET_SUCCESS, TlsSocket::PROTOCOL_TLS_V12);
}

void TLSSocketServer::GetCipherSuite(const int socketFd, const TlsSocket::GetCipherSuiteCallback &callback)
{
    auto connect_iterator = clientIdConnections_.find(socketFd);
    if (connect_iterator == clientIdConnections_.end()) {
        NETSTACK_LOGE("socket = %{public}d The connection has been disconnected", socketFd);
        CallOnErrorCallback(TlsSocket::TLS_ERR_SYS_EINVAL, "The send failed with no corresponding socketFd");
        callback(TlsSocket::TLS_ERR_SYS_EINVAL, {});
        return;
    }
    auto connect = connect_iterator->second;
    auto cipherSuite = connect->GetCipherSuite();
    if (cipherSuite.empty()) {
        int resErr = ConvertSSLError(connect->GetSSL());
        NETSTACK_LOGE("GetCipherSuite error is %{public}d %{public}d", resErr, errno);
        CallOnErrorCallback(resErr, MakeSSLErrorString(resErr));
        callback(resErr, cipherSuite);
        return;
    }
    callback(TlsSocket::TLSSOCKET_SUCCESS, cipherSuite);
}

void TLSSocketServer::GetSignatureAlgorithms(const int socketFd,
                                             const TlsSocket::GetSignatureAlgorithmsCallback &callback)
{
    auto connect_iterator = clientIdConnections_.find(socketFd);
    if (connect_iterator == clientIdConnections_.end()) {
        NETSTACK_LOGE("socket = %{public}d The connection has been disconnected", socketFd);
        CallOnErrorCallback(TlsSocket::TLS_ERR_SYS_EINVAL, "The send failed with no corresponding socketFd");
        callback(TlsSocket::TLS_ERR_SYS_EINVAL, {});
        return;
    }
    auto connect = connect_iterator->second;
    auto signatureAlgorithms = connect->GetSignatureAlgorithms();
    if (signatureAlgorithms.empty()) {
        int resErr = ConvertSSLError(connect->GetSSL());
        NETSTACK_LOGE("GetSignatureAlgorithms error is %{public}d %{public}d", resErr, errno);
        CallOnErrorCallback(resErr, MakeSSLErrorString(resErr));
        callback(resErr, signatureAlgorithms);
        return;
    }
    callback(TlsSocket::TLSSOCKET_SUCCESS, signatureAlgorithms);
}

void TLSSocketServer::Connection::OnMessage(const OnMessageCallback &onMessageCallback)
{
    onMessageCallback_ = onMessageCallback;
    CachedMessageCallback();
}

void TLSSocketServer::Connection::OnClose(const OnCloseCallback &onCloseCallback)
{
    onCloseCallback_ = onCloseCallback;
}

void TLSSocketServer::OnConnect(const OnConnectCallback &onConnectCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    onConnectCallback_ = onConnectCallback;
}

void TLSSocketServer::OnError(const TlsSocket::OnErrorCallback &onErrorCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    onErrorCallback_ = onErrorCallback;
}

void TLSSocketServer::Connection::OffMessage()
{
    if (onMessageCallback_) {
        onMessageCallback_ = nullptr;
    }
}

void TLSSocketServer::OffConnect()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (onConnectCallback_) {
        onConnectCallback_ = nullptr;
    }
}

void TLSSocketServer::Connection::OnError(const TlsSocket::OnErrorCallback &onErrorCallback)
{
    onErrorCallback_ = onErrorCallback;
}

void TLSSocketServer::Connection::OffClose()
{
    if (onCloseCallback_) {
        onCloseCallback_ = nullptr;
    }
}

void TLSSocketServer::Connection::OffError()
{
    onErrorCallback_ = nullptr;
}

void TLSSocketServer::Connection::CallOnErrorCallback(int32_t err, const std::string &errString)
{
    TlsSocket::OnErrorCallback CallBackfunc = nullptr;
    {
        if (onErrorCallback_) {
            CallBackfunc = onErrorCallback_;
        }
    }

    if (CallBackfunc) {
        CallBackfunc(err, errString);
    }
}
void TLSSocketServer::OffError()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (onErrorCallback_) {
        onErrorCallback_ = nullptr;
    }
}

void TLSSocketServer::MakeIpSocket(sa_family_t family)
{
    if (family != AF_INET && family != AF_INET6) {
        return;
    }
    int sock = socket(family, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) {
        int resErr = ConvertErrno();
        NETSTACK_LOGE("Create socket failed (%{public}d:%{public}s)", errno, MakeErrnoString().c_str());
        CallOnErrorCallback(resErr, MakeErrnoString());
        return;
    }
    listenSocketFd_ = sock;
}

void TLSSocketServer::CallOnErrorCallback(int32_t err, const std::string &errString)
{
    TlsSocket::OnErrorCallback CallBackfunc = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (onErrorCallback_) {
            CallBackfunc = onErrorCallback_;
        }
    }

    if (CallBackfunc) {
        CallBackfunc(err, errString);
    }
}
void TLSSocketServer::GetAddr(const Socket::NetAddress &address, sockaddr_in *addr4, sockaddr_in6 *addr6,
                              sockaddr **addr, socklen_t *len)
{
    if (!addr6 || !addr4 || !len) {
        return;
    }
    sa_family_t family = address.GetSaFamily();
    if (family == AF_INET) {
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(address.GetPort());
        addr4->sin_addr.s_addr = inet_addr(address.GetAddress().c_str());
        *addr = reinterpret_cast<sockaddr *>(addr4);
        *len = sizeof(sockaddr_in);
    } else if (family == AF_INET6) {
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(address.GetPort());
        inet_pton(AF_INET6, address.GetAddress().c_str(), &addr6->sin6_addr);
        *addr = reinterpret_cast<sockaddr *>(addr6);
        *len = sizeof(sockaddr_in6);
    }
}

int TLSSocketServer::GetListenSocketFd()
{
    return listenSocketFd_;
}

void TLSSocketServer::SetLocalAddress(const Socket::NetAddress &address)
{
    localAddress_ = address;
}

Socket::NetAddress TLSSocketServer::GetLocalAddress()
{
    return localAddress_;
}

std::shared_ptr<TLSSocketServer::Connection> TLSSocketServer::GetConnectionByClientID(int clientid)
{
    std::shared_ptr<Connection> ptrConnection = nullptr;

    auto it = clientIdConnections_.find(clientid);
    if (it != clientIdConnections_.end()) {
        ptrConnection = it->second;
    }

    return ptrConnection;
}

int TLSSocketServer::GetConnectionClientCount()
{
    return g_userCounter;
}

void TLSSocketServer::CallListenCallback(int32_t err, ListenCallback callback)
{
    if (callback) {
        callback(err);
    }
}

void TLSSocketServer::Connection::SetAddress(const Socket::NetAddress address)
{
    address_ = address;
}

void TLSSocketServer::Connection::SetLocalAddress(const Socket::NetAddress address)
{
    localAddress_ = address;
}

const TlsSocket::X509CertRawData &TLSSocketServer::Connection::GetRemoteCertRawData() const
{
    return remoteRawData_;
}

TLSSocketServer::Connection::~Connection()
{
    NETSTACK_LOGI("TLSSocketServer ~conn");
    Close();
}

bool TLSSocketServer::Connection::TlsAcceptToHost(int sock, const TlsSocket::TLSConnectOptions &options)
{
    SetTlsConfiguration(options);
    std::string cipherSuite = options.GetTlsSecureOptions().GetCipherSuite();
    if (!cipherSuite.empty()) {
        connectionConfiguration_.SetCipherSuite(cipherSuite);
    }
    std::string signatureAlgorithms = options.GetTlsSecureOptions().GetSignatureAlgorithms();
    if (!signatureAlgorithms.empty()) {
        connectionConfiguration_.SetSignatureAlgorithms(signatureAlgorithms);
    }
    const auto protocolVec = options.GetTlsSecureOptions().GetProtocolChain();
    if (!protocolVec.empty()) {
        connectionConfiguration_.SetProtocol(protocolVec);
    }
    connectionConfiguration_.SetVerifyMode(options.GetTlsSecureOptions().GetVerifyMode());
    socketFd_ = sock;
    return StartTlsAccept(options);
}

void TLSSocketServer::Connection::SetTlsConfiguration(const TlsSocket::TLSConnectOptions &config)
{
    connectionConfiguration_.SetPrivateKey(config.GetTlsSecureOptions().GetKey(),
                                           config.GetTlsSecureOptions().GetKeyPass());
    connectionConfiguration_.SetLocalCertificate(config.GetTlsSecureOptions().GetCertChain());
    connectionConfiguration_.SetCaCertificate(config.GetTlsSecureOptions().GetCaChain());
    connectionConfiguration_.SetNetAddress(config.GetNetAddress());
}

bool TLSSocketServer::Connection::Send(const std::string &data)
{
    if (!ssl_) {
        NETSTACK_LOGE("ssl is null");
        return false;
    }
    if (data.empty()) {
        NETSTACK_LOGI("data is empty");
        return true;
    }
    int len = SSL_write(ssl_, data.c_str(), data.length());
    if (len < 0) {
        int resErr = ConvertSSLError(GetSSL());
        NETSTACK_LOGE("data send failed! error is %{public}d %{public}d", resErr, errno);
        return false;
    }
    NETSTACK_LOGD("data Sent successfully,sent in total %{public}d bytes!", len);
    return true;
}

int TLSSocketServer::Connection::Recv(char *buffer, int maxBufferSize)
{
    if (!ssl_) {
        NETSTACK_LOGE("ssl is null");
        return SSL_ERROR_RETURN;
    }
    return SSL_read(ssl_, buffer, maxBufferSize);
}

bool TLSSocketServer::Connection::Close()
{
    if (!ssl_) {
        NETSTACK_LOGE("ssl is null");
        return false;
    }
    int result = SSL_shutdown(ssl_);
    if (result < 0) {
        int resErr = ConvertSSLError(GetSSL());
        NETSTACK_LOGE("Error in shutdown, error is %{public}d %{public}d", resErr, errno);
    }
    SSL_free(ssl_);
    ssl_ = nullptr;
    if (socketFd_ != -1) {
        shutdown(socketFd_, SHUT_RDWR);
        close(socketFd_);
        NETSTACK_LOGI("close connection socketFd %{public}d", socketFd_);
        socketFd_ = -1;
    }
    if (!tlsContextServerPointer_) {
        NETSTACK_LOGE("Tls context pointer is null");
        return false;
    }
    tlsContextServerPointer_->CloseCtx();
    return true;
}

bool TLSSocketServer::Connection::SetAlpnProtocols(const std::vector<std::string> &alpnProtocols)
{
    if (!ssl_) {
        NETSTACK_LOGE("ssl is null");
        return false;
    }
    size_t pos = 0;
    size_t len = std::accumulate(alpnProtocols.begin(), alpnProtocols.end(), static_cast<size_t>(0),
                                 [](size_t init, const std::string &alpnProt) { return init + alpnProt.length(); });
    auto result = std::make_unique<unsigned char[]>(alpnProtocols.size() + len);
    for (const auto &str : alpnProtocols) {
        len = str.length();
        result[pos++] = len;
        if (!strcpy_s(reinterpret_cast<char *>(&result[pos]), len, str.c_str())) {
            NETSTACK_LOGE("strcpy_s failed");
            return false;
        }
        pos += len;
    }
    result[pos] = '\0';

    NETSTACK_LOGD("alpnProtocols after splicing %{public}s", result.get());
    if (SSL_set_alpn_protos(ssl_, result.get(), pos)) {
        int resErr = ConvertSSLError(GetSSL());
        NETSTACK_LOGE("Failed to set negotiable protocol list, error is %{public}d %{public}d", resErr, errno);
        return false;
    }
    return true;
}

void TLSSocketServer::Connection::MakeRemoteInfo(Socket::SocketRemoteInfo &remoteInfo)
{
    remoteInfo.SetAddress(address_.GetAddress());
    remoteInfo.SetPort(address_.GetPort());
    remoteInfo.SetFamily(address_.GetSaFamily());
}

TlsSocket::TLSConfiguration TLSSocketServer::Connection::GetTlsConfiguration() const
{
    return connectionConfiguration_;
}

std::vector<std::string> TLSSocketServer::Connection::GetCipherSuite() const
{
    if (!ssl_) {
        NETSTACK_LOGE("ssl in null");
        return {};
    }
    STACK_OF(SSL_CIPHER) *sk = SSL_get_ciphers(ssl_);
    if (!sk) {
        NETSTACK_LOGE("get ciphers failed");
        return {};
    }
    TlsSocket::CipherSuite cipherSuite;
    std::vector<std::string> cipherSuiteVec;
    for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
        const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
        cipherSuite.cipherName_ = SSL_CIPHER_get_name(c);
        cipherSuiteVec.push_back(cipherSuite.cipherName_);
    }
    return cipherSuiteVec;
}

std::string TLSSocketServer::Connection::GetRemoteCertificate() const
{
    return remoteCert_;
}

const TlsSocket::X509CertRawData &TLSSocketServer::Connection::GetCertificate() const
{
    return connectionConfiguration_.GetCertificate();
}

std::vector<std::string> TLSSocketServer::Connection::GetSignatureAlgorithms() const
{
    return signatureAlgorithms_;
}

std::string TLSSocketServer::Connection::GetProtocol() const
{
    if (!ssl_) {
        NETSTACK_LOGE("ssl in null");
        return PROTOCOL_UNKNOW;
    }
    if (connectionConfiguration_.GetProtocol() == TlsSocket::TLS_V1_3) {
        return TlsSocket::PROTOCOL_TLS_V13;
    }
    return TlsSocket::PROTOCOL_TLS_V12;
}

bool TLSSocketServer::Connection::SetSharedSigals()
{
    if (!ssl_) {
        NETSTACK_LOGE("ssl is null");
        return false;
    }
    int number = SSL_get_shared_sigalgs(ssl_, 0, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!number) {
        NETSTACK_LOGE("SSL_get_shared_sigalgs return value error");
        return false;
    }
    for (int i = 0; i < number; i++) {
        int hash_nid;
        int sign_nid;
        std::string sig_with_md;
        SSL_get_shared_sigalgs(ssl_, i, &sign_nid, &hash_nid, nullptr, nullptr, nullptr);
        switch (sign_nid) {
            case EVP_PKEY_RSA:
                sig_with_md = SIGN_NID_RSA;
                break;
            case EVP_PKEY_RSA_PSS:
                sig_with_md = SIGN_NID_RSA_PSS;
                break;
            case EVP_PKEY_DSA:
                sig_with_md = SIGN_NID_DSA;
                break;
            case EVP_PKEY_EC:
                sig_with_md = SIGN_NID_ECDSA;
                break;
            case NID_ED25519:
                sig_with_md = SIGN_NID_ED;
                break;
            case NID_ED448:
                sig_with_md = SIGN_NID_ED_FOUR_FOUR_EIGHT;
                break;
            default:
                const char *sn = OBJ_nid2sn(sign_nid);
                sig_with_md = (sn != nullptr) ? (std::string(sn) + OPERATOR_PLUS_SIGN) : SIGN_NID_UNDEF_ADD;
        }
        const char *sn_hash = OBJ_nid2sn(hash_nid);
        sig_with_md += (sn_hash != nullptr) ? std::string(sn_hash) : SIGN_NID_UNDEF;
        signatureAlgorithms_.push_back(sig_with_md);
    }
    return true;
}

ssl_st *TLSSocketServer::Connection::GetSSL() const
{
    return ssl_;
}

Socket::NetAddress TLSSocketServer::Connection::GetAddress() const
{
    return address_;
}

Socket::NetAddress TLSSocketServer::Connection::GetLocalAddress() const
{
    return localAddress_;
}

int TLSSocketServer::Connection::GetSocketFd() const
{
    return socketFd_;
}

std::shared_ptr<EventManager> TLSSocketServer::Connection::GetEventManager() const
{
    return eventManager_;
}

void TLSSocketServer::Connection::SetEventManager(std::shared_ptr<EventManager> eventManager)
{
    eventManager_ = eventManager;
}

void TLSSocketServer::Connection::SetClientID(int32_t clientID)
{
    clientID_ = clientID;
}

int TLSSocketServer::Connection::GetClientID()
{
    return clientID_;
}

bool TLSSocketServer::Connection::StartTlsAccept(const TlsSocket::TLSConnectOptions &options)
{
    if (!CreatTlsContext()) {
        NETSTACK_LOGE("failed to create tls context");
        return false;
    }
    if (!StartShakingHands(options)) {
        NETSTACK_LOGE("failed to shaking hands");
        return false;
    }
    return true;
}

bool TLSSocketServer::Connection::CreatTlsContext()
{
    tlsContextServerPointer_ = TlsSocket::TLSContextServer::CreateConfiguration(connectionConfiguration_);
    if (!tlsContextServerPointer_) {
        NETSTACK_LOGE("failed to create tls context pointer");
        return false;
    }
    if (!(ssl_ = tlsContextServerPointer_->CreateSsl())) {
        NETSTACK_LOGE("failed to create ssl session");
        return false;
    }
    SSL_set_fd(ssl_, socketFd_);
    SSL_set_accept_state(ssl_);
    return true;
}

bool TLSSocketServer::Connection::StartShakingHands(const TlsSocket::TLSConnectOptions &options)
{
    if (!ssl_) {
        NETSTACK_LOGE("ssl is null");
        return false;
    }
    int result = SSL_accept(ssl_);
    if (result == -1) {
        int errorStatus = ConvertSSLError(ssl_);
        NETSTACK_LOGE("SSL connect is error, errno is %{public}d, error info is %{public}s", errorStatus,
                      MakeSSLErrorString(errorStatus).c_str());
        return false;
    }

    std::vector<std::string> SslProtocolVer({SSL_get_version(ssl_)});
    connectionConfiguration_.SetProtocol({SslProtocolVer});

    const char *cipherList = SSL_get_cipher_list(ssl_, 0);
    std::string list = (cipherList == NULL) ? "" : cipherList;
    NETSTACK_LOGI("SSL_get_cipher_list: %{public}s", list.c_str());
    connectionConfiguration_.SetCipherSuite(list);
    if (!SetSharedSigals()) {
        NETSTACK_LOGE("Failed to set sharedSigalgs");
    }
    X509 *peerX509 = SSL_get_peer_certificate(ssl_);
    if (!GetRemoteCertificateFromPeer(peerX509)) {
        NETSTACK_LOGE("Failed to get remote certificate");
    }
    if (peerX509 != nullptr) {
        NETSTACK_LOGE("peer x509Certificates is null");

        if (!SetRemoteCertRawData(peerX509)) {
            NETSTACK_LOGE("Failed to set remote x509 certificata Serialization data");
        }
        TlsSocket::CheckServerIdentity checkServerIdentity = options.GetCheckServerIdentity();
        if (!checkServerIdentity) {
            CheckServerIdentityLegal(hostName_, peerX509);
        } else {
            checkServerIdentity(hostName_, {remoteCert_});
        }
    }
    X509_free(peerX509);
    return true;
}

bool TLSSocketServer::Connection::GetRemoteCertificateFromPeer(X509 *peerX509)
{
    if (SSL_get_verify_result(ssl_) == X509_V_OK) {
        NETSTACK_LOGE("SSL_get_verify_result ==X509_V_OK");
    }

    if (peerX509 == nullptr) {
        int resErr = ConvertSSLError(GetSSL());
        NETSTACK_LOGE("open fail errno, errno is %{public}d, error info is %{public}s", resErr,
                      MakeSSLErrorString(resErr).c_str());
        return false;
    }
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        NETSTACK_LOGE("TlsSocket::SetRemoteCertificate bio is null");
        return false;
    }
    X509_print(bio, peerX509);
    char data[REMOTE_CERT_LEN] = {0};
    if (!BIO_read(bio, data, REMOTE_CERT_LEN)) {
        NETSTACK_LOGE("BIO_read function returns error");
        BIO_free(bio);
        return false;
    }
    BIO_free(bio);
    remoteCert_ = std::string(data);
    return true;
}

bool TLSSocketServer::Connection::SetRemoteCertRawData(X509 *peerX509)
{
    if (peerX509 == nullptr) {
        NETSTACK_LOGE("peerX509 is null");
        return false;
    }
    int32_t length = i2d_X509(peerX509, nullptr);
    if (length <= 0) {
        NETSTACK_LOGE("Failed to convert peerX509 to der format");
        return false;
    }
    unsigned char *der = nullptr;
    (void)i2d_X509(peerX509, &der);
    TlsSocket::SecureData data(der, length);
    remoteRawData_.data = data;
    OPENSSL_free(der);
    remoteRawData_.encodingFormat = TlsSocket::EncodingFormat::DER;
    return true;
}

static bool StartsWith(const std::string &s, const std::string &prefix)
{
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}
void CheckIpAndDnsName(const std::string &hostName, std::vector<std::string> &dnsNames, std::vector<std::string> &ips,
                       const X509 *x509Certificates, std::tuple<bool, std::string> &result)
{
    bool valid = false;
    std::string reason = UNKNOW_REASON;
    int index = X509_get_ext_by_NID(x509Certificates, NID_commonName, -1);
    if (IsIP(hostName)) {
        auto it = find(ips.begin(), ips.end(), hostName);
        if (it == ips.end()) {
            reason = IP + hostName + " is not in the cert's list";
        }
        result = {valid, reason};
        return;
    }
    std::string tempHostName = "" + hostName;
    if (!dnsNames.empty() || index > 0) {
        std::vector<std::string> hostParts = SplitHostName(tempHostName);
        std::string tmpStr = "";
        if (!dnsNames.empty()) {
            valid = SeekIntersection(hostParts, dnsNames);
            tmpStr = ". is not in the cert's altnames";
        } else {
            char commonNameBuf[COMMON_NAME_BUF_SIZE] = {0};
            X509_NAME *pSubName = nullptr;
            int len = X509_NAME_get_text_by_NID(pSubName, NID_commonName, commonNameBuf, COMMON_NAME_BUF_SIZE);
            if (len > 0) {
                std::vector<std::string> commonNameVec;
                commonNameVec.emplace_back(commonNameBuf);
                valid = SeekIntersection(hostParts, commonNameVec);
                tmpStr = ". is not cert's CN";
            }
        }
        if (!valid) {
            reason = HOST_NAME + tempHostName + tmpStr;
        }

        result = {valid, reason};
        return;
    }
    reason = "Cert does not contain a DNS name";
    result = {valid, reason};
}

std::string TLSSocketServer::Connection::CheckServerIdentityLegal(const std::string &hostName,
                                                                  const X509 *x509Certificates)
{
    X509_NAME *subjectName = X509_get_subject_name(x509Certificates);
    if (!subjectName) {
        return "subject name is null";
    }
    char subNameBuf[BUF_SIZE] = {0};
    X509_NAME_oneline(subjectName, subNameBuf, BUF_SIZE);
    int index = X509_get_ext_by_NID(x509Certificates, NID_subject_alt_name, -1);
    if (index < 0) {
        return "X509 get ext nid error";
    }
    X509_EXTENSION *ext = X509_get_ext(x509Certificates, index);
    if (ext == nullptr) {
        return "X509 get ext error";
    }
    ASN1_OBJECT *obj = nullptr;
    obj = X509_EXTENSION_get_object(ext);
    char subAltNameBuf[BUF_SIZE] = {0};
    OBJ_obj2txt(subAltNameBuf, BUF_SIZE, obj, 0);
    NETSTACK_LOGD("extions obj : %{public}s\n", subAltNameBuf);

    return CheckServerIdentityLegal(hostName, ext, x509Certificates);
}

std::string TLSSocketServer::Connection::CheckServerIdentityLegal(const std::string &hostName, X509_EXTENSION *ext,
                                                                  const X509 *x509Certificates)
{
    ASN1_OCTET_STRING *extData = X509_EXTENSION_get_data(ext);
    if (!extData) {
        NETSTACK_LOGE("extData is nullptr");
        return "";
    }
    std::string altNames = reinterpret_cast<char *>(extData->data);
    std::string hostname = "" + hostName;
    BIO *bio = BIO_new(BIO_s_file());
    if (!bio) {
        return "bio is null";
    }
    BIO_set_fp(bio, stdout, BIO_NOCLOSE);
    ASN1_STRING_print(bio, extData);
    std::vector<std::string> dnsNames = {};
    std::vector<std::string> ips = {};
    constexpr int DNS_NAME_IDX = 4;
    constexpr int IP_NAME_IDX = 11;
    if (!altNames.empty()) {
        std::vector<std::string> splitAltNames;
        if (altNames.find('\"') != std::string::npos) {
            splitAltNames = SplitEscapedAltNames(altNames);
        } else {
            splitAltNames = CommonUtils::Split(altNames, SPLIT_ALT_NAMES);
        }
        for (auto const &iter : splitAltNames) {
            if (StartsWith(iter, DNS)) {
                dnsNames.push_back(iter.substr(DNS_NAME_IDX));
            } else if (StartsWith(iter, IP_ADDRESS)) {
                ips.push_back(iter.substr(IP_NAME_IDX));
            }
        }
    }
    std::tuple<bool, std::string> result;
    CheckIpAndDnsName(hostName, dnsNames, ips, x509Certificates, result);
    if (!std::get<0>(result)) {
        return "Hostname/IP does not match certificate's altnames: " + std::get<1>(result);
    }
    return HOST_NAME + hostname + ". is cert's CN";
}

void TLSSocketServer::RemoveConnect(int socketFd)
{
    std::unique_lock<std::shared_mutex> its_lock(connectMutex_);
    for (auto it = clientIdConnections_.begin(); it != clientIdConnections_.end(); ++it) {
        if (it->second == nullptr) {
            NETSTACK_LOGE("tlsconnection is nullptr");
            continue;
        }
        if (it->second->GetSocketFd() == socketFd) {
            clientIdConnections_.erase(it);
            break;
        }
    }
}

bool TLSSocketServer::RecvRemoteInfo(int socketFd, int index)
{
    {
        std::shared_lock<std::shared_mutex> its_lock(connectMutex_);
        for (auto it = clientIdConnections_.begin(); it != clientIdConnections_.end();) {
            if (it->second == nullptr) {
                NETSTACK_LOGE("tlsconnection is nullptr");
                return false;
            }
            if (it->second->GetSocketFd() == socketFd) {
                char buffer[MAX_BUFFER_SIZE];
                if (memset_s(buffer, MAX_BUFFER_SIZE, 0, MAX_BUFFER_SIZE) != EOK) {
                    NETSTACK_LOGE("memcpy_s failed");
                    break;
                }
                int len = it->second->Recv(buffer, MAX_BUFFER_SIZE);
                NETSTACK_LOGE("revc message is size is %{public}d", len);
                if (len > 0) {
                    Socket::SocketRemoteInfo remoteInfo;
                    remoteInfo.SetSize(strlen(buffer));
                    it->second->MakeRemoteInfo(remoteInfo);
                    it->second->CallOnMessageCallback(socketFd, buffer, remoteInfo);
                    return false;
                } else if (len == 0) {
                    NETSTACK_LOGE("tls connection is closed by peer, clientId: %{public}d, Fd: %{public}d",
                        it->second->GetClientID(), socketFd);
                    it->second->CallOnCloseCallback(socketFd);
                    break;
                } else {
                    int resErr = ConvertSSLError(it->second->GetSSL());
                    NETSTACK_LOGE("recv fail, clientId: %{public}d, Fd: %{public}d, "
                        "ssl error is %{public}d, error info is %{public}s",
                        it->second->GetClientID(), socketFd, resErr, MakeSSLErrorString(resErr).c_str());
                    it->second->CallOnErrorCallback(resErr, MakeSSLErrorString(resErr));
                    break;
                }
#if defined(CROSS_PLATFORM)
                if (len == 0 &&  errno == 0) {
                    NETSTACK_LOGI("A client left");
                }
#endif
            } else {
                ++it;
            }
        }
    }
    RemoveConnect(socketFd);
    return DropFdFromPollList(index);
}

void TLSSocketServer::Connection::CachedMessageCallback()
{
    int32_t socketFd = GetSocketFd();
    if (socketFd < 0) {
        NETSTACK_LOGE("socketFd is invalid to recv message");
        return;
    }
    if (onMessageCallback_) {
        while (!dataCache_->IsEmpty()) {
            CacheInfo cache = dataCache_->Get();
            onMessageCallback_(socketFd, cache.data, cache.remoteInfo);
        }
    }
    NETSTACK_LOGD("Cached message is callbacked for socket %{public}d", socketFd);
}

void TLSSocketServer::Connection::CallOnMessageCallback(int32_t socketFd, const std::string &data,
                                                        const Socket::SocketRemoteInfo &remoteInfo)
{
    OnMessageCallback CallBackfunc = nullptr;
    {
        if (onMessageCallback_) {
            CallBackfunc = onMessageCallback_;
        }
    }

    if (CallBackfunc) {
        while (!dataCache_->IsEmpty()) {
            CacheInfo cache = dataCache_->Get();
            CallBackfunc(socketFd, cache.data, cache.remoteInfo);
        }
        CallBackfunc(socketFd, data, remoteInfo);
    } else {
        NETSTACK_LOGD("message callback is not registered");
        CacheInfo cache = {data, remoteInfo};
        dataCache_->Set(cache);
    }
}

void TLSSocketServer::AddConnect(int socketFd, std::shared_ptr<Connection> connection)
{
    std::unique_lock<std::shared_mutex> its_lock(connectMutex_);
    clientIdConnections_[connection->GetClientID()] = connection;
}

void TLSSocketServer::Connection::CallOnCloseCallback(const int32_t socketFd)
{
    OnCloseCallback CallBackfunc = nullptr;
    {
        if (onCloseCallback_) {
            CallBackfunc = onCloseCallback_;
        }
    }

    if (CallBackfunc) {
        CallBackfunc(socketFd);
    }
}

void TLSSocketServer::CallOnConnectCallback(const int32_t socketFd, std::shared_ptr<EventManager> eventManager)
{
    OnConnectCallback CallBackfunc = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (onConnectCallback_) {
            CallBackfunc = onConnectCallback_;
        }
    }

    if (CallBackfunc) {
        CallBackfunc(socketFd, eventManager);
    } else {
        NETSTACK_LOGE("CallOnConnectCallback  fun === null");
    }
}

bool TLSSocketServer::GetTlsConnectionLocalAddress(int acceptSockFD, Socket::NetAddress &localAddress)
{
    struct sockaddr_storage addr{};
    socklen_t addrLen = sizeof(addr);
    if (getsockname(acceptSockFD, (struct sockaddr *)&addr, &addrLen) < 0) {
        if (acceptSockFD > 0) {
            close(acceptSockFD);
            CallOnErrorCallback(errno, strerror(errno));
            return false;
        }
    }
    char ipStr[INET6_ADDRSTRLEN] = {0};
    if (addr.ss_family == AF_INET) {
        auto *addr_in = (struct sockaddr_in *)&addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, ipStr, sizeof(ipStr));
        localAddress.SetFamilyBySaFamily(AF_INET);
        localAddress.SetRawAddress(ipStr);
        localAddress.SetPort(ntohs(addr_in->sin_port));
    } else if (addr.ss_family == AF_INET6) {
        auto *addr_in6 = (struct sockaddr_in6 *)&addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ipStr, sizeof(ipStr));
        localAddress.SetFamilyBySaFamily(AF_INET6);
        localAddress.SetRawAddress(ipStr);
        localAddress.SetPort(ntohs(addr_in6->sin6_port));
    }
    return true;
}

void TLSSocketServer::ProcessTcpAccept(const TlsSocket::TLSConnectOptions &tlsListenOptions, int clientID)
{
    struct sockaddr_in clientAddress;
    socklen_t clientAddrLength = sizeof(clientAddress);
    int connectFD = accept(listenSocketFd_, (struct sockaddr *)&clientAddress, &clientAddrLength);
    if (connectFD < 0) {
        int resErr = ConvertErrno();
        NETSTACK_LOGE("Server accept new client ERROR");
        CallOnErrorCallback(resErr, MakeErrnoString());
        return;
    }
    NETSTACK_LOGI("Server accept new client SUCCESS");
    std::shared_ptr<Connection> connection = std::make_shared<Connection>();
    Socket::NetAddress netAddress;
    Socket::NetAddress localAddress;
    char clientIp[INET6_ADDRSTRLEN] = {0};
    inet_ntop(address_.GetSaFamily(), &clientAddress.sin_addr, clientIp, INET_ADDRSTRLEN);
    int clientPort = ntohs(clientAddress.sin_port);
    netAddress.SetRawAddress(clientIp);
    netAddress.SetPort(clientPort);
    netAddress.SetFamilyBySaFamily(address_.GetSaFamily());
    connection->SetAddress(netAddress);
    if (!GetTlsConnectionLocalAddress(connectFD, localAddress)) {
        NETSTACK_LOGE("GetTlsConnectionLocalAddress");
        return;
    }
    connection->SetLocalAddress(localAddress);
    SetTlsConnectionSecureOptions(tlsListenOptions, clientID, connectFD, connection);
}
void TLSSocketServer::SetTlsConnectionSecureOptions(const TlsSocket::TLSConnectOptions &tlsListenOptions, int clientID,
                                                    int connectFD, std::shared_ptr<Connection> &connection)
{
    connection->SetClientID(clientID);
    auto res = connection->TlsAcceptToHost(connectFD, tlsListenOptions);
    if (!res) {
        int resErr = ConvertSSLError(connection->GetSSL());
        NETSTACK_LOGE("setTlsConnectionSecureOptions error is %{public}d %{public}d", resErr, errno);
        CallOnErrorCallback(resErr, MakeSSLErrorString(resErr));
        return;
    }
    if (g_userCounter >= USER_LIMIT) {
        const std::string info = "Too many users!";
        connection->Send(info);
        connection->Close();
        NETSTACK_LOGE("Too many users");
        if (connection->GetSocketFd() != -1) {
            close(connectFD);
        }
        CallOnErrorCallback(-1, "Too many users");
        return;
    }
    g_userCounter++;
    fds_[g_userCounter].fd = connectFD;
#if defined(CROSS_PLATFORM)
    fds_[g_userCounter].events = POLLIN | POLLERR;
#else
    fds_[g_userCounter].events = POLLIN | POLLRDHUP | POLLERR;
#endif
    fds_[g_userCounter].revents = 0;
    AddConnect(connectFD, connection);
    auto ptrEventManager = std::make_shared<EventManager>();
    ptrEventManager->SetData(this);
    connection->SetEventManager(ptrEventManager);
    CallOnConnectCallback(clientID, ptrEventManager);
    NETSTACK_LOGI("New client come in, fd is %{public}d", connectFD);
}

void TLSSocketServer::InitPollList(const int &listendFd)
{
    fds_[0].fd = listendFd;
    fds_[0].events = POLLIN | POLLERR;
    fds_[0].revents = 0;
}

bool TLSSocketServer::DropFdFromPollList(int &fd_index)
{
    if (g_userCounter < 0) {
        NETSTACK_LOGE("g_userCounter = %{public}d", g_userCounter);
        return true;
    }
    if (fd_index == 0) {
        // index 0 is for listen only
        fds_[0].fd = -1;
        fds_[0].events = 0;
        NETSTACK_LOGI("drop listenFd from poll List, g_userCounter = %{public}d", g_userCounter);
    } else {
        // remove the fd_index, and insert the last index
        fds_[fd_index].fd = fds_[g_userCounter].fd;
        fds_[g_userCounter].fd = -1;
        fds_[g_userCounter].events = 0;
        fd_index--;
        g_userCounter--;
        NETSTACK_LOGI("drop clientFd from poll List, g_userCounter = %{public}d", g_userCounter);
    }
    for (int i = 0; i < g_userCounter + 1; ++i) {
        if (fds_[i].fd > 0) {
            return false;
        }
    }
    return true;
}
void TLSSocketServer::NotifyRcvThdExit()
{
    std::unique_lock<std::mutex> lock(sockRcvThdMtx_);
    sockRcvExit_ = true;
    sockRcvThdCon_.notify_one();
    NETSTACK_LOGI("recv thread exit");
}

void TLSSocketServer::WaitForRcvThdExit()
{
    std::unique_lock<std::mutex> lock(sockRcvThdMtx_);
    sockRcvThdCon_.wait(lock, [this]() { return sockRcvExit_; });
}

void TLSSocketServer::PollThread(const TlsSocket::TLSConnectOptions &tlsListenOptions)
{
    int on = 1;
    isRunning_ = true;
    ioctl(listenSocketFd_, FIONBIO, (char *)&on);
    NETSTACK_LOGI("PollThread  start working %{public}d", isRunning_);
    std::thread thread_([this, tlsOption = tlsListenOptions]() {
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
        pthread_setname_np(TLS_SOCKET_SERVER_READ);
#else
        pthread_setname_np(pthread_self(), TLS_SOCKET_SERVER_READ);
#endif
        InitPollList(listenSocketFd_);
        bool exitLoop = false;
        while (isRunning_ && !exitLoop) {
            int ret = poll(fds_, g_userCounter + 1, POLL_WAIT_TIME);
            if (ret < 0) {
                int resErr = ConvertErrno();
                NETSTACK_LOGE("Poll ERROR");
                CallOnErrorCallback(resErr, MakeErrnoString());
                break;
            }
            if (ret == 0) {
                continue;
            }
            for (int i = 0; i < g_userCounter + 1; ++i) {
                if ((fds_[i].fd == listenSocketFd_) && (static_cast<uint16_t>(fds_[i].revents) & POLLIN)) {
                    ProcessTcpAccept(tlsOption, g_userCounter + 1);
#if !defined(CROSS_PLATFORM)
                } else if ((static_cast<uint16_t>(fds_[i].revents) & POLLRDHUP) ||
                           (static_cast<uint16_t>(fds_[i].revents) & (POLLERR | POLLNVAL))) {
#else
                } else if ((static_cast<uint16_t>(fds_[i].revents) & POLLERR | POLLNVAL)) {
#endif
                    RemoveConnect(fds_[i].fd);
                    exitLoop = DropFdFromPollList(i);
                } else if (static_cast<uint16_t>(fds_[i].revents) & POLLIN) {
                    exitLoop = RecvRemoteInfo(fds_[i].fd, i);
                }
            }
        }
        isRunning_ = false;
        NotifyRcvThdExit();
    });
    thread_.detach();
}

std::shared_ptr<TLSSocketServer::Connection> TLSSocketServer::GetConnectionByClientEventManager(
    const std::shared_ptr<EventManager> &eventManager)
{
    std::shared_lock<std::shared_mutex> its_lock(connectMutex_);
    auto it = std::find_if(clientIdConnections_.begin(), clientIdConnections_.end(), [eventManager](const auto& pair) {
        return pair.second->GetEventManager() == eventManager;
    });
    if (it == clientIdConnections_.end()) {
        return nullptr;
    }
    return it->second;
}

void TLSSocketServer::CloseConnectionByEventManager(const std::shared_ptr<EventManager> &eventManager)
{
    std::shared_ptr<Connection> ptrConnection = GetConnectionByClientEventManager(eventManager);

    if (ptrConnection != nullptr) {
        ptrConnection->Close();
    }
}

void TLSSocketServer::DeleteConnectionByEventManager(const std::shared_ptr<EventManager> &eventManager)
{
    std::unique_lock<std::shared_mutex> its_lock(connectMutex_);
    for (auto it = clientIdConnections_.begin(); it != clientIdConnections_.end(); ++it) {
        if (it->second->GetEventManager() == eventManager) {
            it = clientIdConnections_.erase(it);
            break;
        }
    }
}
} // namespace TlsSocketServer
} // namespace NetStack
} // namespace OHOS
