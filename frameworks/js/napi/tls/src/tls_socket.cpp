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

#include "tls_socket.h"

#include <chrono>
#include <memory>
#include <numeric>
#include <poll.h>
#include <regex>
#include <securec.h>
#include <set>
#include <thread>

#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "base_context.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "socket_exec_common.h"
#include "tls.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
namespace {
constexpr int READ_TIMEOUT_MS = 500;
constexpr int REMOTE_CERT_LEN = 8192;
constexpr int COMMON_NAME_BUF_SIZE = 256;
constexpr int BUF_SIZE = 2048;
constexpr int SSL_RET_CODE = 0;
constexpr int SSL_ERROR_RETURN = -1;
constexpr int SSL_WANT_READ_RETURN = -2;
constexpr int OFFSET = 2;
constexpr int DEFAULT_BUFFER_SIZE = 8192;
constexpr int DEFAULT_POLL_TIMEOUT_MS = 500;
constexpr int SEND_RETRY_TIMES = 5;
constexpr int SEND_POLL_TIMEOUT_MS = 1000;
constexpr int MAX_RECV_BUFFER_SIZE = 1024 * 16;
constexpr const char *SPLIT_ALT_NAMES = ",";
constexpr const char *SPLIT_HOST_NAME = ".";
constexpr const char *UNKNOW_REASON = "Unknown reason";
constexpr const char *IP = "IP: ";
constexpr const char *HOST_NAME = "hostname: ";
constexpr const char *DNS = "DNS:";
constexpr const char *IP_ADDRESS = "IP Address:";
constexpr const char *SIGN_NID_RSA = "RSA+";
constexpr const char *SIGN_NID_RSA_PSS = "RSA-PSS+";
constexpr const char *SIGN_NID_DSA = "DSA+";
constexpr const char *SIGN_NID_ECDSA = "ECDSA+";
constexpr const char *SIGN_NID_ED = "Ed25519+";
constexpr const char *SIGN_NID_ED_FOUR_FOUR_EIGHT = "Ed448+";
constexpr const char *SIGN_NID_UNDEF_ADD = "UNDEF+";
constexpr const char *SIGN_NID_UNDEF = "UNDEF";
constexpr const char *OPERATOR_PLUS_SIGN = "+";
static constexpr const char *TLS_SOCKET_CLIENT_READ = "OS_NET_TSCliRD";
const std::regex JSON_STRING_PATTERN{R"(/^"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/)"};
const std::regex PATTERN{
    "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|"
    "2[0-4][0-9]|[01]?[0-9][0-9]?)"};

class CaCertCache {
public:
    static CaCertCache &GetInstance()
    {
        static CaCertCache instance;
        return instance;
    }

    std::set<std::string> Get(const std::string &key)
    {
        std::lock_guard l(mutex_);
        auto it = map_.find(key);
        if (it != map_.end()) {
            return it->second;
        }
        return {};
    }

    void Set(const std::string &key, const std::string &val)
    {
        std::lock_guard l(mutex_);
        map_[key].insert(val);
    }

private:
    CaCertCache() = default;
    ~CaCertCache() = default;
    CaCertCache &operator=(const CaCertCache &) = delete;
    CaCertCache(const CaCertCache &) = delete;

    std::map<std::string, std::set<std::string>> map_;
    std::mutex mutex_;
};

int ConvertErrno()
{
    return TlsSocketError::TLS_ERR_SYS_BASE + errno;
}

std::string MakeErrnoString()
{
    return strerror(errno);
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
} // namespace

static bool SetSockBlockFlag(int sock, bool noneBlock)
{
    int flags = fcntl(sock, F_GETFL, 0);
    while (flags == -1 && errno == EINTR) {
        flags = fcntl(sock, F_GETFL, 0);
    }
    if (flags == -1) {
        NETSTACK_LOGE("set block flags failed, socket is %{public}d, errno is %{public}d", sock, errno);
        return false;
    }

    auto newFlags = static_cast<size_t>(flags);
    if (noneBlock) {
        newFlags |= static_cast<size_t>(O_NONBLOCK);
    } else {
        newFlags &= ~static_cast<size_t>(O_NONBLOCK);
    }

    int ret = fcntl(sock, F_SETFL, newFlags);
    while (ret == -1 && errno == EINTR) {
        ret = fcntl(sock, F_SETFL, newFlags);
    }
    if (ret == -1) {
        NETSTACK_LOGE("set block flags failed, socket is %{public}d, errno is %{public}d", sock, errno);
        return false;
    }
    return true;
}

TLSSecureOptions::TLSSecureOptions(const TLSSecureOptions &tlsSecureOptions)
{
    *this = tlsSecureOptions;
}

TLSSecureOptions &TLSSecureOptions::operator=(const TLSSecureOptions &tlsSecureOptions)
{
    key_ = tlsSecureOptions.GetKey();
    caChain_ = tlsSecureOptions.GetCaChain();
    certChain_ = tlsSecureOptions.GetCertChain();
    protocolChain_ = tlsSecureOptions.GetProtocolChain();
    crlChain_ = tlsSecureOptions.GetCrlChain();
    keyPass_ = tlsSecureOptions.GetKeyPass();
    key_ = tlsSecureOptions.GetKey();
    signatureAlgorithms_ = tlsSecureOptions.GetSignatureAlgorithms();
    cipherSuite_ = tlsSecureOptions.GetCipherSuite();
    useRemoteCipherPrefer_ = tlsSecureOptions.UseRemoteCipherPrefer();
    TLSVerifyMode_ = tlsSecureOptions.GetVerifyMode();
    return *this;
}

void TLSSecureOptions::SetCaChain(const std::vector<std::string> &caChain)
{
    caChain_ = caChain;
}

void TLSSecureOptions::SetCertChain(const std::vector<std::string> &certChain)
{
    certChain_ = certChain;
}

void TLSSecureOptions::SetKey(const SecureData &key)
{
    key_ = key;
}

void TLSSecureOptions::SetKeyPass(const SecureData &keyPass)
{
    keyPass_ = keyPass;
}

void TLSSecureOptions::SetProtocolChain(const std::vector<std::string> &protocolChain)
{
    protocolChain_ = protocolChain;
}

void TLSSecureOptions::SetUseRemoteCipherPrefer(bool useRemoteCipherPrefer)
{
    useRemoteCipherPrefer_ = useRemoteCipherPrefer;
}

void TLSSecureOptions::SetSignatureAlgorithms(const std::string &signatureAlgorithms)
{
    signatureAlgorithms_ = signatureAlgorithms;
}

void TLSSecureOptions::SetCipherSuite(const std::string &cipherSuite)
{
    cipherSuite_ = cipherSuite;
}

void TLSSecureOptions::SetCrlChain(const std::vector<std::string> &crlChain)
{
    crlChain_ = crlChain;
}

const std::vector<std::string> &TLSSecureOptions::GetCaChain() const
{
    return caChain_;
}

const std::vector<std::string> &TLSSecureOptions::GetCertChain() const
{
    return certChain_;
}

const SecureData &TLSSecureOptions::GetKey() const
{
    return key_;
}

const SecureData &TLSSecureOptions::GetKeyPass() const
{
    return keyPass_;
}

const std::vector<std::string> &TLSSecureOptions::GetProtocolChain() const
{
    return protocolChain_;
}

bool TLSSecureOptions::UseRemoteCipherPrefer() const
{
    return useRemoteCipherPrefer_;
}

const std::string &TLSSecureOptions::GetSignatureAlgorithms() const
{
    return signatureAlgorithms_;
}

const std::string &TLSSecureOptions::GetCipherSuite() const
{
    return cipherSuite_;
}

const std::vector<std::string> &TLSSecureOptions::GetCrlChain() const
{
    return crlChain_;
}

void TLSSecureOptions::SetVerifyMode(VerifyMode verifyMode)
{
    TLSVerifyMode_ = verifyMode;
}

VerifyMode TLSSecureOptions::GetVerifyMode() const
{
    return TLSVerifyMode_;
}

void TLSConnectOptions::SetNetAddress(const Socket::NetAddress &address)
{
    address_.SetFamilyBySaFamily(address.GetSaFamily());
    address_.SetRawAddress(address.GetAddress());
    address_.SetPort(address.GetPort());
}

void TLSConnectOptions::SetTlsSecureOptions(TLSSecureOptions &tlsSecureOptions)
{
    tlsSecureOptions_ = tlsSecureOptions;
}

void TLSConnectOptions::SetCheckServerIdentity(const CheckServerIdentity &checkServerIdentity)
{
    checkServerIdentity_ = checkServerIdentity;
}

void TLSConnectOptions::SetAlpnProtocols(const std::vector<std::string> &alpnProtocols)
{
    alpnProtocols_ = alpnProtocols;
}

void TLSConnectOptions::SetSkipRemoteValidation(bool skipRemoteValidation)
{
    skipRemoteValidation_ = skipRemoteValidation;
}

Socket::NetAddress TLSConnectOptions::GetNetAddress() const
{
    return address_;
}

TLSSecureOptions TLSConnectOptions::GetTlsSecureOptions() const
{
    return tlsSecureOptions_;
}

CheckServerIdentity TLSConnectOptions::GetCheckServerIdentity() const
{
    return checkServerIdentity_;
}

const std::vector<std::string> &TLSConnectOptions::GetAlpnProtocols() const
{
    return alpnProtocols_;
}

bool TLSConnectOptions::GetSkipRemoteValidation() const
{
    return skipRemoteValidation_;
}

void TLSConnectOptions::SetHostName(const std::string &hostName)
{
    hostName_ = hostName;
}

std::string TLSConnectOptions::GetHostName() const
{
    return hostName_;
}

void TLSConnectOptions::SetTimeout(const uint32_t &timeout)
{
    timeout_ = timeout;
}

uint32_t TLSConnectOptions::GetTimeout() const
{
    return timeout_;
}

std::string TLSSocket::MakeAddressString(sockaddr *addr)
{
    if (!addr) {
        return {};
    }
    if (addr->sa_family == AF_INET) {
        auto *addr4 = reinterpret_cast<sockaddr_in *>(addr);
        const char *str = inet_ntoa(addr4->sin_addr);
        if (str == nullptr || strlen(str) == 0) {
            return {};
        }
        return str;
    } else if (addr->sa_family == AF_INET6) {
        auto *addr6 = reinterpret_cast<sockaddr_in6 *>(addr);
        char str[INET6_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET6, &addr6->sin6_addr, str, INET6_ADDRSTRLEN) == nullptr || strlen(str) == 0) {
            return {};
        }
        return str;
    }
    return {};
}

void TLSSocket::GetAddr(const Socket::NetAddress &address, sockaddr_in *addr4, sockaddr_in6 *addr6, sockaddr **addr,
                        socklen_t *len)
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

bool TLSSocket::ExecTlsSetSockBlockFlag(int sock, bool noneBlock)
{
    return SetSockBlockFlag(sock, noneBlock);
}

void TLSSocket::ExecTlsGetAddr(
    const Socket::NetAddress &address, sockaddr_in *addr4, sockaddr_in6 *addr6, sockaddr **addr, socklen_t *len)
{
    GetAddr(address, addr4, addr6, addr, len);
}

bool TLSSocket::IsExtSock() const
{
    return isExtSock_;
}

void TLSSocket::MakeIpSocket(sa_family_t family)
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
    sockFd_ = sock;
}

int TLSSocket::ReadMessage()
{
    char buffer[MAX_RECV_BUFFER_SIZE];
    if (memset_s(buffer, MAX_RECV_BUFFER_SIZE, 0, MAX_RECV_BUFFER_SIZE) != EOK) {
        NETSTACK_LOGE("memset_s failed!");
        return -1;
    }
    nfds_t num = 1;
    pollfd fds[1] = {{.fd = sockFd_, .events = POLLIN}};
    int ret = poll(fds, num, READ_TIMEOUT_MS);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EINTR) {
            return 0;
        }
        int resErr = ConvertErrno();
        NETSTACK_LOGE("Message poll errno is %{public}d %{public}s", errno, MakeErrnoString().c_str());
        CallOnErrorCallback(resErr, MakeErrnoString());
        return ret;
    } else if (ret == 0) {
        NETSTACK_LOGD("tls recv poll timeout");
        return ret;
    }

    std::lock_guard<std::mutex> lock(recvMutex_);
    if (!isRunning_) {
        return -1;
    }
    int len = tlsSocketInternal_.Recv(buffer, MAX_RECV_BUFFER_SIZE);
    if (len < 0) {
        if (errno == EAGAIN || errno == EINTR || len == SSL_WANT_READ_RETURN) {
            return 0;
        }
        int resErr = tlsSocketInternal_.ConvertSSLError();
        NETSTACK_LOGE("SSL_read function read error, errno is %{public}d, errno info is %{public}s", resErr,
                      MakeSSLErrorString(resErr).c_str());
        CallOnErrorCallback(resErr, MakeSSLErrorString(resErr));
        return len;
    } else if (len == 0) {
        NETSTACK_LOGI("Message recv len 0, session is closed by peer");
        CallOnCloseCallback();
        return -1;
    }
    Socket::SocketRemoteInfo remoteInfo;
    remoteInfo.SetSize(len);
    tlsSocketInternal_.MakeRemoteInfo(remoteInfo);
    std::string bufContent(buffer, len);
    CallOnMessageCallback(bufContent, remoteInfo);

    return ret;
}

void TLSSocket::StartReadMessage()
{
    auto wp = std::weak_ptr<TLSSocket>(shared_from_this());
    std::thread thread([wp]() {
        auto tlsSocket = wp.lock();
        if (tlsSocket == nullptr) {
            return;
        }
        tlsSocket->isRunning_ = true;
        tlsSocket->isRunOver_ = false;
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
        pthread_setname_np(TLS_SOCKET_CLIENT_READ);
#else
        pthread_setname_np(pthread_self(), TLS_SOCKET_CLIENT_READ);
#endif
        while (tlsSocket->isRunning_) {
            int ret = tlsSocket->ReadMessage();
            if (ret < 0) {
                break;
            }
        }
        tlsSocket->isRunOver_ = true;
        tlsSocket->cvSslFree_.notify_one();
    });
    thread.detach();
}

void TLSSocket::CallOnMessageCallback(const std::string &data, const Socket::SocketRemoteInfo &remoteInfo)
{
    OnMessageCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (onMessageCallback_) {
            func = onMessageCallback_;
        }
    }

    if (func) {
        func(data, remoteInfo);
    }
}

void TLSSocket::CallOnConnectCallback()
{
    OnConnectCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (onConnectCallback_) {
            func = onConnectCallback_;
        }
    }

    if (func) {
        func();
    }
}

void TLSSocket::CallOnCloseCallback()
{
    OnCloseCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (onCloseCallback_) {
            func = onCloseCallback_;
        }
    }

    if (func) {
        func();
    }
}

void TLSSocket::CallOnErrorCallback(int32_t err, const std::string &errString)
{
    OnErrorCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (onErrorCallback_) {
            func = onErrorCallback_;
        }
    }

    if (func) {
        func(err, errString);
    }
}

void TLSSocket::CallBindCallback(int32_t err, BindCallback callback)
{
    DealCallback<BindCallback>(err, callback);
}

void TLSSocket::CallConnectCallback(int32_t err, ConnectCallback callback)
{
    DealCallback<ConnectCallback>(err, callback);
}

void TLSSocket::CallSendCallback(int32_t err, SendCallback callback)
{
    DealCallback<SendCallback>(err, callback);
}

void TLSSocket::CallCloseCallback(int32_t err, CloseCallback callback)
{
    DealCallback<CloseCallback>(err, callback);
}

void TLSSocket::CallGetRemoteAddressCallback(int32_t err, const Socket::NetAddress &address,
                                             GetRemoteAddressCallback callback)
{
    if (callback) {
        callback(err, address);
    }
}

void TLSSocket::CallGetStateCallback(int32_t err, const Socket::SocketStateBase &state, GetStateCallback callback)
{
    if (callback) {
        callback(err, state);
    }
}

void TLSSocket::CallSetExtraOptionsCallback(int32_t err, SetExtraOptionsCallback callback)
{
    DealCallback<SetExtraOptionsCallback>(err, callback);
}

void TLSSocket::CallGetCertificateCallback(int32_t err, const X509CertRawData &cert, GetCertificateCallback callback)
{
    if (callback) {
        callback(err, cert);
    }
}

void TLSSocket::CallGetRemoteCertificateCallback(int32_t err, const X509CertRawData &cert,
                                                 GetRemoteCertificateCallback callback)
{
    if (callback) {
        callback(err, cert);
    }
}

void TLSSocket::CallGetProtocolCallback(int32_t err, const std::string &protocol, GetProtocolCallback callback)
{
    if (callback) {
        callback(err, protocol);
    }
}

void TLSSocket::CallGetCipherSuiteCallback(int32_t err, const std::vector<std::string> &suite,
                                           GetCipherSuiteCallback callback)
{
    if (callback) {
        callback(err, suite);
    }
}

void TLSSocket::CallGetSignatureAlgorithmsCallback(int32_t err, const std::vector<std::string> &algorithms,
                                                   GetSignatureAlgorithmsCallback callback)
{
    if (callback) {
        callback(err, algorithms);
    }
}

void TLSSocket::Bind(Socket::NetAddress &address, const BindCallback &callback)
{
    static constexpr int32_t PARSE_ERROR_CODE = 401;
    if (!CommonUtils::HasInternetPermission()) {
        CallBindCallback(PERMISSION_DENIED_CODE, callback);
        return;
    }
    if (sockFd_ >= 0) {
        CallBindCallback(TLSSOCKET_SUCCESS, callback);
        return;
    }

    MakeIpSocket(address.GetSaFamily());
    if (sockFd_ < 0) {
        int resErr = ConvertErrno();
        NETSTACK_LOGE("make tcp socket failed errno is %{public}d %{public}s", errno, MakeErrnoString().c_str());
        CallOnErrorCallback(resErr, MakeErrnoString());
        CallBindCallback(resErr, callback);
        return;
    }

    auto temp = address.GetAddress();
    address.SetRawAddress("");
    address.SetAddress(temp);
    if (address.GetAddress().empty()) {
        CallBindCallback(PARSE_ERROR_CODE, callback);
        return;
    }

    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len;
    GetAddr(address, &addr4, &addr6, &addr, &len);
    if (addr == nullptr) {
        NETSTACK_LOGE("TLSSocket::Bind Address Is Invalid");
        CallOnErrorCallback(-1, "Address Is Invalid");
        CallBindCallback(ConvertErrno(), callback);
        return;
    }
    CallBindCallback(TLSSOCKET_SUCCESS, callback);
}

void TLSSocket::Connect(OHOS::NetStack::TlsSocket::TLSConnectOptions &tlsConnectOptions,
                        const OHOS::NetStack::TlsSocket::ConnectCallback &callback)
{
    if (sockFd_ < 0) {
        int resErr = ConvertErrno();
        NETSTACK_LOGE("connect error is %{public}s %{public}d", MakeErrnoString().c_str(), errno);
        CallOnErrorCallback(resErr, MakeErrnoString());
        callback(resErr);
        return;
    }

    if (isExtSock_ && !SetSockBlockFlag(sockFd_, false)) {
        int resErr = ConvertErrno();
        NETSTACK_LOGE("SetSockBlockFlag error is %{public}s %{public}d", MakeErrnoString().c_str(), errno);
        CallOnErrorCallback(resErr, MakeErrnoString());
        callback(resErr);
        return;
    }

    auto res = tlsSocketInternal_.TlsConnectToHost(sockFd_, tlsConnectOptions, isExtSock_);
    if (!res) {
        int resErr = tlsSocketInternal_.ConvertSSLError();
        NETSTACK_LOGE("connect error is %{public}d %{public}d", resErr, errno);
        CallOnErrorCallback(resErr, MakeSSLErrorString(resErr));
        callback(resErr);
        return;
    }
    if (!SetSockBlockFlag(sockFd_, true)) {
        int resErr = ConvertErrno();
        NETSTACK_LOGE("SetSockBlockFlag error is %{public}s %{public}d", MakeErrnoString().c_str(), errno);
        CallOnErrorCallback(resErr, MakeErrnoString());
        callback(resErr);
        return;
    }
    StartReadMessage();
    CallOnConnectCallback();
    callback(TLSSOCKET_SUCCESS);
}

void TLSSocket::Send(const OHOS::NetStack::Socket::TCPSendOptions &tcpSendOptions, const SendCallback &callback)
{
    auto res = tlsSocketInternal_.Send(tcpSendOptions.GetData());
    if (!res) {
        int resErr = tlsSocketInternal_.ConvertSSLError();
        NETSTACK_LOGE("send error is %{public}d %{public}d", resErr, errno);
        CallOnErrorCallback(resErr, MakeSSLErrorString(resErr));
        CallSendCallback(resErr, callback);
        return;
    }
    CallSendCallback(TLSSOCKET_SUCCESS, callback);
}

void TLSSocket::Close(const CloseCallback &callback)
{
    isRunning_ = false;
    std::unique_lock<std::mutex> cvLock(cvMutex_);
    auto wp = std::weak_ptr<TLSSocket>(shared_from_this());
    cvSslFree_.wait(cvLock, [wp]() -> bool {
        auto tlsSocket = wp.lock();
        if (tlsSocket == nullptr) {
            return true;
        }
        return tlsSocket->isRunOver_;
    });

    std::lock_guard<std::mutex> lock(recvMutex_);
    NETSTACK_LOGI("tls socket close, fd =%{public}d", sockFd_);
    close(sockFd_);
    sockFd_ = -1;
    CallOnCloseCallback();
    callback(TLSSOCKET_SUCCESS);
}

void TLSSocket::GetRemoteAddress(const GetRemoteAddressCallback &callback)
{
    sockaddr sockAddr = {0};
    socklen_t len = sizeof(sockaddr);
    int ret = getsockname(sockFd_, &sockAddr, &len);
    if (ret < 0) {
        int resErr = ConvertErrno();
        NETSTACK_LOGE("getsockname failed errno %{public}d", resErr);
        CallOnErrorCallback(resErr, MakeErrnoString());
        CallGetRemoteAddressCallback(resErr, {}, callback);
        return;
    }

    if (sockAddr.sa_family == AF_INET) {
        GetIp4RemoteAddress(callback);
    } else if (sockAddr.sa_family == AF_INET6) {
        GetIp6RemoteAddress(callback);
    }
}

void TLSSocket::GetIp4RemoteAddress(const GetRemoteAddressCallback &callback)
{
    sockaddr_in addr4 = {0};
    socklen_t len4 = sizeof(sockaddr_in);

    int ret = getpeername(sockFd_, reinterpret_cast<sockaddr *>(&addr4), &len4);
    if (ret < 0) {
        int resErr = ConvertErrno();
        NETSTACK_LOGE("GetIp4RemoteAddress failed errno %{public}d", resErr);
        CallOnErrorCallback(resErr, MakeErrnoString());
        CallGetRemoteAddressCallback(resErr, {}, callback);
        return;
    }

    std::string address = MakeAddressString(reinterpret_cast<sockaddr *>(&addr4));
    if (address.empty()) {
        NETSTACK_LOGE("GetIp4RemoteAddress failed errno %{public}d", errno);
        CallOnErrorCallback(-1, "Address is invalid");
        CallGetRemoteAddressCallback(ConvertErrno(), {}, callback);
        return;
    }
    Socket::NetAddress netAddress;
    netAddress.SetFamilyBySaFamily(AF_INET);
    netAddress.SetRawAddress(address);
    netAddress.SetPort(ntohs(addr4.sin_port));
    CallGetRemoteAddressCallback(TLSSOCKET_SUCCESS, netAddress, callback);
}

void TLSSocket::GetIp6RemoteAddress(const GetRemoteAddressCallback &callback)
{
    sockaddr_in6 addr6 = {0};
    socklen_t len6 = sizeof(sockaddr_in6);

    int ret = getpeername(sockFd_, reinterpret_cast<sockaddr *>(&addr6), &len6);
    if (ret < 0) {
        int resErr = ConvertErrno();
        NETSTACK_LOGE("GetIp6RemoteAddress failed errno %{public}d", resErr);
        CallOnErrorCallback(resErr, MakeErrnoString());
        CallGetRemoteAddressCallback(resErr, {}, callback);
        return;
    }

    std::string address = MakeAddressString(reinterpret_cast<sockaddr *>(&addr6));
    if (address.empty()) {
        NETSTACK_LOGE("GetIp6RemoteAddress failed errno %{public}d", errno);
        CallOnErrorCallback(-1, "Address is invalid");
        CallGetRemoteAddressCallback(ConvertErrno(), {}, callback);
        return;
    }
    Socket::NetAddress netAddress;
    netAddress.SetFamilyBySaFamily(AF_INET6);
    netAddress.SetRawAddress(address);
    netAddress.SetPort(ntohs(addr6.sin6_port));
    CallGetRemoteAddressCallback(TLSSOCKET_SUCCESS, netAddress, callback);
}

void TLSSocket::GetState(const GetStateCallback &callback)
{
    int opt;
    socklen_t optLen = sizeof(int);
    int r = getsockopt(sockFd_, SOL_SOCKET, SO_TYPE, &opt, &optLen);
    if (r < 0) {
        Socket::SocketStateBase state;
        state.SetIsClose(true);
        CallGetStateCallback(ConvertErrno(), state, callback);
        return;
    }
    sockaddr sockAddr = {0};
    socklen_t len = sizeof(sockaddr);
    Socket::SocketStateBase state;
    int ret = getsockname(sockFd_, &sockAddr, &len);
    state.SetIsBound(ret == 0);
    ret = getpeername(sockFd_, &sockAddr, &len);
    state.SetIsConnected(ret == 0);
    CallGetStateCallback(TLSSOCKET_SUCCESS, state, callback);
}

bool TLSSocket::SetBaseOptions(const Socket::ExtraOptionsBase &option) const
{
    if (option.GetReceiveBufferSize() != 0) {
        int size = (int)option.GetReceiveBufferSize();
        if (setsockopt(sockFd_, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<void *>(&size), sizeof(size)) < 0) {
            return false;
        }
    }

    if (option.GetSendBufferSize() != 0) {
        int size = (int)option.GetSendBufferSize();
        if (setsockopt(sockFd_, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<void *>(&size), sizeof(size)) < 0) {
            return false;
        }
    }

    if (option.IsReuseAddress()) {
        int reuse = 1;
        if (setsockopt(sockFd_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<void *>(&reuse), sizeof(reuse)) < 0) {
            return false;
        }
    }

    if (option.GetSocketTimeout() != 0) {
        timeval timeout = {(int)option.GetSocketTimeout(), 0};
        if (setsockopt(sockFd_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<void *>(&timeout), sizeof(timeout)) < 0) {
            return false;
        }
        if (setsockopt(sockFd_, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<void *>(&timeout), sizeof(timeout)) < 0) {
            return false;
        }
    }

    return true;
}

bool TLSSocket::SetExtraOptions(const Socket::TCPExtraOptions &option) const
{
    if (option.IsKeepAlive()) {
        int keepalive = 1;
        if (setsockopt(sockFd_, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0) {
            return false;
        }
    }

    if (option.IsOOBInline()) {
        int oobInline = 1;
        if (setsockopt(sockFd_, SOL_SOCKET, SO_OOBINLINE, &oobInline, sizeof(oobInline)) < 0) {
            return false;
        }
    }

    if (option.IsTCPNoDelay()) {
        int tcpNoDelay = 1;
        if (setsockopt(sockFd_, IPPROTO_TCP, TCP_NODELAY, &tcpNoDelay, sizeof(tcpNoDelay)) < 0) {
            return false;
        }
    }

    linger soLinger = {0};
    soLinger.l_onoff = option.socketLinger.IsOn();
    soLinger.l_linger = (int)option.socketLinger.GetLinger();
    if (setsockopt(sockFd_, SOL_SOCKET, SO_LINGER, &soLinger, sizeof(soLinger)) < 0) {
        return false;
    }

    return true;
}

void TLSSocket::SetExtraOptions(const OHOS::NetStack::Socket::TCPExtraOptions &tcpExtraOptions,
                                const SetExtraOptionsCallback &callback)
{
    if (!SetBaseOptions(tcpExtraOptions)) {
        NETSTACK_LOGE("SetExtraOptions errno %{public}d", errno);
        CallOnErrorCallback(errno, MakeErrnoString());
        CallSetExtraOptionsCallback(ConvertErrno(), callback);
        return;
    }

    if (!SetExtraOptions(tcpExtraOptions)) {
        NETSTACK_LOGE("SetExtraOptions errno %{public}d", errno);
        CallOnErrorCallback(errno, MakeErrnoString());
        CallSetExtraOptionsCallback(ConvertErrno(), callback);
        return;
    }

    CallSetExtraOptionsCallback(TLSSOCKET_SUCCESS, callback);
}

void TLSSocket::GetCertificate(const GetCertificateCallback &callback)
{
    const auto &cert = tlsSocketInternal_.GetCertificate();
    NETSTACK_LOGI("cert der is %{public}d", cert.encodingFormat);

    if (!cert.data.Length()) {
        int resErr = tlsSocketInternal_.ConvertSSLError();
        NETSTACK_LOGE("GetCertificate errno %{public}d, %{public}s", resErr, MakeSSLErrorString(resErr).c_str());
        CallOnErrorCallback(resErr, MakeSSLErrorString(resErr));
        callback(resErr, {});
        return;
    }
    callback(TLSSOCKET_SUCCESS, cert);
}

void TLSSocket::GetRemoteCertificate(const GetRemoteCertificateCallback &callback)
{
    const auto &remoteCert = tlsSocketInternal_.GetRemoteCertRawData();
    if (!remoteCert.data.Length()) {
        int resErr = tlsSocketInternal_.ConvertSSLError();
        NETSTACK_LOGE("GetRemoteCertificate errno %{public}d, %{public}s", resErr, MakeSSLErrorString(resErr).c_str());
        CallOnErrorCallback(resErr, MakeSSLErrorString(resErr));
        callback(resErr, {});
        return;
    }
    callback(TLSSOCKET_SUCCESS, remoteCert);
}

void TLSSocket::GetProtocol(const GetProtocolCallback &callback)
{
    const auto &protocol = tlsSocketInternal_.GetProtocol();
    if (protocol.empty()) {
        NETSTACK_LOGE("GetProtocol errno %{public}d", errno);
        int resErr = tlsSocketInternal_.ConvertSSLError();
        NETSTACK_LOGE("getProtocol error is %{public}d %{public}d", resErr, errno);
        CallOnErrorCallback(resErr, MakeSSLErrorString(resErr));
        callback(resErr, "");
        return;
    }
    callback(TLSSOCKET_SUCCESS, protocol);
}

void TLSSocket::GetCipherSuite(const GetCipherSuiteCallback &callback)
{
    const auto &cipherSuite = tlsSocketInternal_.GetCipherSuite();
    if (cipherSuite.empty()) {
        int resErr = tlsSocketInternal_.ConvertSSLError();
        NETSTACK_LOGE("getCipherSuite error is %{public}d %{public}d", resErr, errno);
        CallOnErrorCallback(resErr, MakeSSLErrorString(resErr));
        callback(resErr, cipherSuite);
        return;
    }
    callback(TLSSOCKET_SUCCESS, cipherSuite);
}

void TLSSocket::GetSignatureAlgorithms(const GetSignatureAlgorithmsCallback &callback)
{
    const auto &signatureAlgorithms = tlsSocketInternal_.GetSignatureAlgorithms();
    if (signatureAlgorithms.empty()) {
        int resErr = tlsSocketInternal_.ConvertSSLError();
        NETSTACK_LOGE("getSignatureAlgorithms error is %{public}d %{public}d", resErr, errno);
        CallOnErrorCallback(resErr, MakeSSLErrorString(resErr));
        callback(resErr, {});
        return;
    }
    callback(TLSSOCKET_SUCCESS, signatureAlgorithms);
}

void TLSSocket::OnMessage(const OnMessageCallback &onMessageCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    onMessageCallback_ = onMessageCallback;
}

void TLSSocket::OffMessage()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (onMessageCallback_) {
        onMessageCallback_ = nullptr;
    }
}

void TLSSocket::OnConnect(const OnConnectCallback &onConnectCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    onConnectCallback_ = onConnectCallback;
}

void TLSSocket::OffConnect()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (onConnectCallback_) {
        onConnectCallback_ = nullptr;
    }
}

void TLSSocket::OnClose(const OnCloseCallback &onCloseCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    onCloseCallback_ = onCloseCallback;
}

void TLSSocket::OffClose()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (onCloseCallback_) {
        onCloseCallback_ = nullptr;
    }
}

void TLSSocket::OnError(const OnErrorCallback &onErrorCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    onErrorCallback_ = onErrorCallback;
}

void TLSSocket::OffError()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (onErrorCallback_) {
        onErrorCallback_ = nullptr;
    }
}

int TLSSocket::GetSocketFd()
{
    return sockFd_;
}

void TLSSocket::SetLocalAddress(const Socket::NetAddress &address)
{
    localAddress_ = address;
}

Socket::NetAddress TLSSocket::GetLocalAddress()
{
    return localAddress_;
}

bool ExecSocketConnect(const std::string &host, int port, sa_family_t family, int socketDescriptor)
{
    auto hostName = ConvertAddressToIp(host, family);

    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len = 0;
    if (family == AF_INET) {
        if (inet_pton(AF_INET, hostName.c_str(), &addr4.sin_addr.s_addr) <= 0) {
            return false;
        }
        addr4.sin_family = family;
        addr4.sin_port = htons(port);
        addr = reinterpret_cast<sockaddr *>(&addr4);
        len = sizeof(sockaddr_in);
    } else {
        if (inet_pton(AF_INET6, hostName.c_str(), &addr6.sin6_addr) <= 0) {
            return false;
        }
        addr6.sin6_family = family;
        addr6.sin6_port = htons(port);
        addr = reinterpret_cast<sockaddr *>(&addr6);
        len = sizeof(sockaddr_in6);
    }

    int connectResult = connect(socketDescriptor, addr, len);
    if (connectResult == -1) {
        NETSTACK_LOGE("socket connect error!The error code is %{public}d, The error message is %{public}s", errno,
                      strerror(errno));
        return false;
    }
    return true;
}

int TLSSocket::TLSSocketInternal::ConvertSSLError(void)
{
    std::shared_lock<std::shared_mutex> lock(mutexForSsl_);
    if (!ssl_) {
        return TLS_ERR_SSL_NULL;
    }
    return TlsSocketError::TLS_ERR_SSL_BASE + SSL_get_error(ssl_, SSL_RET_CODE);
}

bool TLSSocket::TLSSocketInternal::TlsConnectToHost(int sock, const TLSConnectOptions &options, bool isExtSock)
{
    SetTlsConfiguration(options);
    std::string cipherSuite = options.GetTlsSecureOptions().GetCipherSuite();
    if (!cipherSuite.empty()) {
        configuration_.SetCipherSuite(cipherSuite);
    }
    std::string signatureAlgorithms = options.GetTlsSecureOptions().GetSignatureAlgorithms();
    if (!signatureAlgorithms.empty()) {
        configuration_.SetSignatureAlgorithms(signatureAlgorithms);
    }
    const auto protocolVec = options.GetTlsSecureOptions().GetProtocolChain();
    if (!protocolVec.empty()) {
        configuration_.SetProtocol(protocolVec);
    }
    configuration_.SetSkipFlag(options.GetSkipRemoteValidation());
    hostName_ = options.GetNetAddress().GetAddress();
    port_ = options.GetNetAddress().GetPort();
    family_ = options.GetNetAddress().GetSaFamily();
    socketDescriptor_ = sock;
    if (options.proxyOptions_ == nullptr && !isExtSock &&
        !ExecSocketConnect(options.GetNetAddress().GetAddress(), options.GetNetAddress().GetPort(),
        options.GetNetAddress().GetSaFamily(), socketDescriptor_)) {
        return false;
    }
    return StartTlsConnected(options);
}

void TLSSocket::TLSSocketInternal::SetTlsConfiguration(const TLSConnectOptions &config)
{
    configuration_.SetPrivateKey(config.GetTlsSecureOptions().GetKey(), config.GetTlsSecureOptions().GetKeyPass());
    configuration_.SetLocalCertificate(config.GetTlsSecureOptions().GetCertChain());
    configuration_.SetCaCertificate(config.GetTlsSecureOptions().GetCaChain());
    configuration_.SetNetAddress(config.GetNetAddress());
}

bool TLSSocket::TLSSocketInternal::SendRetry(ssl_st *ssl, const char *curPos, size_t curSendSize, int sockfd)
{
    pollfd fds[1] = {{.fd = sockfd, .events = POLLOUT}};
    for (int i = 0; i <= SEND_RETRY_TIMES; i++) {
        int ret = poll(fds, 1, SEND_POLL_TIMEOUT_MS);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }
            NETSTACK_LOGE("send poll error, fd: %{public}d, errno: %{public}d", sockfd, errno);
            return false;
        } else if (ret == 0) {
            NETSTACK_LOGI("send poll timeout, fd: %{public}d, errno: %{public}d", sockfd, errno);
            continue;
        }
        int len = SSL_write(ssl, curPos, curSendSize);
        if (len < 0) {
            int err = SSL_get_error(ssl, SSL_RET_CODE);
            NETSTACK_LOGE("Error in PollSend, errno is %{public}d %{public}d", err, errno);
            if (err == SSL_ERROR_WANT_WRITE || errno == EAGAIN) {
                NETSTACK_LOGI("write retry times: %{public}d err: %{public}d errno: %{public}d", i, err, errno);
                continue;
            } else {
                NETSTACK_LOGE("write failed err: %{public}d errno: %{public}d", err, errno);
                return false;
            }
        } else if (len == 0) {
            NETSTACK_LOGI("send len is 0, should have sent len");
            return false;
        } else {
            return true;
        }
    }
    return false;
}

bool TLSSocket::TLSSocketInternal::PollSend(int sockfd, const char *pdata, int sendSize)
{
    std::unique_lock<std::shared_mutex> lock(mutexForSsl_);
    if (!ssl_) {
        NETSTACK_LOGE("ssl is null");
        return false;
    }
    int bufferSize = DEFAULT_BUFFER_SIZE;
    auto curPos = pdata;
    nfds_t num = 1;
    pollfd fds[1] = {{.fd = sockfd, .events = POLLOUT}};
    while (sendSize > 0) {
        int ret = poll(fds, num, DEFAULT_POLL_TIMEOUT_MS);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }
            NETSTACK_LOGE("send poll error, fd: %{public}d, errno: %{public}d", sockfd, errno);
            return false;
        } else if (ret == 0) {
            NETSTACK_LOGI("send poll timeout, fd: %{public}d, errno: %{public}d", sockfd, errno);
            continue;
        }
        size_t curSendSize = std::min<size_t>(sendSize, bufferSize);
        int len = SSL_write(ssl_, curPos, curSendSize);
        if (len < 0) {
            int err = SSL_get_error(ssl_, SSL_RET_CODE);
            NETSTACK_LOGE("Error in PollSend, errno is %{public}d %{public}d", err, errno);
            if (err != SSL_ERROR_WANT_WRITE || errno != EAGAIN) {
                NETSTACK_LOGE("write failed, return, err: %{public}d errno: %{public}d", err, errno);
                return false;
            } else if (!SendRetry(ssl_, curPos, curSendSize, sockfd)) {
                return false;
            }
        } else if (len == 0) {
            NETSTACK_LOGI("send len is 0, should have sent len is %{public}d", sendSize);
            return false;
        }
        curPos += len;
        sendSize -= len;
    }
    return true;
}

bool TLSSocket::TLSSocketInternal::Send(const std::string &data)
{
    if (data.empty()) {
        NETSTACK_LOGE("data is empty");
        return true;
    }

    if (!PollSend(socketDescriptor_, data.c_str(), data.size())) {
        return false;
    }
    return true;
}
int TLSSocket::TLSSocketInternal::Recv(char *buffer, int maxBufferSize)
{
    std::unique_lock<std::shared_mutex> lock(mutexForSsl_);
    if (!ssl_) {
        NETSTACK_LOGE("ssl is null");
        return SSL_ERROR_RETURN;
    }

    int ret = SSL_read(ssl_, buffer, maxBufferSize);
    if (ret < 0) {
        int err = SSL_get_error(ssl_, SSL_RET_CODE);
        switch (err) {
            case SSL_ERROR_SSL:
                NETSTACK_LOGE("An error occurred in the SSL library %{public}d %{public}d", err, errno);
                return SSL_ERROR_RETURN;
            case SSL_ERROR_ZERO_RETURN:
                NETSTACK_LOGE("peer disconnected...");
                return SSL_ERROR_RETURN;
            case SSL_ERROR_WANT_READ:
                NETSTACK_LOGD("SSL_read function no data available for reading, try again at a later time");
                return SSL_WANT_READ_RETURN;
            default:
                NETSTACK_LOGE("SSL_read function failed, error code is %{public}d", err);
                return SSL_ERROR_RETURN;
        }
    }
    return ret;
}

bool TLSSocket::TLSSocketInternal::SetAlpnProtocols(const std::vector<std::string> &alpnProtocols)
{
    std::unique_lock<std::shared_mutex> lock(mutexForSsl_);
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
        lock.unlock();
        int resErr = ConvertSSLError();
        NETSTACK_LOGE("Failed to set negotiable protocol list, errno is %{public}d, error info is %{public}s", resErr,
                      MakeSSLErrorString(resErr).c_str());
        return false;
    }
    return true;
}

void TLSSocket::TLSSocketInternal::MakeRemoteInfo(Socket::SocketRemoteInfo &remoteInfo)
{
    remoteInfo.SetFamily(family_);
    remoteInfo.SetAddress(hostName_);
    remoteInfo.SetPort(port_);
}

TLSConfiguration TLSSocket::TLSSocketInternal::GetTlsConfiguration() const
{
    return configuration_;
}

std::vector<std::string> TLSSocket::TLSSocketInternal::GetCipherSuite()
{
    std::shared_lock<std::shared_mutex> lock(mutexForSsl_);
    if (!ssl_) {
        NETSTACK_LOGE("ssl in null");
        return {};
    }
    STACK_OF(SSL_CIPHER) *sk = SSL_get_ciphers(ssl_);
    lock.unlock();
    if (!sk) {
        NETSTACK_LOGE("get ciphers failed");
        return {};
    }
    CipherSuite cipherSuite;
    std::vector<std::string> cipherSuiteVec;
    for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
        const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
        cipherSuite.cipherName_ = SSL_CIPHER_get_name(c);
        cipherSuiteVec.push_back(cipherSuite.cipherName_);
    }
    return cipherSuiteVec;
}

std::string TLSSocket::TLSSocketInternal::GetRemoteCertificate() const
{
    return remoteCert_;
}

const X509CertRawData &TLSSocket::TLSSocketInternal::GetCertificate() const
{
    return configuration_.GetCertificate();
}

std::vector<std::string> TLSSocket::TLSSocketInternal::GetSignatureAlgorithms() const
{
    std::shared_lock<std::shared_mutex> lock(rw_mutex_);
    return signatureAlgorithms_;
}

std::string TLSSocket::TLSSocketInternal::GetProtocol() const
{
    if (configuration_.GetProtocol() == TLS_V1_3) {
        return PROTOCOL_TLS_V13;
    }
    return PROTOCOL_TLS_V12;
}

bool TLSSocket::TLSSocketInternal::SetSharedSigals()
{
    std::shared_lock<std::shared_mutex> lock(mutexForSsl_);
    if (!ssl_) {
        return false;
    }
    int number = SSL_get_shared_sigalgs(ssl_, 0, nullptr, nullptr, nullptr, nullptr, nullptr);
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
        std::unique_lock<std::shared_mutex> lock(rw_mutex_);
        signatureAlgorithms_.push_back(sig_with_md);
    }
    return true;
}

bool TLSSocket::TLSSocketInternal::StartTlsConnected(const TLSConnectOptions &options)
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

bool TLSSocket::TLSSocketInternal::CreatTlsContext()
{
    std::unique_lock<std::shared_mutex> sslLock(mutexForSsl_);
    if (tlsContextPointer_ != nullptr && ssl_ != nullptr) {
        return true;
    }
    tlsContextPointer_ = TLSContext::CreateConfiguration(configuration_);
    if (!tlsContextPointer_) {
        NETSTACK_LOGE("failed to create tls context pointer");
        return false;
    }

    ssl_ = tlsContextPointer_->CreateSsl();
    if (ssl_ == nullptr) {
        NETSTACK_LOGE("failed to create ssl session");
        return false;
    }
    SSL_set_fd(ssl_, socketDescriptor_);
    SSL_set_connect_state(ssl_);
    return true;
}

static bool StartsWith(const std::string &s, const std::string &prefix)
{
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

void CheckIpAndDnsName(const std::string &hostName, std::vector<std::string> dnsNames, std::vector<std::string> ips,
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
        if (!dnsNames.empty()) {
            valid = SeekIntersection(hostParts, dnsNames);
            if (!valid) {
                reason = HOST_NAME + tempHostName + ". is not in the cert's altnames";
            }
        } else {
            char commonNameBuf[COMMON_NAME_BUF_SIZE] = {0};
            X509_NAME *pSubName = nullptr;
            int len = X509_NAME_get_text_by_NID(pSubName, NID_commonName, commonNameBuf, COMMON_NAME_BUF_SIZE);
            if (len > 0) {
                std::vector<std::string> commonNameVec;
                commonNameVec.emplace_back(commonNameBuf);
                valid = SeekIntersection(hostParts, commonNameVec);
                if (!valid) {
                    reason = HOST_NAME + tempHostName + ". is not cert's CN";
                }
            }
        }
        result = {valid, reason};
        return;
    }
    reason = "Cert does not contain a DNS name";
    result = {valid, reason};
}

std::string TLSSocket::TLSSocketInternal::CheckServerIdentityLegal(const std::string &hostName,
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

    return CheckServerIdentityLegal(hostName, ext, x509Certificates);
}

std::string TLSSocket::TLSSocketInternal::CheckServerIdentityLegal(const std::string &hostName, X509_EXTENSION *ext,
                                                                   const X509 *x509Certificates)
{
    ASN1_OCTET_STRING *extData = X509_EXTENSION_get_data(ext);
    if (!extData) {
        NETSTACK_LOGE("extData is nullptr");
        return "";
    }
    std::string altNames = reinterpret_cast<char *>(extData->data);
    std::string hostname = " " + hostName;
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

static void LoadCaCertFromMemory(X509_STORE *store, const std::string &pemCerts)
{
    if (!store || pemCerts.empty() || pemCerts.size() > static_cast<size_t>(INT_MAX)) {
        return;
    }

    auto cbio = BIO_new_mem_buf(pemCerts.data(), static_cast<int>(pemCerts.size()));
    if (!cbio) {
        return;
    }

    auto inf = PEM_X509_INFO_read_bio(cbio, nullptr, nullptr, nullptr);
    if (!inf) {
        BIO_free(cbio);
        return;
    }

    /* add each entry from PEM file to x509_store */
    for (int i = 0; i < static_cast<int>(sk_X509_INFO_num(inf)); ++i) {
        auto itmp = sk_X509_INFO_value(inf, i);
        if (!itmp) {
            continue;
        }
        if (itmp->x509) {
            X509_STORE_add_cert(store, itmp->x509);
        }
        if (itmp->crl) {
            X509_STORE_add_crl(store, itmp->crl);
        }
    }

    sk_X509_INFO_pop_free(inf, X509_INFO_free);
    BIO_free(cbio);
}

static std::string X509_to_PEM(X509 *cert)
{
    if (!cert) {
        return {};
    }
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return {};
    }
    if (!PEM_write_bio_X509(bio, cert)) {
        BIO_free(bio);
        return {};
    }

    char *data = nullptr;
    auto pemStringLength = BIO_get_mem_data(bio, &data);
    if (!data) {
        BIO_free(bio);
        return {};
    }
    std::string certificateInPEM(data, pemStringLength);
    BIO_free(bio);
    return certificateInPEM;
}

void TLSSocket::TLSSocketInternal::CacheCertificates(const std::string &hostName)
{
    std::shared_lock<std::shared_mutex> lock(mutexForSsl_);
    if (ssl_ == nullptr || hostName.empty()) {
        return;
    }
    auto certificatesStack = SSL_get_peer_cert_chain(ssl_);
    lock.unlock();
    if (!certificatesStack) {
        return;
    }
    auto numCertificates = sk_X509_num(certificatesStack);
    for (auto i = 0; i < numCertificates; ++i) {
        auto cert = sk_X509_value(certificatesStack, i);
        auto certificateInPEM = X509_to_PEM(cert);
        if (!certificateInPEM.empty()) {
            CaCertCache::GetInstance().Set(hostName, certificateInPEM);
        }
    }
}

void TLSSocket::TLSSocketInternal::SetSNIandLoadCachedCaCert(const std::string &hostName)
{
    if (!ssl_) {
        return;
    }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    std::unique_lock<std::shared_mutex> wLock(mutexForSsl_);
    SSL_set_tlsext_host_name(ssl_, hostName.c_str());
    wLock.unlock();
#endif
    auto cachedPem = CaCertCache::GetInstance().Get(hostName);
    std::shared_lock<std::shared_mutex> rLock(mutexForSsl_);
    auto sslCtx = SSL_get_SSL_CTX(ssl_);
    rLock.unlock();
    if (!sslCtx) {
        return;
    }
    auto x509Store = SSL_CTX_get_cert_store(sslCtx);
    if (!x509Store) {
        return;
    }
    for (const auto &pem : cachedPem) {
        LoadCaCertFromMemory(x509Store, pem);
    }
}

int TLSSocket::TLSSocketInternal::ShakingHandsTimeout(int fd, uint32_t timeout)
{
    if (timeout <= 0) {
        NETSTACK_LOGI("No need to wait timeout, timeout is %{public}d", timeout);
        return NO_TIMEOUT;
    }
    SetSockBlockFlag(fd, true);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
    while (true) {
        int remain = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remain <= 0) {
            return TLS_TIMEOUT;
        }
        std::unique_lock<std::shared_mutex> lock(mutexForSsl_);
        int rc = SSL_connect(ssl_);
        int err = SSL_get_error(ssl_, rc);
        lock.unlock();
        if (rc == 1) {
            break;
        }
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            return TlsSocketError::TLS_ERR_SSL_BASE + err;
        }
        short ev = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
        struct pollfd pfd{ fd, ev, 0};
        int pr = poll(&pfd, 1, remain);
        if (pr == 0) {
            return TLS_TIMEOUT;
        }
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            return TLS_TIMEOUT;
        }
        if (static_cast<unsigned short>(pfd.revents) & (POLLERR | POLLHUP | POLLNVAL)) {
            return POLL_ERR_IN_TLS;
        }
    }
    return TlsSocketError::TLSSOCKET_SUCCESS;
}
bool TLSSocket::TLSSocketInternal::StartShakingHands(const TLSConnectOptions &options)
{
    if (!ssl_) {
        NETSTACK_LOGE("ssl is null");
        return false;
    }

    auto hostName = options.GetHostName();
    // indicates hostName is not ip address
    if (hostName != options.GetNetAddress().GetAddress()) {
        SetSNIandLoadCachedCaCert(hostName);
    }
    uint32_t timeout_ms = options.GetTimeout();
    int TimeoutErr = ShakingHandsTimeout(socketDescriptor_, timeout_ms);
    if (TimeoutErr == NO_TIMEOUT) {
        std::unique_lock<std::shared_mutex> wLock(mutexForSsl_);
        int result = SSL_connect(ssl_);
        if (result == -1) {
            char err[MAX_ERR_LEN] = {0};
            auto code = ERR_get_error();
            ERR_error_string_n(code, err, MAX_ERR_LEN);
            int errorStatus = TlsSocketError::TLS_ERR_SSL_BASE + SSL_get_error(ssl_, SSL_RET_CODE);
            NETSTACK_LOGE("SSLConnect fail %{public}d, error: %{public}s errno: %{public}d "
                "ERR_get_error %{public}s", errorStatus, MakeSSLErrorString(errorStatus).c_str(), errno, err);
            return false;
        }
    } else if (TimeoutErr != TlsSocketError::TLSSOCKET_SUCCESS) {
        SetSockBlockFlag(socketDescriptor_, false);
        NETSTACK_LOGE("TLS failed to shaking hands after %{public}d ms", timeout_ms);
        return false;
    }

    // indicates hostName is not ip address
    if (hostName != options.GetNetAddress().GetAddress()) {
        CacheCertificates(hostName);
    }
    std::shared_lock<std::shared_mutex> rLock(mutexForSsl_);
    const char *cipherList = SSL_get_cipher_list(ssl_, 0);
    std::string list = (cipherList == NULL) ? "" : cipherList;
    NETSTACK_LOGI("cipher_list: %{public}s, Version: %{public}s, Cipher: %{public}s", list.c_str(),
                  SSL_get_version(ssl_), SSL_get_cipher(ssl_));
    configuration_.SetCipherSuite(list);
    if (!CheckAfterShankingHands(options)) {
        return false;
    }
    return true;
}

bool TLSSocket::TLSSocketInternal::CheckAfterShankingHands(const TLSConnectOptions &options)
{
    if (!SetSharedSigals()) {
        NETSTACK_LOGE("Failed to set sharedSigalgs");
    }
    X509 *peerX509 = SSL_get_peer_certificate(ssl_);
    if (!GetRemoteCertificateFromPeer(peerX509)) {
        NETSTACK_LOGE("Failed to get remote certificate");
    }
    if (!peerX509) {
        NETSTACK_LOGE("peer x509Certificates is null");
        return false;
    }
    if (!SetRemoteCertRawData(peerX509)) {
        NETSTACK_LOGE("Failed to set remote x509 certificata Serialization data");
    }
    CheckServerIdentity checkServerIdentity = options.GetCheckServerIdentity();
    if (!checkServerIdentity) {
        CheckServerIdentityLegal(hostName_, peerX509);
    } else {
        checkServerIdentity(hostName_, {remoteCert_});
    }
    X509_free(peerX509);
    return true;
}

bool TLSSocket::TLSSocketInternal::GetRemoteCertificateFromPeer(X509 *peerX509)
{
    if (peerX509 == nullptr) {
        int resErr = ConvertSSLError();
        NETSTACK_LOGE("open fail errno, errno is %{public}d %{public}d", resErr, errno);
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

bool TLSSocket::TLSSocketInternal::SetRemoteCertRawData(X509 *peerX509)
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
    SecureData data(der, length);
    remoteRawData_.data = data;
    OPENSSL_free(der);
    remoteRawData_.encodingFormat = DER;
    return true;
}

const X509CertRawData &TLSSocket::TLSSocketInternal::GetRemoteCertRawData() const
{
    return remoteRawData_;
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
