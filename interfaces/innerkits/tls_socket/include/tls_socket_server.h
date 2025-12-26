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

#ifndef COMMUNICATIONNETSTACK_TLS_SERVER_SOCEKT_H
#define COMMUNICATIONNETSTACK_TLS_SERVER_SOCEKT_H

#include "event_manager.h"
#include "extra_options_base.h"
#include "net_address.h"
#include "socket_error.h"
#include "socket_remote_info.h"
#include "socket_state_base.h"
#include "tcp_connect_options.h"
#include "tcp_extra_options.h"
#include "tcp_send_options.h"
#include "tls.h"
#include "tls_certificate.h"
#include "tls_configuration.h"
#include "tls_context_server.h"
#include "tls_key.h"
#include "tls_socket.h"
#include <any>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <map>
#include <poll.h>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <vector>

namespace OHOS {
namespace NetStack {
namespace TlsSocketServer {
constexpr int USER_LIMIT = 10;
struct CacheInfo {
    std::string data;
    Socket::SocketRemoteInfo remoteInfo;
};
using OnMessageCallback =
    std::function<void(const int &socketFd, const std::string &data, const Socket::SocketRemoteInfo &remoteInfo)>;
using OnCloseCallback = std::function<void(const int &socketFd)>;
using OnConnectCallback = std::function<void(const int &socketFd, std::shared_ptr<EventManager> eventManager)>;
using ListenCallback = std::function<void(int32_t errorNumber)>;
class TLSServerSendOptions {
public:
    /**
     * Set the socket ID to be transmitted
     * @param socketFd Communication descriptor
     */
    void SetSocket(const int &socketFd);

    /**
     * Set the data to send
     * @param data Send data
     */
    void SetSendData(const std::string &data);

    /**
     * Get the socket ID
     * @return Gets the communication descriptor
     */
    [[nodiscard]] const int &GetSocket() const;

    /**
     * Gets the data sent
     * @return Send data
     */
    [[nodiscard]] const std::string &GetSendData() const;

private:
    int socketFd_ = 0;
    std::string data_ = "";
};

class TLSSocketServer {
public:
    TLSSocketServer(const TLSSocketServer &) = delete;
    TLSSocketServer(TLSSocketServer &&) = delete;

    TLSSocketServer &operator=(const TLSSocketServer &) = delete;
    TLSSocketServer &operator=(TLSSocketServer &&) = delete;

    TLSSocketServer() = default;
    ~TLSSocketServer();

    /**
     * Create sockets, bind and listen waiting for clients to connect
     * @param tlsListenOptions Bind the listening connection configuration
     * @param callback callback to the caller if bind ok or not
     */
    void Listen(const TlsSocket::TLSConnectOptions &tlsListenOptions, const ListenCallback &callback);

    /**
     * Send data through an established encrypted connection
     * @param data data sent over an established encrypted connection
     * @return whether the data is successfully sent to the server
     */
    bool Send(const TLSServerSendOptions &data, const TlsSocket::SendCallback &callback);

    /**
     * Disconnect by releasing the socket when communicating
     * @param socketFd The socket ID of the client
     * @param callback callback to the caller
     */
    void Close(const int socketFd, const TlsSocket::CloseCallback &callback);

    /**
     * Disconnect by releasing the socket when communicating
     * @param callback callback to the caller
     */
    void Stop(const TlsSocket::CloseCallback &callback);

    /**
     * Get the peer network address
     * @param socketFd The socket ID of the client
     * @param callback callback to the caller
     */
    void GetRemoteAddress(const int socketFd, const TlsSocket::GetRemoteAddressCallback &callback);

    /**
     * Get the peer network address
     * @param socketFd The socket ID of the client
     * @param callback callback to the caller
     */
    void GetLocalAddress(const int socketFd, const TlsSocket::GetLocalAddressCallback &callback);

    /**
     * Get the status of the current socket
     * @param callback callback to the caller
     */
    void GetState(const TlsSocket::GetStateCallback &callback);

    /**
     * Gets or sets the options associated with the current socket
     * @param tcpExtraOptions options associated with the current socket
     * @param callback callback to the caller
     */
    bool SetExtraOptions(const Socket::TCPExtraOptions &tcpExtraOptions,
                         const TlsSocket::SetExtraOptionsCallback &callback);

    /**
     *  Get a local digital certificate
     * @param callback callback to the caller
     */
    void GetCertificate(const TlsSocket::GetCertificateCallback &callback);

    /**
     * Get the peer digital certificate
     * @param socketFd The socket ID of the client
     * @param needChain need chain
     * @param callback callback to the caller
     */
    void GetRemoteCertificate(const int socketFd, const TlsSocket::GetRemoteCertificateCallback &callback);

    /**
     * Obtain the protocol used in communication
     * @param callback callback to the caller
     */
    void GetProtocol(const TlsSocket::GetProtocolCallback &callback);

    /**
     * Obtain the cipher suite used in communication
     * @param socketFd The socket ID of the client
     * @param callback callback to the caller
     */
    void GetCipherSuite(const int socketFd, const TlsSocket::GetCipherSuiteCallback &callback);

    /**
     * Obtain the encryption algorithm used in the communication process
     * @param socketFd The socket ID of the client
     * @param callback callback to the caller
     */
    void GetSignatureAlgorithms(const int socketFd, const TlsSocket::GetSignatureAlgorithmsCallback &callback);

    /**
     * Register the callback that is called when the connection is disconnected
     * @param onCloseCallback callback invoked when disconnected
     */

    /**
     * Register the callback that is called when the connection is established
     * @param onConnectCallback callback invoked when connection is established
     */
    void OnConnect(const OnConnectCallback &onConnectCallback);

    /**
     * Register the callback that is called when an error occurs
     * @param onErrorCallback callback invoked when an error occurs
     */
    void OnError(const TlsSocket::OnErrorCallback &onErrorCallback);

    /**
     * Off Connect
     */
    void OffConnect();

    /**
     * Off Error
     */
    void OffError();

    /**
     * Get the socket file description of the server
     */
    int GetListenSocketFd();

    /**
     * Set the current socket file description address of the server
     */
    void SetLocalAddress(const Socket::NetAddress &address);

    /**
     * Get the current socket file description address of the server
     */
    Socket::NetAddress GetLocalAddress();

    /**
     * Get the socketFd of the connection
     */
    int32_t GetClientSocketFd(int32_t clientId);

public:
    class Connection : public std::enable_shared_from_this<Connection> {
    public:
        ~Connection();
        /**
         * Establish an encrypted accept on the specified socket
         * @param sock socket for establishing encrypted connection
         * @param options some options required during tls accept
         * @return whether the encrypted accept is successfully established
         */
        bool TlsAcceptToHost(int sock, const TlsSocket::TLSConnectOptions &options);

        /**
         * Set the configuration items for establishing encrypted connections
         * @param config configuration item when establishing encrypted connection
         */
        void SetTlsConfiguration(const TlsSocket::TLSConnectOptions &config);

        /**
         * Set address information
         */
        void SetAddress(const Socket::NetAddress address);

        /**
         * Set local address information
         */
        void SetLocalAddress(const Socket::NetAddress address);

        /**
         * Send data through an established encrypted connection
         * @param data data sent over an established encrypted connection
         * @return whether the data is successfully sent to the server
         */
        bool Send(const std::string &data);

        /**
         * Receive the data sent by the server through the established encrypted connection
         * @param buffer receive the data sent by the server
         * @param maxBufferSize the size of the data received from the server
         * @return whether the data sent by the server is successfully received
         */
        int Recv(char *buffer, int maxBufferSize);

        /**
         * Disconnect encrypted connection
         * @return whether the encrypted connection was successfully disconnected
         */
        bool Close();

        /**
         * Set the application layer negotiation protocol in the encrypted communication process
         * @param alpnProtocols application layer negotiation protocol
         * @return set whether the application layer negotiation protocol is successful during encrypted communication
         */
        bool SetAlpnProtocols(const std::vector<std::string> &alpnProtocols);

        /**
         * Storage of server communication related network information
         * @param remoteInfo communication related network information
         */
        void MakeRemoteInfo(Socket::SocketRemoteInfo &remoteInfo);

        /**
         * Get configuration options for encrypted communication process
         * @return configuration options for encrypted communication processes
         */
        [[nodiscard]] TlsSocket::TLSConfiguration GetTlsConfiguration() const;

        /**
         * Obtain the cipher suite during encrypted communication
         * @return crypto suite used in encrypted communication
         */
        [[nodiscard]] std::vector<std::string> GetCipherSuite() const;

        /**
         * Obtain the peer certificate used in encrypted communication
         * @return peer certificate used in encrypted communication
         */
        [[nodiscard]] std::string GetRemoteCertificate() const;

        /**
         * Obtain the peer certificate used in encrypted communication
         * @return peer certificate serialization data used in encrypted communication
         */
        [[nodiscard]] const TlsSocket::X509CertRawData &GetRemoteCertRawData() const;

        /**
         * Obtain the certificate used in encrypted communication
         * @return certificate serialization data used in encrypted communication
         */
        [[nodiscard]] const TlsSocket::X509CertRawData &GetCertificate() const;

        /**
         * Get the encryption algorithm used in encrypted communication
         * @return encryption algorithm used in encrypted communication
         */
        [[nodiscard]] std::vector<std::string> GetSignatureAlgorithms() const;

        /**
         * Obtain the communication protocol used in encrypted communication
         * @return communication protocol used in encrypted communication
         */
        [[nodiscard]] std::string GetProtocol() const;

        /**
         * Set the information about the shared signature algorithm supported by peers during encrypted communication
         * @return information about peer supported shared signature algorithms
         */
        [[nodiscard]] bool SetSharedSigals();

        /**
         * Obtain the ssl used in encrypted communication
         * @return SSL used in encrypted communication
         */
        [[nodiscard]] ssl_st *GetSSL() const;

        /**
         * Get address information
         * @return Returns the address information of the remote client
         */
        [[nodiscard]] Socket::NetAddress GetAddress() const;

        /**
         * Get local address information
         * @return Returns the address information of the local accept connect
         */
        [[nodiscard]] Socket::NetAddress GetLocalAddress() const;

        /**
         * Get address information
         * @return Returns the address information of the remote client
         */
        [[nodiscard]] int GetSocketFd() const;

        /**
         * Get EventManager information
         * @return Returns the address information of the remote client
         */
        [[nodiscard]] std::shared_ptr<EventManager> GetEventManager() const;

        void OnMessage(const OnMessageCallback &onMessageCallback);
        /**
         * Unregister the callback which is called when message is received
         */
        void OffMessage();

        void CallOnMessageCallback(int32_t socketFd, const std::string &data,
                                   const Socket::SocketRemoteInfo &remoteInfo);

        void SetEventManager(std::shared_ptr<EventManager> eventManager);

        void SetClientID(int32_t clientID);

        [[nodiscard]] int GetClientID();

        void CallOnCloseCallback(const int32_t socketFd);
        void OnClose(const OnCloseCallback &onCloseCallback);
        OnCloseCallback onCloseCallback_;

        /**
         * Off Close
         */
        void OffClose();

        /**
         * Register the callback that is called when an error occurs
         * @param onErrorCallback callback invoked when an error occurs
         */
        void OnError(const TlsSocket::OnErrorCallback &onErrorCallback);
        /**
         * Off Error
         */
        void OffError();

        void CallOnErrorCallback(int32_t err, const std::string &errString);

        class DataCache {
        public:
            
            CacheInfo Get()
            {
                std::lock_guard l(mutex_);
                CacheInfo cache = cacheDeque_.front();
                cacheDeque_.pop_front();
                return cache;
            }
            void Set(const CacheInfo &data)
            {
                std::lock_guard l(mutex_);
                cacheDeque_.emplace_back(data);
            }
            bool IsEmpty()
            {
                std::lock_guard l(mutex_);
                return cacheDeque_.empty();
            }

        private:
            std::deque<CacheInfo> cacheDeque_;
            std::mutex mutex_;
        };

        TlsSocket::OnErrorCallback onErrorCallback_;

    private:
        bool StartTlsAccept(const TlsSocket::TLSConnectOptions &options);
        bool CreatTlsContext();
        bool StartShakingHands(const TlsSocket::TLSConnectOptions &options);
        bool GetRemoteCertificateFromPeer(X509 *peerX509);
        bool SetRemoteCertRawData(X509 *peerX509);
        std::string CheckServerIdentityLegal(const std::string &hostName, const X509 *x509Certificates);
        std::string CheckServerIdentityLegal(const std::string &hostName, X509_EXTENSION *ext,
                                             const X509 *x509Certificates);
        void CachedMessageCallback();

    private:
        ssl_st *ssl_ = nullptr;
        int32_t socketFd_ = -1;

        TlsSocket::TLSContextServer tlsContext_;
        TlsSocket::TLSConfiguration connectionConfiguration_;
        Socket::NetAddress address_;
        Socket::NetAddress localAddress_;
        TlsSocket::X509CertRawData remoteRawData_;

        std::string hostName_;
        std::string remoteCert_;
        std::string keyPass_;

        std::vector<std::string> signatureAlgorithms_;
        std::unique_ptr<TlsSocket::TLSContextServer> tlsContextServerPointer_ = nullptr;

        std::shared_ptr<EventManager> eventManager_ = nullptr;
        int32_t clientID_ = 0;
        OnMessageCallback onMessageCallback_;
        std::shared_ptr<DataCache> dataCache_ = std::make_shared<DataCache>();
    };

private:
    void SetLocalTlsConfiguration(const TlsSocket::TLSConnectOptions &config);
    bool RecvRemoteInfo(int socketFd, int index);
    void RemoveConnect(int socketFd);
    void AddConnect(int socketFd, std::shared_ptr<Connection> connection);
    void CallListenCallback(int32_t err, ListenCallback callback);
    void CallOnErrorCallback(int32_t err, const std::string &errString);

    void CallGetStateCallback(int32_t err, const Socket::SocketStateBase &state, TlsSocket::GetStateCallback callback);
    void CallOnConnectCallback(const int32_t socketFd, std::shared_ptr<EventManager> eventManager);
    void CallSendCallback(int32_t err, TlsSocket::SendCallback callback);
    bool ExecBind(const Socket::NetAddress &address, const ListenCallback &callback);
    void ExecAccept(const TlsSocket::TLSConnectOptions &tlsAcceptOptions, const ListenCallback &callback);
    void MakeIpSocket(sa_family_t family);
    void GetAddr(const Socket::NetAddress &address, sockaddr_in *addr4, sockaddr_in6 *addr6, sockaddr **addr,
                 socklen_t *len);
    static constexpr const size_t MAX_ERROR_LEN = 128;
    static constexpr const size_t MAX_BUFFER_SIZE = 8192;

    void PollThread(const TlsSocket::TLSConnectOptions &tlsListenOptions);
    void NotifyRcvThdExit();
    void WaitForRcvThdExit();
private:
    std::mutex mutex_;
    std::shared_mutex connectMutex_;
    std::mutex sockRcvThdMtx_;
    std::condition_variable sockRcvThdCon_;
    bool sockRcvExit_ = false;
    int listenSocketFd_ = -1;
    Socket::NetAddress address_;
    Socket::NetAddress localAddress_;

    std::map<int, std::shared_ptr<Connection>> clientIdConnections_;
    TlsSocket::TLSConfiguration TLSServerConfiguration_;

    OnConnectCallback onConnectCallback_;
    TlsSocket::OnErrorCallback onErrorCallback_;

    bool GetTlsConnectionLocalAddress(int acceptSockFD, Socket::NetAddress &localAddress);
    void ProcessTcpAccept(const TlsSocket::TLSConnectOptions &tlsListenOptions, int clientId);
    bool DropFdFromPollList(int &fd_index);
    void InitPollList(const int &listendFd);

    pollfd fds_[USER_LIMIT + 1];
    bool isRunning_ = false;

public:
    std::shared_ptr<Connection> GetConnectionByClientID(int clientid);
    int GetConnectionClientCount();

    std::shared_ptr<Connection> GetConnectionByClientEventManager(const std::shared_ptr<EventManager> &eventManager);
    void CloseConnectionByEventManager(const std::shared_ptr<EventManager> &eventManager);
    void DeleteConnectionByEventManager(const std::shared_ptr<EventManager> &eventManager);
    void SetTlsConnectionSecureOptions(const TlsSocket::TLSConnectOptions &tlsListenOptions, int clientID,
                                       int connectFD, std::shared_ptr<Connection> &connection);
};
} // namespace TlsSocketServer
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATIONNETSTACK_TLS_SERVER_SOCEKT_H
