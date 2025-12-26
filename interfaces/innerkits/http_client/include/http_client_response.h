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

#ifndef COMMUNICATIONNETSTACK_HTTP_CLIENT_RESPONSE_H
#define COMMUNICATIONNETSTACK_HTTP_CLIENT_RESPONSE_H

#include <map>
#include <string>
#include "common.h"

namespace OHOS {
namespace NetStack {
namespace HttpClient {
static constexpr const char *WARNING = "Warning";

enum AddressFamily {
    FAMILY_INVALID = -1,
    FAMILY_IPV4 = 1,
    FAMILY_IPV6 = 2,
};
 
struct NetAddress {
    std::string address_;
    int8_t family_;
    uint16_t port_;
};
 
struct HttpStatistics {
    NetAddress serverIpAddress;
};

enum ResponseCode {
    NONE = 0,
    OK = 200,
    CREATED,
    ACCEPTED,
    NOT_AUTHORITATIVE,
    NO_CONTENT,
    RESET,
    PARTIAL,
    MULT_CHOICE = 300,
    MOVED_PERM,
    MOVED_TEMP,
    SEE_OTHER,
    NOT_MODIFIED,
    USE_PROXY,
    BAD_REQUEST = 400,
    UNAUTHORIZED,
    PAYMENT_REQUIRED,
    FORBIDDEN,
    NOT_FOUND,
    BAD_METHOD,
    NOT_ACCEPTABLE,
    PROXY_AUTH,
    CLIENT_TIMEOUT,
    CONFLICT,
    GONE,
    LENGTH_REQUIRED,
    PRECON_FAILED,
    ENTITY_TOO_LARGE,
    REQ_TOO_LONG,
    UNSUPPORTED_TYPE,
    INTERNAL_ERROR = 500,
    NOT_IMPLEMENTED,
    BAD_GATEWAY,
    UNAVAILABLE,
    GATEWAY_TIMEOUT,
    VERSION,
};

/**
 * Counting the time taken of various stages of HTTP request.
 */
struct PerformanceInfo {
    /** Time taken from startup to DNS resolution completion, in milliseconds. */
    double dnsTiming = 0.0;
    /** Time taken from startup to TCP connection completion, in milliseconds. */
    double connectTiming = 0.0;
    /** Time taken from startup to TLS connection completion, in milliseconds. */
    double tlsTiming = 0.0;
    /** Time taken from startup to start sending the first byte, in milliseconds. */
    double firstSendTiming = 0.0;
    /** Time taken from startup to receiving the first byte, in milliseconds. */
    double firstReceiveTiming = 0.0;
    /** Time taken from startup to the completion of the request, in milliseconds. */
    double totalTiming = 0.0;
    /** Time taken from startup to completion of all redirection steps, in milliseconds. */
    double redirectTiming = 0.0;
};

class HttpClientResponse {
public:
    /**
     * Default constructor for HttpClientResponse.
     */
    HttpClientResponse() : responseCode_(NONE), result_(""){};

    /**
     * Get the response code of the HTTP response.
     * @return The response code.
     */
    [[nodiscard]] ResponseCode GetResponseCode() const;

    /**
     * Get the header of the HTTP response.
     * @return The header of the response.
     */
    [[nodiscard]] const std::string &GetHeader() const;

    /**
     * Get the cookies of the HTTP response.
     * @return The cookies of the response.
     */
    [[nodiscard]] const std::string &GetCookies() const;

    /**
     * Get the set-cookie of the HTTP response.
     * @return The set-cookie of the response.
     */
    [[nodiscard]] const std::vector<std::string> &GetsetCookie() const;

    /**
     * Get the request time of the HTTP response.
     * @return The request time of the response.
     */
    [[nodiscard]] const std::string &GetRequestTime() const;

    /**
     * Get the response time of the HTTP response.
     * @return The response time of the response.
     */
    [[nodiscard]] const std::string &GetResponseTime() const;

    /**
     * Set the request time of the HTTP response.
     * @param time The request time to be set.
     */
    void SetRequestTime(const std::string &time);

    /**
     * @brief Set the response time of the HTTP response.
     * @param time The response time to be set.
     */
    void SetResponseTime(const std::string &time);

    /**
     * Set the response code of the HTTP response.
     * @param code The response code to be set.
     */
    void SetResponseCode(ResponseCode code);

    /**
     * Parses the headers of the HTTP response.
     */
    void ParseHeaders();

    /**
     * Retrieves the headers of the HTTP response.
     * @return A constant reference to a map of header key-value pairs.
     */
    [[nodiscard]] const std::map<std::string, std::string> &GetHeaders() const;

    /**
     * Sets a warning message for the HTTP response.
     * @param val The warning message.
     */
    void SetWarning(const std::string &val);

    /**
     * Sets a raw header for the HTTP response.
     * @param header The raw header string.
     */
    void SetRawHeader(const std::string &header);

    /**
     * Get the raw header of the HTTP response.
     * @return The raw header of the response.
     */
    const std::string &GetRawHeader() const;

    /**
     * Sets the cookies for the HTTP response.
     * @param cookies The cookie string.
     */
    void SetCookies(const std::string &cookies);

    /**
     * Sets the result of the HTTP response.
     * @param res The result string.
     */
    void SetResult(const std::string &res);

    /**
     * Retrieves the result of the HTTP response.
     * @return A constant reference to the result string.
     */
    [[nodiscard]] const std::string &GetResult() const;

    /**
     * Get the time taken of various stages of HTTP request.
     * @return The performance info including the time taken of various stages of HTTP request.
     */
    [[nodiscard]] PerformanceInfo GetPerformanceTiming() const;

    /**
     * Get the statistics of HTTP request
     * @return The statistics including the information of HTTP request
     */
    [[nodiscard]] HttpStatistics GetHttpStatistics() const;

    /**
     * Sets the expect type of the HTTP response.
     * @param type The expect type.
     */
    void SetExpectDataType(const HttpDataType &type);

    /**
     * Get the time taken of various stages of HTTP request.
     * @return Expected types of the response result.
     */
    [[nodiscard]] HttpDataType GetExpectDataType() const;

private:
    friend class HttpClientTask;

    /**
     * @brief Append data to the header of the HTTP response.
     * @param data Pointer to the data.
     * @param length Length of the data.
     */
    void AppendHeader(const char *data, size_t length);

    /**
     * Append data to the cookies of the HTTP response.
     * @param data Pointer to the data.
     * @param length Length of the data.
     */
    void AppendCookies(const char *data, size_t length);
    void AppendResult(const void *data, size_t length);
    void SetNetAddress(NetAddress &netAddress);

    ResponseCode responseCode_;
    std::string rawHeader_;
    std::map<std::string, std::string> headers_;
    std::string cookies_;
    std::string responseTime_;
    std::string requestTime_;
    std::string result_;
    HttpStatistics httpStatistics_;
    PerformanceInfo performanceInfo_;
    std::vector<std::string> setCookie_;
    HttpDataType dataType_ = HttpDataType::NO_DATA_TYPE;
};
} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATIONNETSTACK_HTTP_CLIENT_RESPONSE_H
