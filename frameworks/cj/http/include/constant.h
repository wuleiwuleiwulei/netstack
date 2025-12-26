/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HTTP_CONSTANT_H
#define HTTP_CONSTANT_H

#include <cstddef>
#include <cstdint>

#include "curl/curl.h"

namespace OHOS::NetStack::Http {
constexpr const uint32_t MAX_LIMIT = 100 * 1024 * 1024;
constexpr const uint32_t DEFAULT_MAX_LIMIT = 5 * 1024 * 1024;
constexpr const uint32_t DEFAULT_READ_TIMEOUT = 60000;
constexpr const uint32_t DEFAULT_CONNECT_TIMEOUT = 60000;
constexpr const size_t MAX_JSON_PARSE_SIZE = 65536;
constexpr const uint32_t MIN_PRIORITY = 1;
constexpr const uint32_t MAX_PRIORITY = 1000;
constexpr const int64_t MIN_RESUM_NUMBER = 1;
constexpr const int64_t MAX_RESUM_NUMBER = 4294967296;
constexpr const size_t MAP_TUPLE_SIZE = 2;

constexpr const char *HTTP_METHOD_GET = "GET";
constexpr const char *HTTP_METHOD_HEAD = "HEAD";
constexpr const char *HTTP_METHOD_OPTIONS = "OPTIONS";
constexpr const char *HTTP_METHOD_TRACE = "TRACE";
constexpr const char *HTTP_METHOD_DELETE = "DELETE";
constexpr const char *HTTP_METHOD_POST = "POST";
constexpr const char *HTTP_METHOD_PUT = "PUT";
constexpr const char *HTTP_METHOD_CONNECT = "CONNECT";
constexpr const char *HTTP_LINE_SEPARATOR = "\r\n";
constexpr const char *HTTP_HEADER_SEPARATOR = ":";
constexpr const char *RESPONSE_KEY_RESULT = "result";
constexpr const char *RESPONSE_KEY_RESPONSE_CODE = "responseCode";
constexpr const char *RESPONSE_KEY_HEADER = "header";
constexpr const char *RESPONSE_KEY_COOKIES = "cookies";
constexpr const char *RESPONSE_KEY_RESULT_TYPE = "resultType";
constexpr const char *REQUEST_TIME = "requestTime";
constexpr const char *RESPONSE_TIME = "responseTime";
constexpr const char *HTTP_HEADER_BLANK_SEPARATOR = ";";
constexpr const char *HTTP_RESPONSE_HEADER_SEPARATOR = "\r\n\r\n";
constexpr const char *HTTP_URL_PARAM_START = "?";
constexpr const char *HTTP_URL_PARAM_SEPARATOR = "&";
constexpr const char *HTTP_URL_NAME_VALUE_SEPARATOR = "=";
constexpr const char *HTTP_PROXY_EXCLUSIONS_SEPARATOR = ",";
// cache constant
constexpr const int DECIMAL = 10;
constexpr const char *SPLIT = ", ";
constexpr const char EQUAL = '=';

constexpr const char *HTTP_DEFAULT_USER_AGENT = "libcurl-agent/1.0";
constexpr const char *RESPONSE_KEY_SET_COOKIE = "set-cookie";
constexpr const char *NO_CACHE = "no-cache";
constexpr const char *NO_STORE = "no-store";
constexpr const char *NO_TRANSFORM = "no-transform";
constexpr const char *ONLY_IF_CACHED = "only-if-cached";
constexpr const char *MAX_AGE = "max-age";
constexpr const char *MAX_STALE = "max-stale";
constexpr const char *MIN_FRESH = "min-fresh";
constexpr const char *CACHE_CONTROL = "cache-control";
constexpr const char *IF_MODIFIED_SINCE = "if-modified-since";
constexpr const char *IF_NONE_MATCH = "if-none-match";
constexpr const char *MUST_REVALIDATE = "must-revalidate";
constexpr const char *PUBLIC = "public";
constexpr const char *PRIVATE = "private";
constexpr const char *PROXY_REVALIDATE = "proxy-revalidate";
constexpr const char *S_MAXAGE = "s-maxage";
constexpr const char *EXPIRES = "expires";
constexpr const char *LAST_MODIFIED = "last-modified";
constexpr const char *ETAG = "etag";
constexpr const char *AGE = "age";
constexpr const char *DATE = "date";
constexpr const int INVALID_TIME = -1;
constexpr const char *HTTP_PREPARE_CA_PATH = "/etc/security/certificates";

constexpr const char *HTTP_CONTENT_TYPE = "content-type";
constexpr const char *HTTP_CONTENT_TYPE_URL_ENCODE = "application/x-www-form-urlencoded";
constexpr const char *HTTP_CONTENT_TYPE_JSON = "application/json";
constexpr const char *HTTP_CONTENT_TYPE_OCTET_STREAM = "application/octet-stream";
constexpr const char *HTTP_CONTENT_TYPE_IMAGE = "image";
constexpr const char *HTTP_CONTENT_TYPE_MULTIPART = "multipart/form-data";

// events
constexpr const char *ON_HEADER_RECEIVE = "headerReceive";
constexpr const char *ON_DATA_RECEIVE = "dataReceive";
constexpr const char *ON_DATA_END = "dataEnd";
constexpr const char *ON_DATA_RECEIVE_PROGRESS = "dataReceiveProgress";
constexpr const char *ON_HEADERS_RECEIVE = "headersReceive";


constexpr const char *RESPONSE_PERFORMANCE_TIMING = "performanceTiming";
constexpr const char *RESPONSE_DNS_TIMING = "dnsTiming";
constexpr const char *RESPONSE_TCP_TIMING = "tcpTiming";
constexpr const char *RESPONSE_TLS_TIMING = "tlsTiming";
constexpr const char *RESPONSE_FIRST_SEND_TIMING = "firstSendTiming";
constexpr const char *RESPONSE_FIRST_RECEIVE_TIMING = "firstReceiveTiming";
constexpr const char *RESPONSE_TOTAL_FINISH_TIMING = "totalFinishTiming";
constexpr const char *RESPONSE_REDIRECT_TIMING = "redirectTiming";
constexpr const char *RESPONSE_HEADER_TIMING = "responseHeaderTiming";
constexpr const char *RESPONSE_BODY_TIMING = "responseBodyTiming";
constexpr const char *RESPONSE_TOTAL_TIMING = "totalTiming";

enum class ResponseCode {
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

enum class HttpErrorCode {
    HTTP_ERROR_CODE_BASE = 2300000,
    HTTP_UNSUPPORTED_PROTOCOL = HTTP_ERROR_CODE_BASE + CURLE_UNSUPPORTED_PROTOCOL,
    HTTP_URL_MALFORMAT = HTTP_ERROR_CODE_BASE + CURLE_URL_MALFORMAT,
    HTTP_COULDNT_RESOLVE_PROXY = HTTP_ERROR_CODE_BASE + CURLE_COULDNT_RESOLVE_PROXY,
    HTTP_COULDNT_RESOLVE_HOST = HTTP_ERROR_CODE_BASE + CURLE_COULDNT_RESOLVE_HOST,
    HTTP_COULDNT_CONNECT = HTTP_ERROR_CODE_BASE + CURLE_COULDNT_CONNECT,
    HTTP_WEIRD_SERVER_REPLY = HTTP_ERROR_CODE_BASE + CURLE_WEIRD_SERVER_REPLY,
    HTTP_REMOTE_ACCESS_DENIED = HTTP_ERROR_CODE_BASE + CURLE_REMOTE_ACCESS_DENIED,
    HTTP_HTTP2_ERROR = HTTP_ERROR_CODE_BASE + CURLE_HTTP2,
    HTTP_PARTIAL_FILE = HTTP_ERROR_CODE_BASE + CURLE_PARTIAL_FILE,
    HTTP_WRITE_ERROR = HTTP_ERROR_CODE_BASE + CURLE_WRITE_ERROR,
    HTTP_UPLOAD_FAILED = HTTP_ERROR_CODE_BASE + CURLE_UPLOAD_FAILED,
    HTTP_READ_ERROR = HTTP_ERROR_CODE_BASE + CURLE_READ_ERROR,
    HTTP_OUT_OF_MEMORY = HTTP_ERROR_CODE_BASE + CURLE_OUT_OF_MEMORY,
    HTTP_OPERATION_TIMEDOUT = HTTP_ERROR_CODE_BASE + CURLE_OPERATION_TIMEDOUT,
    HTTP_TOO_MANY_REDIRECTS = HTTP_ERROR_CODE_BASE + CURLE_TOO_MANY_REDIRECTS,
    HTTP_GOT_NOTHING = HTTP_ERROR_CODE_BASE + CURLE_GOT_NOTHING,
    HTTP_SEND_ERROR = HTTP_ERROR_CODE_BASE + CURLE_SEND_ERROR,
    HTTP_RECV_ERROR = HTTP_ERROR_CODE_BASE + CURLE_RECV_ERROR,
    HTTP_SSL_CERTPROBLEM = HTTP_ERROR_CODE_BASE + CURLE_SSL_CERTPROBLEM,
    HTTP_SSL_CIPHER = HTTP_ERROR_CODE_BASE + CURLE_SSL_CIPHER,
    HTTP_PEER_FAILED_VERIFICATION = HTTP_ERROR_CODE_BASE + CURLE_PEER_FAILED_VERIFICATION,
    HTTP_BAD_CONTENT_ENCODING = HTTP_ERROR_CODE_BASE + CURLE_BAD_CONTENT_ENCODING,
    HTTP_FILESIZE_EXCEEDED = HTTP_ERROR_CODE_BASE + CURLE_FILESIZE_EXCEEDED,
    HTTP_REMOTE_DISK_FULL = HTTP_ERROR_CODE_BASE + CURLE_REMOTE_DISK_FULL,
    HTTP_REMOTE_FILE_EXISTS = HTTP_ERROR_CODE_BASE + CURLE_REMOTE_FILE_EXISTS,
    HTTP_SSL_CACERT_BADFILE = HTTP_ERROR_CODE_BASE + CURLE_SSL_CACERT_BADFILE,
    HTTP_REMOTE_FILE_NOT_FOUND = HTTP_ERROR_CODE_BASE + CURLE_REMOTE_FILE_NOT_FOUND,
    HTTP_AUTH_ERROR = HTTP_ERROR_CODE_BASE + CURLE_AUTH_ERROR,
    HTTP_UNKNOWN_OTHER_ERROR = 2300999
};

enum class HttpDataType {
    /**
     * The returned type is string.
     */
    STRING,
    /**
     * The returned type is Object.
     */
    OBJECT = 1,
    /**
     * The returned type is ArrayBuffer.
     */
    ARRAY_BUFFER = 2,
    /**
     * The returned type is not set.
     */
    NO_DATA_TYPE = 3,
};
} // namespace OHOS::NetStack::Http

#endif /* HTTP_CONSTANT_H */
