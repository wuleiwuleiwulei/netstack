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

#ifndef COMMUNICATIONNETSTACK_HTTP_CLIENT_ERROR_H
#define COMMUNICATIONNETSTACK_HTTP_CLIENT_ERROR_H

#include <string>
#include <map>
#include <curl/curl.h>

namespace OHOS {
namespace NetStack {
namespace HttpClient {
enum HttpErrorCode {
    HTTP_NONE_ERR = 0,
    HTTP_PERMISSION_DENIED_CODE = 201,
    HTTP_PARSE_ERROR_CODE = 401,
    HTTP_ERROR_CODE_BASE = 2300000,
    HTTP_UNSUPPORTED_PROTOCOL = HTTP_ERROR_CODE_BASE + CURLE_UNSUPPORTED_PROTOCOL,
    HTTP_FAILED_INIT = HTTP_ERROR_CODE_BASE + CURLE_FAILED_INIT,
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
    HTTP_POST_ERROR = HTTP_ERROR_CODE_BASE + CURLE_HTTP_POST_ERROR,
    HTTP_TASK_CANCELED = HTTP_ERROR_CODE_BASE + CURLE_ABORTED_BY_CALLBACK,
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
    HTTP_SSL_PINNEDPUBKEYNOTMATCH = HTTP_ERROR_CODE_BASE + CURLE_SSL_PINNEDPUBKEYNOTMATCH,
    HTTP_CURLE_RANGE_ERROR = HTTP_ERROR_CODE_BASE + CURLE_RANGE_ERROR,
    HTTP_CLEARTEXT_NOT_PERMITTED = 2300997,
    HTTP_UNKNOWN_OTHER_ERROR = 2300999
};

class HttpClientError {
public:
    /**
     * Constructor that initializes the HttpClientError object.
     */
    HttpClientError() : errorCode_(HTTP_NONE_ERR) {}

    /**
     * Get the error code.
     * @return Error code of type HttpErrorCode.
     */
    [[nodiscard]] HttpErrorCode GetErrorCode() const;

    /**
     * Get the error message.
     * @return Error message string.
     */
    [[nodiscard]] const std::string &GetErrorMessage() const;

private:
    friend class HttpClientTask;

    /**
     * Set the error code.
     * @param code Error code of type HttpErrorCode.
     */
    void SetErrorCode(HttpErrorCode code);

    /**
     * Set the CURL result code.
     * @param result Result code of type CURLcode.
     */
    void SetCURLResult(CURLcode result);

    HttpErrorCode errorCode_;
};
} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATIONNETSTACK_HTTP_CLIENT_ERROR_H
