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

#include <iostream>

#include "http_client_error.h"
#include "netstack_log.h"

namespace OHOS {
namespace NetStack {
namespace HttpClient {

static const std::map<int32_t, const std::string> HTTP_ERR_MAP = {
    {HTTP_NONE_ERR, "No errors occurred"},
    {HTTP_PERMISSION_DENIED_CODE, "Permission denied"},
    {HTTP_PARSE_ERROR_CODE, "Parameter error"},
    {HTTP_UNSUPPORTED_PROTOCOL, "Unsupported protocol"},
    {HTTP_FAILED_INIT, "Failed to initialize"},
    {HTTP_URL_MALFORMAT, "Invalid URL format or missing URL"},
    {HTTP_COULDNT_RESOLVE_PROXY, "Failed to resolve the proxy name"},
    {HTTP_COULDNT_RESOLVE_HOST, "Failed to resolve the host name"},
    {HTTP_COULDNT_CONNECT, "Failed to connect to the server"},
    {HTTP_WEIRD_SERVER_REPLY, "Invalid server response"},
    {HTTP_REMOTE_ACCESS_DENIED, "Access to the remote resource denied"},
    {HTTP_HTTP2_ERROR, "Error in the HTTP2 framing layer"},
    {HTTP_PARTIAL_FILE, "Transferred a partial file"},
    {HTTP_WRITE_ERROR, "Failed to write the received data to the disk or application"},
    {HTTP_UPLOAD_FAILED, "Upload failed"},
    {HTTP_READ_ERROR, "Failed to open or read local data from the file or application"},
    {HTTP_OUT_OF_MEMORY, "Out of memory"},
    {HTTP_POST_ERROR, "Post error"},
    {HTTP_OPERATION_TIMEDOUT, "Operation timeout"},
    {HTTP_TASK_CANCELED, "Task was canceled"},
    {HTTP_TOO_MANY_REDIRECTS, "The number of redirections reaches the maximum allowed"},
    {HTTP_GOT_NOTHING, "The server returned nothing (no header or data)"},
    {HTTP_SEND_ERROR, "Failed to send data to the peer"},
    {HTTP_RECV_ERROR, "Failed to receive data from the peer"},
    {HTTP_SSL_CERTPROBLEM, "Local SSL certificate error"},
    {HTTP_SSL_CIPHER, "The specified SSL cipher cannot be used"},
    {HTTP_PEER_FAILED_VERIFICATION, "Invalid SSL peer certificate or SSH remote key"},
    {HTTP_BAD_CONTENT_ENCODING, "Invalid HTTP encoding format"},
    {HTTP_FILESIZE_EXCEEDED, "Maximum file size exceeded"},
    {HTTP_REMOTE_DISK_FULL, "Remote disk full"},
    {HTTP_REMOTE_FILE_EXISTS, "Remote file already exists"},
    {HTTP_SSL_CACERT_BADFILE, "The SSL CA certificate does not exist or is inaccessible"},
    {HTTP_REMOTE_FILE_NOT_FOUND, "Remote file not found"},
    {HTTP_AUTH_ERROR, "Authentication error"},
    {HTTP_SSL_PINNEDPUBKEYNOTMATCH, "Specified pinned public key did not match"},
    {HTTP_CLEARTEXT_NOT_PERMITTED, "Cleartext traffic not permitted"},
    {HTTP_UNKNOWN_OTHER_ERROR, "Internal error"},
};

const std::string &HttpClientError::GetErrorMessage() const
{
    auto err = errorCode_;
    if (HTTP_ERR_MAP.find(err) == HTTP_ERR_MAP.end()) {
        err = HTTP_UNKNOWN_OTHER_ERROR;
    }

    return HTTP_ERR_MAP.find(err)->second;
}

void HttpClientError::SetErrorCode(HttpErrorCode code)
{
    errorCode_ = code;
}

HttpErrorCode HttpClientError::GetErrorCode() const
{
    return errorCode_;
}

void HttpClientError::SetCURLResult(CURLcode result)
{
    if (result != CURLE_OK) {
        NETSTACK_LOGE("HttpClient CURLcode result %{public}d", result);
    }
    HttpErrorCode err = HTTP_UNKNOWN_OTHER_ERROR;
    if (result > CURLE_OK) {
        if (HTTP_ERR_MAP.find(result + HTTP_ERROR_CODE_BASE) != HTTP_ERR_MAP.end()) {
            err = static_cast<HttpErrorCode>(result + HTTP_ERROR_CODE_BASE);
        }
    } else {
        err = HTTP_NONE_ERR;
    }
    SetErrorCode(err);
}
} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS