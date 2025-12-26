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

#include "http_client_constant.h"
#include <unistd.h>
#include <string>

namespace OHOS {
namespace NetStack {
namespace HttpClient {
const char *const HttpConstant::HTTP_METHOD_GET = "GET";
const char *const HttpConstant::HTTP_METHOD_HEAD = "HEAD";
const char *const HttpConstant::HTTP_METHOD_OPTIONS = "OPTIONS";
const char *const HttpConstant::HTTP_METHOD_TRACE = "TRACE";
const char *const HttpConstant::HTTP_METHOD_DELETE = "DELETE";
const char *const HttpConstant::HTTP_METHOD_POST = "POST";
const char *const HttpConstant::HTTP_METHOD_PUT = "PUT";
const char *const HttpConstant::HTTP_METHOD_CONNECT = "CONNECT";

const uint32_t HttpConstant::DEFAULT_READ_TIMEOUT = 60000;
const uint32_t HttpConstant::DEFAULT_CONNECT_TIMEOUT = 60000;
const uint32_t HttpConstant::DEFAULT_MAX_LIMIT = 5 * 1024 * 1024;
const uint32_t HttpConstant::MAX_LIMIT = 100 * 1024 * 1024;

const size_t HttpConstant::MAX_JSON_PARSE_SIZE = 65536;
const size_t HttpConstant::MAX_DATA_LIMIT = 100 * 1024 * 1024;

const char *const HttpConstant::PARAM_KEY_METHOD = "method";
const char *const HttpConstant::PARAM_KEY_EXTRA_DATA = "extraData";
const char *const HttpConstant::PARAM_KEY_HEADER = "header";
const char *const HttpConstant::PARAM_KEY_READ_TIMEOUT = "readTimeout";
const char *const HttpConstant::PARAM_KEY_CONNECT_TIMEOUT = "connectTimeout";
const char *const HttpConstant::PARAM_KEY_USING_PROTOCOL = "usingProtocol";
const char *const HttpConstant::PARAM_KEY_USING_CACHE = "usingCache";
const char *const HttpConstant::PARAM_KEY_EXPECT_DATA_TYPE = "expectDataType";
const char *const HttpConstant::PARAM_KEY_PRIORITY = "priority";

const char *const HttpConstant::PARAM_KEY_USING_HTTP_PROXY = "usingProxy";
const char *const HttpConstant::PARAM_KEY_CA_PATH = "caPath";

const char *const HttpConstant::HTTP_PROXY_KEY_HOST = "host";
const char *const HttpConstant::HTTP_PROXY_KEY_PORT = "port";
const char *const HttpConstant::HTTP_PROXY_KEY_EXCLUSION_LIST = "exclusionList";
const char *const HttpConstant::HTTP_PROXY_EXCLUSIONS_SEPARATOR = ",";

const char *const HttpConstant::RESPONSE_KEY_RESULT = "result";
const char *const HttpConstant::RESPONSE_KEY_RESPONSE_CODE = "responseCode";
const char *const HttpConstant::RESPONSE_KEY_HEADER = "header";
const char *const HttpConstant::RESPONSE_KEY_COOKIES = "cookies";
const char *const HttpConstant::RESPONSE_KEY_SET_COOKIE = "set-cookie";
const char *const HttpConstant::RESPONSE_KEY_SET_COOKIE_SEPARATOR = "\r\n";
const char *const HttpConstant::RESPONSE_KEY_RESULT_TYPE = "resultType";

const char *const HttpConstant::HTTP_URL_PARAM_START = "?";
const char *const HttpConstant::HTTP_URL_PARAM_SEPARATOR = "&";
const char *const HttpConstant::HTTP_URL_NAME_VALUE_SEPARATOR = "=";
const char *const HttpConstant::HTTP_HEADER_SEPARATOR = ":";
const char *const HttpConstant::HTTP_HEADER_BLANK_SEPARATOR = ";";
const char *const HttpConstant::HTTP_LINE_SEPARATOR = "\r\n";
const char *const HttpConstant::HTTP_RESPONSE_HEADER_SEPARATOR = "\r\n\r\n";

const char *const HttpConstant::HTTP_DEFAULT_USER_AGENT = "libcurl-agent/1.0";

#ifdef HTTP_MULTIPATH_CERT_ENABLE
const int32_t HttpConstant::UID_TRANSFORM_DIVISOR = 200000;
const std::string HttpConstant::USER_CERT_BASE_PATH = "/data/certificates/user_cacerts/";
const std::string HttpConstant::USER_CERT_ROOT_PATH = "/data/certificates/user_cacerts/0/";
#endif

const char *const HttpConstant::HTTP_CONTENT_TYPE = "content-type";
const char *const HttpConstant::HTTP_CONTENT_TYPE_URL_ENCODE = "application/x-www-form-urlencoded";
const char *const HttpConstant::HTTP_CONTENT_TYPE_JSON = "application/json";
const char *const HttpConstant::HTTP_CONTENT_TYPE_OCTET_STREAM = "application/octet-stream";
const char *const HttpConstant::HTTP_CONTENT_TYPE_IMAGE = "image";
const char *const HttpConstant::HTTP_CONTENT_TYPE_MULTIPART = "multipart/form-data";
const char *const HttpConstant::HTTP_PREPARE_CA_PATH = "/etc/security/certificates";

const char *const HttpConstant::HTTP_CONTENT_ENCODING_GZIP = "gzip";

const char *const HttpConstant::REQUEST_TIME = "requestTime";
const char *const HttpConstant::RESPONSE_TIME = "responseTime";
} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS