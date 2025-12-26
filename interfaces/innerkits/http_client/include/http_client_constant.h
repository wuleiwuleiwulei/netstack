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

#ifndef COMMUNICATIONNETSTACK_CONSTANT_H
#define COMMUNICATIONNETSTACK_CONSTANT_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace OHOS {
namespace NetStack {
namespace HttpClient {

class HttpConstant final {
public:
    /* Http Method */
    static const char *const HTTP_METHOD_GET;
    static const char *const HTTP_METHOD_HEAD;
    static const char *const HTTP_METHOD_OPTIONS;
    static const char *const HTTP_METHOD_TRACE;
    static const char *const HTTP_METHOD_DELETE;
    static const char *const HTTP_METHOD_POST;
    static const char *const HTTP_METHOD_PUT;
    static const char *const HTTP_METHOD_CONNECT;

    /* default options */
    static const uint32_t DEFAULT_READ_TIMEOUT;
    static const uint32_t DEFAULT_CONNECT_TIMEOUT;
    static const uint32_t DEFAULT_MAX_LIMIT;
    static const uint32_t MAX_LIMIT;

    static const size_t MAX_JSON_PARSE_SIZE;
    static const size_t MAX_DATA_LIMIT;

    /* options key */
    static const char *const PARAM_KEY_METHOD;
    static const char *const PARAM_KEY_EXTRA_DATA;
    static const char *const PARAM_KEY_HEADER;
    static const char *const PARAM_KEY_READ_TIMEOUT;
    static const char *const PARAM_KEY_CONNECT_TIMEOUT;
    static const char *const PARAM_KEY_USING_PROTOCOL;
    static const char *const PARAM_KEY_USING_CACHE;
    static const char *const PARAM_KEY_EXPECT_DATA_TYPE;
    static const char *const PARAM_KEY_PRIORITY;
    static const char *const PARAM_KEY_CA_PATH;
    static const char *const HTTP_PREPARE_CA_PATH;

    static const char *const PARAM_KEY_USING_HTTP_PROXY;

    static const char *const HTTP_PROXY_KEY_HOST;
    static const char *const HTTP_PROXY_KEY_PORT;
    static const char *const HTTP_PROXY_KEY_EXCLUSION_LIST;
    static const char *const HTTP_PROXY_EXCLUSIONS_SEPARATOR;

    static const char *const RESPONSE_KEY_RESULT;
    static const char *const RESPONSE_KEY_RESPONSE_CODE;
    static const char *const RESPONSE_KEY_HEADER;
    static const char *const RESPONSE_KEY_COOKIES;
    static const char *const RESPONSE_KEY_SET_COOKIE;
    static const char *const RESPONSE_KEY_SET_COOKIE_SEPARATOR;
    static const char *const RESPONSE_KEY_RESULT_TYPE;

    static const char *const HTTP_URL_PARAM_START;
    static const char *const HTTP_URL_PARAM_SEPARATOR;
    static const char *const HTTP_URL_NAME_VALUE_SEPARATOR;
    static const char *const HTTP_HEADER_SEPARATOR;
    static const char *const HTTP_HEADER_BLANK_SEPARATOR;
    static const char *const HTTP_LINE_SEPARATOR;
    static const char *const HTTP_RESPONSE_HEADER_SEPARATOR;

    static const char *const HTTP_DEFAULT_USER_AGENT;

#ifdef HTTP_MULTIPATH_CERT_ENABLE
    static const int32_t UID_TRANSFORM_DIVISOR;
    static const std::string USER_CERT_BASE_PATH;
    static const std::string USER_CERT_ROOT_PATH;
#endif

    static const char *const HTTP_CONTENT_TYPE;
    static const char *const HTTP_CONTENT_TYPE_URL_ENCODE;
    static const char *const HTTP_CONTENT_TYPE_JSON;
    static const char *const HTTP_CONTENT_TYPE_OCTET_STREAM;
    static const char *const HTTP_CONTENT_TYPE_IMAGE;
    static const char *const HTTP_CONTENT_TYPE_MULTIPART;

    static const char *const HTTP_CONTENT_ENCODING_GZIP;

    static const char *const REQUEST_TIME;
    static const char *const RESPONSE_TIME;
};
} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS

#endif /* COMMUNICATIONNETSTACK_CONSTANT_H */
