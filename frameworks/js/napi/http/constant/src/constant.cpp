/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "constant.h"

namespace OHOS::NetStack::Http {
const char *const HttpConstant::HTTP_METHOD_GET = "GET";
const char *const HttpConstant::HTTP_METHOD_HEAD = "HEAD";
const char *const HttpConstant::HTTP_METHOD_OPTIONS = "OPTIONS";
const char *const HttpConstant::HTTP_METHOD_TRACE = "TRACE";
const char *const HttpConstant::HTTP_METHOD_DELETE = "DELETE";
const char *const HttpConstant::HTTP_METHOD_POST = "POST";
const char *const HttpConstant::HTTP_METHOD_PUT = "PUT";
const char *const HttpConstant::HTTP_METHOD_CONNECT = "CONNECT";

const uint32_t HttpConstant::DEFAULT_MAX_LIMIT = 5 * 1024 * 1024;
const uint32_t HttpConstant::MAX_LIMIT = 100 * 1024 * 1024;
const uint32_t HttpConstant::DEFAULT_READ_TIMEOUT = 60000;
const uint32_t HttpConstant::DEFAULT_CONNECT_TIMEOUT = 60000;

const size_t HttpConstant::MAX_JSON_PARSE_SIZE = 65536;

const char *const HttpConstant::PARAM_KEY_METHOD = "method";
const char *const HttpConstant::PARAM_KEY_CUSTOM_METHOD = "customMethod";
const char *const HttpConstant::PARAM_KEY_EXTRA_DATA = "extraData";
const char *const HttpConstant::PARAM_KEY_HEADER = "header";
const char *const HttpConstant::PARAM_KEY_MAX_LIMIT = "maxLimit";
const char *const HttpConstant::PARAM_KEY_READ_TIMEOUT = "readTimeout";
const char *const HttpConstant::PARAM_KEY_DNS_SERVERS = "dnsServers";
const char *const HttpConstant::PARAM_KEY_RESUME_FROM = "resumeFrom";
const char *const HttpConstant::PARAM_KEY_RESUME_TO = "resumeTo";
const char *const HttpConstant::PARAM_KEY_CONNECT_TIMEOUT = "connectTimeout";
const char *const HttpConstant::PARAM_KEY_USING_PROTOCOL = "usingProtocol";
const char *const HttpConstant::PARAM_KEY_USING_CACHE = "usingCache";
const char *const HttpConstant::PARAM_KEY_EXPECT_DATA_TYPE = "expectDataType";
const char *const HttpConstant::PARAM_KEY_PRIORITY = "priority";
const char *const HttpConstant::PARAM_KEY_MAX_REDIRECTS = "maxRedirects";

const char *const HttpConstant::PARAM_KEY_USING_HTTP_PROXY = "usingProxy";
const char *const HttpConstant::PARAM_KEY_CA_PATH = "caPath";
const char *const HttpConstant::PARAM_KEY_CA_DATA = "caData";
const char *const HttpConstant::PARAM_KEY_DOH_URL = "dnsOverHttps";
const char *const HttpConstant::PARAM_KEY_CLIENT_CERT = "clientCert";
const char *const HttpConstant::PARAM_KEY_MULTI_FORM_DATA_LIST = "multiFormDataList";

const char *const HttpConstant::PARAM_KEY_CERTIFICATE_PINNING = "certificatePinning";

const char *const HttpConstant::PARAM_KEY_REMOTE_VALIDATION = "remoteValidation";
const char *const HttpConstant::PARAM_KEY_TLS_OPTION = "tlsOptions";
const char *const HttpConstant::PARAM_KEY_SERVER_AUTH = "serverAuthentication";

const char *const HttpConstant::HTTP_PROXY_KEY_HOST = "host";
const char *const HttpConstant::HTTP_PROXY_KEY_PORT = "port";
const char *const HttpConstant::HTTP_PROXY_KEY_EXCLUSION_LIST = "exclusionList";
const char *const HttpConstant::HTTP_PROXY_KEY_USERNAME = "username";
const char *const HttpConstant::HTTP_PROXY_KEY_PASSWORD = "password";

const char *const HttpConstant::HTTP_CLIENT_CERT = "certPath";
const char *const HttpConstant::HTTP_CLIENT_KEY = "keyPath";
const char *const HttpConstant::HTTP_CLIENT_CERT_TYPE = "certType";
const char *const HttpConstant::HTTP_CLIENT_KEY_PASSWD = "keyPassword";

const char *const HttpConstant::HTTP_PUBLIC_KEY_HASH = "publicKeyHash";
const char *const HttpConstant::HTTP_HASH_ALGORITHM = "hashAlgorithm";

const char *const HttpConstant::HTTP_CERT_TYPE_PEM = "PEM";
const char *const HttpConstant::HTTP_CERT_TYPE_DER = "DER";
const char *const HttpConstant::HTTP_CERT_TYPE_P12 = "P12";

const char *const HttpConstant::TLS_VERSION_1_0 = "TLS_V_1_0";
const char *const HttpConstant::TLS_VERSION_1_1 = "TLS_V_1_1";
const char *const HttpConstant::TLS_VERSION_1_2 = "TLS_V_1_2";
const char *const HttpConstant::TLS_VERSION_1_3 = "TLS_V_1_3";

const char *const HttpConstant::HTTP_PROXY_EXCLUSIONS_SEPARATOR = ",";

const char *const HttpConstant::RESPONSE_KEY_RESULT = "result";
const char *const HttpConstant::RESPONSE_KEY_RESPONSE_CODE = "responseCode";
const char *const HttpConstant::RESPONSE_KEY_HEADER = "header";
const char *const HttpConstant::RESPONSE_KEY_COOKIES = "cookies";
const char *const HttpConstant::RESPONSE_KEY_RESULT_TYPE = "resultType";
const char *const HttpConstant::RESPONSE_KEY_SET_COOKIE = "set-cookie";
const char *const HttpConstant::RESPONSE_KEY_SET_COOKIE_SEPARATOR = "\r\n";

const char *const HttpConstant::HTTP_MULTI_FORM_DATA_NAME = "name";
const char *const HttpConstant::HTTP_MULTI_FORM_DATA_CONTENT_TYPE = "contentType";
const char *const HttpConstant::HTTP_MULTI_FORM_DATA_REMOTE_FILE_NAME = "remoteFileName";
const char *const HttpConstant::HTTP_MULTI_FORM_DATA_DATA = "data";
const char *const HttpConstant::HTTP_MULTI_FORM_DATA_FILE_PATH = "filePath";

const char *const HttpConstant::HTTP_URL_PARAM_START = "?";
const char *const HttpConstant::HTTP_URL_PARAM_SEPARATOR = "&";
const char *const HttpConstant::HTTP_URL_NAME_VALUE_SEPARATOR = "=";
const char *const HttpConstant::HTTP_HEADER_SEPARATOR = ":";
const char *const HttpConstant::HTTP_HEADER_BLANK_SEPARATOR = ";";
const char *const HttpConstant::HTTP_LINE_SEPARATOR = "\r\n";
const char *const HttpConstant::HTTP_RESPONSE_HEADER_SEPARATOR = "\r\n\r\n";

const char *const HttpConstant::HTTP_DEFAULT_USER_AGENT = "libcurl-agent/1.0";

const char *const HttpConstant::HTTP_PREPARE_CA_PATH = "/etc/security/certificates";
const char *const HttpConstant::HTTP_CONTENT_TYPE = "content-type";
const char *const HttpConstant::HTTP_CONTENT_TYPE_URL_ENCODE = "application/x-www-form-urlencoded";
const char *const HttpConstant::HTTP_CONTENT_TYPE_JSON = "application/json";
const char *const HttpConstant::HTTP_CONTENT_TYPE_OCTET_STREAM = "application/octet-stream";
const char *const HttpConstant::HTTP_CONTENT_TYPE_IMAGE = "image";
const char *const HttpConstant::HTTP_CONTENT_TYPE_MULTIPART = "multipart/form-data";

const char *const HttpConstant::HTTP_CONTENT_ENCODING_GZIP = "gzip";

const char *const HttpConstant::REQUEST_TIME = "requestTime";
const char *const HttpConstant::RESPONSE_TIME = "responseTime";
const char *const HttpConstant::RESPONSE_PERFORMANCE_TIMING = "performanceTiming";
const char *const HttpConstant::RESPONSE_DNS_TIMING = "dnsTiming";
const char *const HttpConstant::RESPONSE_TCP_TIMING = "tcpTiming";
const char *const HttpConstant::RESPONSE_TLS_TIMING = "tlsTiming";
const char *const HttpConstant::RESPONSE_FIRST_SEND_TIMING = "firstSendTiming";
const char *const HttpConstant::RESPONSE_FIRST_RECEIVE_TIMING = "firstReceiveTiming";
const char *const HttpConstant::RESPONSE_TOTAL_FINISH_TIMING = "totalFinishTiming";
const char *const HttpConstant::RESPONSE_REDIRECT_TIMING = "redirectTiming";
const char *const HttpConstant::RESPONSE_HEADER_TIMING = "responseHeaderTiming";
const char *const HttpConstant::RESPONSE_BODY_TIMING = "responseBodyTiming";
const char *const HttpConstant::RESPONSE_TOTAL_TIMING = "totalTiming";

const char *const HttpConstant::PARAM_KEY_ADDRESS_FAMILY = "addressFamily";
const char *const HttpConstant::HTTP_ADDRESS_FAMILY_UNSPEC = "DEFAULT";
const char *const HttpConstant::HTTP_ADDRESS_FAMILY_ONLYV4 = "ONLY_V4";
const char *const HttpConstant::HTTP_ADDRESS_FAMILY_ONLYV6 = "ONLY_V6";

const char *const HttpConstant::SSL_TYPE_TLCP = "sslType";
const char *const HttpConstant::PARAM_KEY_CLIENT_ENC_CERT = "clientEncCert";

const char *const HttpConstant::INTERCEPTOR_INITIAL_REQUEST = "INITIAL_REQUEST";
const char *const HttpConstant::INTERCEPTOR_REDIRECTION = "REDIRECTION";
const char *const HttpConstant::INTERCEPTOR_CACHE_CHECKED = "CACHE_CHECKED";
const char *const HttpConstant::INTERCEPTOR_READ_CACHE = "READ_CACHE";
const char *const HttpConstant::INTERCEPTOR_NETWORK_CONNECT = "NETWORK_CONNECT";
const char *const HttpConstant::INTERCEPTOR_CONNECT_NETWORK = "CONNECT_NETWORK";
const char *const HttpConstant::INTERCEPTOR_FINAL_RESPONSE = "FINAL_RESPONSE";
const char *const HttpConstant::INTERCEPTOR_TYPE = "InterceptorType";
} // namespace OHOS::NetStack::Http
