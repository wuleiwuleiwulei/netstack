/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_HTTP_MODULE_H
#define COMMUNICATIONNETSTACK_HTTP_MODULE_H

#include <string>
#include <vector>
#include "napi/native_api.h"

namespace OHOS::NetStack::Http {
class HttpModuleExports {
public:
    class HttpResponseCache {
    public:
        static constexpr const char *FUNCTION_FLUSH = "flush";
        static constexpr const char *FUNCTION_DELETE = "delete";

        static napi_value Flush(napi_env env, napi_callback_info info);
        static napi_value Delete(napi_env env, napi_callback_info info);
    };

    class HttpRequest {
    public:
        static constexpr const char *FUNCTION_REQUEST = "request";
        static constexpr const char *FUNCTION_REQUEST_IN_STREAM = "requestInStream";
        static constexpr const char *FUNCTION_DESTROY = "destroy";
        static constexpr const char *FUNCTION_ON = "on";
        static constexpr const char *FUNCTION_ONCE = "once";
        static constexpr const char *FUNCTION_OFF = "off";

        static napi_value Request(napi_env env, napi_callback_info info);
        static napi_value RequestInStream(napi_env env, napi_callback_info info);
        static napi_value Destroy(napi_env env, napi_callback_info info);
        static napi_value On(napi_env env, napi_callback_info info);
        static napi_value Once(napi_env env, napi_callback_info info);
        static napi_value Off(napi_env env, napi_callback_info info);
    };

    class HttpInterceptor {
    public:
        napi_env napi_env_ = nullptr;
        std::string interceptorType_;
        napi_ref interceptorRef_ = nullptr;

        HttpInterceptor(napi_env env, const std::string &type, napi_value interceptorInstance)
            : napi_env_(env), interceptorType_(type)
        {
            napi_create_reference(env, interceptorInstance, 1, &interceptorRef_);
        }

        ~HttpInterceptor()
        {
            if (interceptorRef_ != nullptr) {
                napi_delete_reference(napi_env_, interceptorRef_);
            }
        }
        napi_value GetInstance(napi_env env) const
        {
            napi_value instance;
            napi_get_reference_value(env, interceptorRef_, &instance);
            return instance;
        }
    };

    class HttpInterceptorChain {
    public:
        std::vector<HttpInterceptor *> chain_;
        napi_env env_ = nullptr;
        HttpInterceptorChain(napi_env env) : env_(env) { }
        ~HttpInterceptorChain()
        {
            for (auto *interceptor : chain_) {
                delete interceptor;
            }
        }

        static constexpr const char *FUNCTION_GETCHAIN = "getChain";
        static constexpr const char *FUNCTION_ADDCHAIN = "addChain";
        static constexpr const char *FUNCTION_APPLY = "apply";

        static napi_value GetChain(napi_env env, napi_callback_info info);
        static napi_value AddChain(napi_env env, napi_callback_info info);
        static napi_value Apply(napi_env env, napi_callback_info info);
    };

    static constexpr const char *FUNCTION_CREATE_HTTP = "createHttp";
    static constexpr const char *FUNCTION_CREATE_HTTP_RESPONSE_CACHE = "createHttpResponseCache";
    static constexpr const char *INTERFACE_REQUEST_METHOD = "RequestMethod";
    static constexpr const char *INTERFACE_RESPONSE_CODE = "ResponseCode";
    static constexpr const char *INTERFACE_HTTP_REQUEST = "OHOS_NET_HTTP_HttpRequest";
    static constexpr const char *INTERFACE_HTTP_PROTOCOL = "HttpProtocol";
    static constexpr const char *INTERFACE_CERT_TYPE = "CertType";
    static constexpr const char *INTERFACE_HTTP_RESPONSE_CACHE = "OHOS_NET_HTTP_HttpResponseCache";
    static constexpr const char *INTERFACE_HTTP_DATA_TYPE = "HttpDataType";
    static constexpr const char *INTERFACE_TLS_VERSION = "TlsVersion";
    static constexpr const char *INTERFACE_ADDRESS_FAMILY = "AddressFamily";
    static constexpr const char *INTERFACE_SSL_TYPE = "SslType";
    static constexpr const char *INTERFACE_CLIENT_ENC_CERT = "CertType";
    static constexpr const char *INTERFACE_HTTP_INTERCEPTOR_CHAIN = "HttpInterceptorChain";

    static napi_value InitHttpModule(napi_env env, napi_value exports);

private:
    static napi_value CreateHttp(napi_env env, napi_callback_info info);

    static napi_value CreateHttpResponseCache(napi_env env, napi_callback_info info);

    static void DefineHttpRequestClass(napi_env env, napi_value exports);

    static void DefineHttpResponseCacheClass(napi_env env, napi_value exports);

    static void DefineHttpInterceptorChainClass(napi_env env, napi_value exports);

    static void InitHttpProperties(napi_env env, napi_value exports);

    static void InitRequestMethod(napi_env env, napi_value exports);

    static void InitResponseCode(napi_env env, napi_value exports);

    static void InitTlsVersion(napi_env env, napi_value exports);

    static void InitHttpProtocol(napi_env env, napi_value exports);

    static void InitCertType(napi_env env, napi_value exports);

    static void InitHttpDataType(napi_env env, napi_value exports);

    static void InitAddressFamily(napi_env env, napi_value exports);

    static void InitSslType(napi_env env, napi_value exports);

    static void InitClientEncCert(napi_env env, napi_value exports);
};
} // namespace OHOS::NetStack::Http
#endif // COMMUNICATIONNETSTACK_HTTP_MODULE_H