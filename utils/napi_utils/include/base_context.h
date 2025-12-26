/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_BASE_CONTEXT_H
#define COMMUNICATIONNETSTACK_BASE_CONTEXT_H

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <string>
#include <utility>

#include <napi/native_api.h>
#include <napi/native_common.h>

#include "event_manager.h"
#include "node_api_types.h"

namespace OHOS::NetStack {
typedef void (*AsyncWorkExecutor)(napi_env env, void *data);
typedef void (*AsyncWorkCallback)(napi_env env, napi_status status, void *data);
static constexpr size_t PERMISSION_DENIED_CODE = 201;
static constexpr const char *PERMISSION_DENIED_MSG = "Permission denied";
static constexpr size_t PARSE_ERROR_CODE = 401;
static constexpr const char *PARSE_ERROR_MSG = "Parameter error";
static constexpr int32_t SOCKS5_ERROR_CODE = 205;

class BaseContext {
public:
    BaseContext() = delete;

    BaseContext(napi_env env, const std::shared_ptr<EventManager> &sharedManager);

    virtual ~BaseContext();

    void SetParseOK(bool parseOK);

    void SetExecOK(bool requestOK);

    void SetErrorCode(int32_t errorCode);

    void SetError(int32_t errorCode, const std::string &errorMessage);

    napi_status SetCallback(napi_value callback);

    void DeleteCallback();

    void CreateAsyncWork(const std::string &name, AsyncWorkExecutor executor, AsyncWorkCallback callback);

    void DeleteAsyncWork();

    napi_value CreatePromise();

    void DeletePromise();

    [[nodiscard]] bool IsParseOK() const;

    [[nodiscard]] bool IsExecOK() const;

    [[nodiscard]] napi_env GetEnv() const;

    [[nodiscard]] virtual int32_t GetErrorCode() const;

    [[nodiscard]] virtual std::string GetErrorMessage() const;

    [[nodiscard]] napi_value GetCallback() const;

    [[nodiscard]] napi_deferred GetDeferred() const;

    [[nodiscard]] const std::string &GetAsyncWorkName() const;

    void EmitSharedManager(const std::string &type, const std::pair<napi_value, napi_value> &argv);

    void SetNeedPromise(bool needPromise);

    [[nodiscard]] bool IsNeedPromise() const;

    void SetNeedThrowException(bool needThrowException);

    [[nodiscard]] bool IsNeedThrowException() const;

    void SetPermissionDenied(bool needThrowException);

    [[nodiscard]] bool IsPermissionDenied() const;

    void SetNoAllowedHost(bool needThrowException);

    void SetCleartextNotPermitted(bool notPermitted);

    [[nodiscard]] bool IsNoAllowedHost() const;

    [[nodiscard]] bool IsCleartextNotPermitted() const;

    [[nodiscard]] std::shared_ptr<EventManager> GetSharedManager() const;

    void SetSharedManager(const std::shared_ptr<EventManager> &sharedManager);

    void CreateReference(napi_value value);

    void DeleteReference();

    napi_async_work GetAsyncWork();

    virtual void ParseParams(napi_value *params, size_t paramsCount);

    napi_deferred deferredBack1_ = nullptr;
    napi_deferred deferredBack2_ = nullptr;
    napi_deferred deferredBack3_ = nullptr;
    napi_deferred deferredBack4_ = nullptr;
    napi_async_work asyncWorkBack1_ = nullptr;
    napi_async_work asyncWorkBack2_ = nullptr;
    napi_async_work asyncWorkBack3_ = nullptr;
    napi_async_work asyncWorkBack4_ = nullptr;

private:
    napi_env env_ = nullptr;

    napi_ref ref_ = nullptr;

    bool parseOK_;

    bool requestOK_;

    int32_t errorCode_;

    napi_ref callback_ = nullptr;

    napi_ref promiseRef_ = nullptr;

    napi_async_work asyncWork_ = nullptr;

    napi_deferred deferred_ = nullptr;

    bool needPromise_;

    bool needThrowException_;

    bool permissionDenied_;

    bool noAllowedHost_;

    bool cleartextNotPermitted_;

    std::string asyncWorkName_;

    std::string errorMessage_;

protected:
    std::shared_ptr<EventManager> sharedManager_;

private:
    napi_ref callbackBak1_ = nullptr;
    napi_ref callbackBak2_ = nullptr;
    napi_ref callbackBak3_ = nullptr;
    napi_ref callbackBak4_ = nullptr;
};
} // namespace OHOS::NetStack

#endif /* COMMUNICATIONNETSTACK_BASE_CONTEXT_H */
