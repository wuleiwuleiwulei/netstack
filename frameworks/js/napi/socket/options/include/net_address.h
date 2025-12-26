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

#ifndef COMMUNICATIONNETSTACK_NET_ADDRESS_H
#define COMMUNICATIONNETSTACK_NET_ADDRESS_H

#include <arpa/inet.h>
#include <string>

namespace OHOS::NetStack::Socket {
class NetAddress final {
public:
    enum class Family : uint32_t {
        IPv4 = 1,
        IPv6 = 2,
        DOMAIN_NAME = 3,
    };

    NetAddress();

    NetAddress(const NetAddress &other);

    ~NetAddress() = default;

    void SetRawAddress(const std::string &address);

    void SetIpAddress(const std::string &address);

    void SetAddress(const std::string &address);

    void SetAddress(const std::string &address, bool resolveDns);

    void SetFamilyByJsValue(uint32_t family);

    void SetFamilyBySaFamily(sa_family_t family);

    void SetPort(uint16_t port);

    [[nodiscard]] const std::string &GetAddress() const;

    [[nodiscard]] uint32_t GetJsValueFamily() const;

    [[nodiscard]] sa_family_t GetSaFamily() const;

    [[nodiscard]] uint16_t GetPort() const;

    [[nodiscard]] Family GetFamily() const;

    NetAddress &operator=(const NetAddress &other);

private:
    void SetIpAddressInner(const std::string &address);

    std::string address_;

    Family family_;

    uint16_t port_;
};
} // namespace OHOS::NetStack::Socket

#endif /* COMMUNICATIONNETSTACK_NET_ADDRESS_H */
