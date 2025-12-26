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

#ifndef COMMUNICATIONNETSTACK_NET_SSL_TYPE_H
#define COMMUNICATIONNETSTACK_NET_SSL_TYPE_H

namespace OHOS {
namespace NetStack {
namespace Ssl {
enum CertType {
    /** PEM certificate type */
    CERT_TYPE_PEM = 0,
    /** DER certificate type */
    CERT_TYPE_DER = 1,
    /** error certificate type */
    CERT_TYPE_MAX
};

struct CertBlob {
    /** certificate type */
    CertType type;
    /** certificate size */
    uint32_t size;
    /** certificate data */
    uint8_t *data;
};
} // namespace Ssl
} // namespace NetStack
} // namespace OHOS
#endif // COMMUNICATIONNETSTACK_NET_SSL_TYPE_H
