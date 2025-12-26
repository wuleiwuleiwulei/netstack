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


import type { AsyncCallback } from '@ohos.base';
import { BusinessError }  from '@ohos.base';

export default namespace networkSecurity {
  loadLibrary("network_security_ani")

  export enum CertType {
    CERT_TYPE_PEM = 0,
    CERT_TYPE_DER = 1
  }

  export interface CertBlob {
    type: CertType;

    data: string | ArrayBuffer;
  }

  export function certVerification(cert: CertBlob, caCert?: CertBlob): Promise<int> {
    return new Promise<int>((resolve, reject) => {
          taskpool.execute((): int => {
              return certVerificationAsync(cert, caCert);
          }).then((content: Any) => {
              resolve(content as int);
          }, (err: Error): void => {
              reject(err as BusinessError);
          });
      });
  }

  export native function certVerificationAsync(cert: CertBlob, caCert?: CertBlob): int;

  export native function certVerificationSync(cert: CertBlob, caCert?: CertBlob): int;

  export native function isCleartextPermitted(): boolean;

  export native function isCleartextPermittedByHostName(hostName: string): boolean;
}
