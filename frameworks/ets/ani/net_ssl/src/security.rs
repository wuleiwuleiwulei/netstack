// Copyright (C) 2025 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use ani_rs::business_error::BusinessError;

use crate::{
    bridge::CertBlob,
    wrapper::{convert_to_business_error, NetworkSecurityClient},
};

#[ani_rs::native]
pub fn is_cleartext_permitted() -> Result<bool, BusinessError> {
    NetworkSecurityClient::is_cleartext_permitted()
        .map_err(|e| {
            BusinessError::new(
                e,
                "NetworkSecurityClient::is_cleartext_permitted failed".to_string(),
            )
        })
        .map(|result| result)
}

#[ani_rs::native]
pub fn is_cleartext_permitted_by_host_name(host_name: String) -> Result<bool, BusinessError> {
    NetworkSecurityClient::is_cleartext_permitted_by_host_name(host_name)
        .map_err(|e| {
            BusinessError::new(
                e,
                "NetworkSecurityClient::is_cleartext_permitted_by_host_name failed".to_string(),
            )
        })
        .map(|result| result)
}

#[ani_rs::native]
pub fn cert_verification_async(
    cert: CertBlob,
    ca_cert: Option<CertBlob>,
) -> Result<i32, BusinessError> {
    let mut res = NetworkSecurityClient::cert_verification(cert, ca_cert);
    if res == 0 {
        Ok(res)
    } else {
        Err(convert_to_business_error(&mut res))
    }
}

#[ani_rs::native]
pub fn cert_verification_sync(
    cert: CertBlob,
    ca_cert: Option<CertBlob>,
) -> Result<i32, BusinessError> {
    let mut res = NetworkSecurityClient::cert_verification(cert, ca_cert);
    let _ = convert_to_business_error(&mut res);
    Ok(res)
}
