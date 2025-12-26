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
use cxx::let_cxx_string;

use crate::bridge::{self, CertBlob};

pub struct NetworkSecurityClient;
impl NetworkSecurityClient {
    pub fn is_cleartext_permitted() -> Result<bool, i32> {
        let mut is_permitted = false;
        let ret = ffi::IsCleartextPermitted(&mut is_permitted);
        if ret != 0 {
            return Err(ret);
        }
        Ok(is_permitted)
    }

    pub fn is_cleartext_permitted_by_host_name(host_name: String) -> Result<bool, i32> {
        let mut is_permitted = false;
        let_cxx_string!(host_name = host_name);
        let ret = ffi::IsCleartextPermittedByHostName(&host_name, &mut is_permitted);
        if ret != 0 {
            return Err(ret);
        }
        Ok(is_permitted)
    }

    pub fn cert_verification(cert: CertBlob, ca_cert: Option<CertBlob>) -> i32 {
        let ret = if let Some(ca_cert) = ca_cert {
            ffi::NetStackVerifyCertificationCa(&cert.into(), &ca_cert.into())
        } else {
            ffi::NetStackVerifyCertification(&cert.into())
        };
        ret as i32
    }
}

impl From<bridge::CertBlob> for ffi::CertBlob {
    fn from(cert_blob: bridge::CertBlob) -> Self {
        let data = match cert_blob.data {
            bridge::Data::S(s) => s.into_bytes(),
            bridge::Data::ArrayBuffer(a) => a.to_vec(),
        };

        ffi::CertBlob {
            cert_type: cert_blob.type_.into(),
            data,
        }
    }
}

impl From<bridge::CertType> for ffi::CertType {
    fn from(cert_type: bridge::CertType) -> Self {
        match cert_type {
            bridge::CertType::CertTypePem => ffi::CertType::CERT_TYPE_PEM,
            bridge::CertType::CertTypeDer => ffi::CertType::CERT_TYPE_DER,
        }
    }
}

#[cxx::bridge(namespace = "OHOS::NetStackAni")]
mod ffi {
    #[namespace = "OHOS::NetStack::Ssl"]
    #[repr(i32)]
    enum CertType {
        CERT_TYPE_PEM = 0,
        CERT_TYPE_DER = 1,
        CERT_TYPE_MAX,
    }

    struct CertBlob {
        cert_type: CertType,
        data: Vec<u8>,
    }

    unsafe extern "C++" {
        include!("network_security_ani.h");
        #[namespace = "OHOS::NetStack::Ssl"]
        type CertType;

        fn IsCleartextPermitted(is_permitted: &mut bool) -> i32;

        fn IsCleartextPermittedByHostName(host_name: &CxxString, is_permitted: &mut bool) -> i32;

        fn NetStackVerifyCertificationCa(cert: &CertBlob, ca_cert: &CertBlob) -> u32;

        fn NetStackVerifyCertification(cert: &CertBlob) -> u32;

        fn GetErrorCodeAndMessage(error_code: &mut i32) -> String;

    }
}

pub fn convert_to_business_error(code: &mut i32) -> BusinessError {
    let error_msg = crate::wrapper::ffi::GetErrorCodeAndMessage(code);
    BusinessError::new(*code, error_msg)
}
