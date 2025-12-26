/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

//! Implementation of some tool functions.

use std::cell::Cell;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::num::Wrapping;

// XORShift* fast-random realization.
pub(crate) fn xor_shift() -> u64 {
    thread_local! {
        static RNG: Cell<Wrapping<u64>> = Cell::new(Wrapping(seed()));
    }

    // The returned value of `seed()` must be nonzero.
    fn seed() -> u64 {
        let seed = RandomState::new();

        let mut out;
        let mut cnt = 1;
        let mut hasher = seed.build_hasher();

        loop {
            hasher.write_usize(cnt);
            out = hasher.finish();
            if out != 0 {
                break;
            }
            cnt += 1;
            hasher = seed.build_hasher();
        }
        out
    }

    RNG.with(|rng| {
        let mut n = rng.get();
        n ^= n >> 12;
        n ^= n << 25;
        n ^= n >> 27;
        rng.set(n);
        n.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    })
}
