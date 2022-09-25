// Copyright 2022 The Matrix.org Foundation C.I.C.
//
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

#![feature(test)]

use synapse::push::utils::{glob_to_regex, GlobMatchType};
use test::Bencher;

extern crate test;

#[bench]
fn bench_whole(b: &mut Bencher) {
    b.iter(|| glob_to_regex("test", GlobMatchType::Whole));
}

#[bench]
fn bench_word(b: &mut Bencher) {
    b.iter(|| glob_to_regex("test", GlobMatchType::Word));
}

#[bench]
fn bench_whole_wildcard_run(b: &mut Bencher) {
    b.iter(|| glob_to_regex("test***??*?*?foo", GlobMatchType::Whole));
}

#[bench]
fn bench_word_wildcard_run(b: &mut Bencher) {
    b.iter(|| glob_to_regex("test***??*?*?foo", GlobMatchType::Whole));
}
