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

use synapse::tree_cache::TreeCache;
use test::Bencher;

extern crate test;

#[bench]
fn bench_tree_cache_get_non_empty(b: &mut Bencher) {
    let mut cache: TreeCache<&str, &str> = TreeCache::new();

    cache.set(["a", "b", "c", "d"], "f").unwrap();

    b.iter(|| cache.get(&["a", "b", "c", "d"]));
}

#[bench]
fn bench_tree_cache_get_empty(b: &mut Bencher) {
    let cache: TreeCache<&str, &str> = TreeCache::new();

    b.iter(|| cache.get(&["a", "b", "c", "d"]));
}

#[bench]
fn bench_tree_cache_set(b: &mut Bencher) {
    let mut cache: TreeCache<&str, &str> = TreeCache::new();

    b.iter(|| cache.set(["a", "b", "c", "d"], "f").unwrap());
}

#[bench]
fn bench_tree_cache_length(b: &mut Bencher) {
    let mut cache: TreeCache<u32, u32> = TreeCache::new();

    for c1 in 0..=10 {
        for c2 in 0..=10 {
            for c3 in 0..=10 {
                for c4 in 0..=10 {
                    cache.set([c1, c2, c3, c4], 1).unwrap()
                }
            }
        }
    }

    b.iter(|| cache.len());
}

#[bench]
fn tree_cache_iterate(b: &mut Bencher) {
    let mut cache: TreeCache<u32, u32> = TreeCache::new();

    for c1 in 0..=10 {
        for c2 in 0..=10 {
            for c3 in 0..=10 {
                for c4 in 0..=10 {
                    cache.set([c1, c2, c3, c4], 1).unwrap()
                }
            }
        }
    }

    b.iter(|| cache.items().count());
}
