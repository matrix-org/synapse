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
