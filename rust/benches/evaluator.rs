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

use std::borrow::Cow;

use synapse::push::{
    evaluator::PushRuleEvaluator, Condition, EventMatchCondition, FilteredPushRules, JsonValue,
    PushRules, SimpleJsonValue,
};
use test::Bencher;

extern crate test;

#[bench]
fn bench_match_exact(b: &mut Bencher) {
    let flattened_keys = [
        (
            "type".to_string(),
            JsonValue::Value(SimpleJsonValue::Str(Cow::Borrowed("m.text"))),
        ),
        (
            "room_id".to_string(),
            JsonValue::Value(SimpleJsonValue::Str(Cow::Borrowed("!room:server"))),
        ),
        (
            "content.body".to_string(),
            JsonValue::Value(SimpleJsonValue::Str(Cow::Borrowed("test message"))),
        ),
    ]
    .into_iter()
    .collect();

    let eval = PushRuleEvaluator::py_new(
        flattened_keys,
        false,
        10,
        Some(0),
        Default::default(),
        Default::default(),
        true,
        vec![],
        false,
    )
    .unwrap();

    let condition = Condition::Known(synapse::push::KnownCondition::EventMatch(
        EventMatchCondition {
            key: "room_id".into(),
            pattern: "!room:server".into(),
        },
    ));

    let matched = eval.match_condition(&condition, None, None).unwrap();
    assert!(matched, "Didn't match");

    b.iter(|| eval.match_condition(&condition, None, None).unwrap());
}

#[bench]
fn bench_match_word(b: &mut Bencher) {
    let flattened_keys = [
        (
            "type".to_string(),
            JsonValue::Value(SimpleJsonValue::Str(Cow::Borrowed("m.text"))),
        ),
        (
            "room_id".to_string(),
            JsonValue::Value(SimpleJsonValue::Str(Cow::Borrowed("!room:server"))),
        ),
        (
            "content.body".to_string(),
            JsonValue::Value(SimpleJsonValue::Str(Cow::Borrowed("test message"))),
        ),
    ]
    .into_iter()
    .collect();

    let eval = PushRuleEvaluator::py_new(
        flattened_keys,
        false,
        10,
        Some(0),
        Default::default(),
        Default::default(),
        true,
        vec![],
        false,
    )
    .unwrap();

    let condition = Condition::Known(synapse::push::KnownCondition::EventMatch(
        EventMatchCondition {
            key: "content.body".into(),
            pattern: "test".into(),
        },
    ));

    let matched = eval.match_condition(&condition, None, None).unwrap();
    assert!(matched, "Didn't match");

    b.iter(|| eval.match_condition(&condition, None, None).unwrap());
}

#[bench]
fn bench_match_word_miss(b: &mut Bencher) {
    let flattened_keys = [
        (
            "type".to_string(),
            JsonValue::Value(SimpleJsonValue::Str(Cow::Borrowed("m.text"))),
        ),
        (
            "room_id".to_string(),
            JsonValue::Value(SimpleJsonValue::Str(Cow::Borrowed("!room:server"))),
        ),
        (
            "content.body".to_string(),
            JsonValue::Value(SimpleJsonValue::Str(Cow::Borrowed("test message"))),
        ),
    ]
    .into_iter()
    .collect();

    let eval = PushRuleEvaluator::py_new(
        flattened_keys,
        false,
        10,
        Some(0),
        Default::default(),
        Default::default(),
        true,
        vec![],
        false,
    )
    .unwrap();

    let condition = Condition::Known(synapse::push::KnownCondition::EventMatch(
        EventMatchCondition {
            key: "content.body".into(),
            pattern: "foobar".into(),
        },
    ));

    let matched = eval.match_condition(&condition, None, None).unwrap();
    assert!(!matched, "Didn't match");

    b.iter(|| eval.match_condition(&condition, None, None).unwrap());
}

#[bench]
fn bench_eval_message(b: &mut Bencher) {
    let flattened_keys = [
        (
            "type".to_string(),
            JsonValue::Value(SimpleJsonValue::Str(Cow::Borrowed("m.text"))),
        ),
        (
            "room_id".to_string(),
            JsonValue::Value(SimpleJsonValue::Str(Cow::Borrowed("!room:server"))),
        ),
        (
            "content.body".to_string(),
            JsonValue::Value(SimpleJsonValue::Str(Cow::Borrowed("test message"))),
        ),
    ]
    .into_iter()
    .collect();

    let eval = PushRuleEvaluator::py_new(
        flattened_keys,
        false,
        10,
        Some(0),
        Default::default(),
        Default::default(),
        true,
        vec![],
        false,
    )
    .unwrap();

    let rules = FilteredPushRules::py_new(
        PushRules::new(Vec::new()),
        Default::default(),
        false,
        false,
        false,
        false,
    );

    b.iter(|| eval.run(&rules, Some("bob"), Some("person")));
}
