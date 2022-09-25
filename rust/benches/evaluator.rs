#![feature(test)]
use synapse::push::{
    evaluator::PushRuleEvaluator, Condition, EventMatchCondition, FilteredPushRules, PushRules,
};
use test::Bencher;

extern crate test;

#[bench]
fn bench_match_exact(b: &mut Bencher) {
    let flattened_keys = [
        ("type".to_string(), "m.text".to_string()),
        ("room_id".to_string(), "!room:server".to_string()),
        ("content.body".to_string(), "test message".to_string()),
    ]
    .into_iter()
    .collect();

    let eval = PushRuleEvaluator::py_new(
        flattened_keys,
        10,
        0,
        Default::default(),
        Default::default(),
        true,
    )
    .unwrap();

    let condition = Condition::Known(synapse::push::KnownCondition::EventMatch(
        EventMatchCondition {
            key: "room_id".into(),
            pattern: Some("!room:server".into()),
            pattern_type: None,
        },
    ));

    let matched = eval.match_condition(&condition, None, None).unwrap();
    assert!(matched, "Didn't match");

    b.iter(|| eval.match_condition(&condition, None, None).unwrap());
}

#[bench]
fn bench_match_word(b: &mut Bencher) {
    let flattened_keys = [
        ("type".to_string(), "m.text".to_string()),
        ("room_id".to_string(), "!room:server".to_string()),
        ("content.body".to_string(), "test message".to_string()),
    ]
    .into_iter()
    .collect();

    let eval = PushRuleEvaluator::py_new(
        flattened_keys,
        10,
        0,
        Default::default(),
        Default::default(),
        true,
    )
    .unwrap();

    let condition = Condition::Known(synapse::push::KnownCondition::EventMatch(
        EventMatchCondition {
            key: "content.body".into(),
            pattern: Some("test".into()),
            pattern_type: None,
        },
    ));

    let matched = eval.match_condition(&condition, None, None).unwrap();
    assert!(matched, "Didn't match");

    b.iter(|| eval.match_condition(&condition, None, None).unwrap());
}

#[bench]
fn bench_match_word_miss(b: &mut Bencher) {
    let flattened_keys = [
        ("type".to_string(), "m.text".to_string()),
        ("room_id".to_string(), "!room:server".to_string()),
        ("content.body".to_string(), "test message".to_string()),
    ]
    .into_iter()
    .collect();

    let eval = PushRuleEvaluator::py_new(
        flattened_keys,
        10,
        0,
        Default::default(),
        Default::default(),
        true,
    )
    .unwrap();

    let condition = Condition::Known(synapse::push::KnownCondition::EventMatch(
        EventMatchCondition {
            key: "content.body".into(),
            pattern: Some("foobar".into()),
            pattern_type: None,
        },
    ));

    let matched = eval.match_condition(&condition, None, None).unwrap();
    assert!(!matched, "Didn't match");

    b.iter(|| eval.match_condition(&condition, None, None).unwrap());
}

#[bench]
fn bench_eval_message(b: &mut Bencher) {
    let flattened_keys = [
        ("type".to_string(), "m.text".to_string()),
        ("room_id".to_string(), "!room:server".to_string()),
        ("content.body".to_string(), "test message".to_string()),
    ]
    .into_iter()
    .collect();

    let eval = PushRuleEvaluator::py_new(
        flattened_keys,
        10,
        0,
        Default::default(),
        Default::default(),
        true,
    )
    .unwrap();

    let rules =
        FilteredPushRules::py_new(PushRules::new(Vec::new()), Default::default(), false, false);

    b.iter(|| eval.run(&rules, Some("bob"), Some("person")));
}
