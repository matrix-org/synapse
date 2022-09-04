use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use anyhow::{Context, Error};
use lazy_static::lazy_static;
use log::{debug, info};
use pyo3::prelude::*;
use pythonize::pythonize;
use regex::Regex;
use serde::de::Error as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

lazy_static! {
    static ref INEQUALITY_EXPR: Regex = Regex::new(r"^([=<>]*)([0-9]*)$").expect("valid regex");
}

pub fn register_module(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    let child_module = PyModule::new(py, "push")?;
    child_module.add_class::<PushRule>()?;
    child_module.add_class::<PushRules>()?;
    child_module.add_class::<PushRuleEvaluator>()?;
    child_module.add_class::<FilteredPushRules>()?;
    m.add_submodule(child_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("synapse.synapse_rust.push", child_module)?;

    Ok(())
}

#[derive(Debug, Clone)]
#[pyclass(frozen)]
pub struct PushRule {
    pub rule_id: Cow<'static, str>,
    #[pyo3(get)]
    pub priority_class: i32,
    pub conditions: Cow<'static, [Condition]>,
    pub actions: Cow<'static, [Action]>,
    #[pyo3(get)]
    pub default: bool,
    #[pyo3(get)]
    pub default_enabled: bool,
}

#[pymethods]
impl PushRule {
    #[staticmethod]
    pub fn from_db(
        rule_id: String,
        priority_class: i32,
        conditions: &str,
        actions: &str,
    ) -> Result<PushRule, Error> {
        let conditions = serde_json::from_str(conditions).context("parsing conditions")?;
        let actions = serde_json::from_str(actions).context("parsing actions")?;

        Ok(PushRule {
            rule_id: Cow::Owned(rule_id),
            priority_class,
            conditions,
            actions,
            default: false,
            default_enabled: true,
        })
    }

    #[getter]
    fn rule_id(&self) -> &str {
        &self.rule_id
    }

    #[getter]
    fn actions(&self) -> Vec<Action> {
        self.actions.clone().into_owned()
    }

    #[getter]
    fn conditions(&self) -> Vec<Condition> {
        self.conditions.clone().into_owned()
    }

    fn __repr__(&self) -> String {
        format!(
            "<PushRule rule_id={}, conditions={:?}, actions={:?}>",
            self.rule_id, self.conditions, self.actions
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    DontNotify,
    Notify,
    Coalesce,
    SetTweak(SetTweak),
}

impl IntoPy<PyObject> for Action {
    fn into_py(self, py: Python<'_>) -> PyObject {
        pythonize(py, &self).expect("valid action")
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SetTweak {
    set_tweak: Cow<'static, str>,
    value: Option<TweakValue>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum TweakValue {
    String(Cow<'static, str>),
    Other(Value),
}

impl Serialize for Action {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Action::DontNotify => serializer.serialize_str("dont_notify"),
            Action::Notify => serializer.serialize_str("notify"),
            Action::Coalesce => serializer.serialize_str("coalesce"),
            Action::SetTweak(tweak) => tweak.serialize(serializer),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ActionDeserializeHelper {
    Str(String),
    SetTweak(SetTweak),
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper: ActionDeserializeHelper = Deserialize::deserialize(deserializer)?;
        match helper {
            ActionDeserializeHelper::Str(s) => match &*s {
                "dont_notify" => Ok(Action::DontNotify),
                "notify" => Ok(Action::Notify),
                "coalesce" => Ok(Action::Coalesce),
                _ => Err(D::Error::custom("unrecognized action")),
            },
            ActionDeserializeHelper::SetTweak(set_tweak) => Ok(Action::SetTweak(set_tweak)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "kind")]
pub enum Condition {
    EventMatch(EventMatchCondition),
    ContainsDisplayName,
    RoomMemberCount {
        #[serde(skip_serializing_if = "Option::is_none")]
        is: Option<Cow<'static, str>>,
    },
    SenderNotificationPermission {
        key: Cow<'static, str>,
    },
    #[serde(rename = "org.matrix.msc3772.relation_match")]
    RelationMatch,
}

impl IntoPy<PyObject> for Condition {
    fn into_py(self, py: Python<'_>) -> PyObject {
        pythonize(py, &self).expect("valid condition")
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EventMatchCondition {
    key: Cow<'static, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<Cow<'static, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern_type: Option<Cow<'static, str>>,
}

#[derive(Debug, Clone, Default)]
#[pyclass(frozen)]
struct PushRules {
    overridden_base_rules: HashMap<Cow<'static, str>, PushRule>,

    override_rules: Vec<PushRule>,
    content: Vec<PushRule>,
    room: Vec<PushRule>,
    sender: Vec<PushRule>,
    underride: Vec<PushRule>,
}

#[pymethods]
impl PushRules {
    #[new]
    fn new(rules: Vec<PushRule>) -> PushRules {
        let mut push_rules: PushRules = Default::default();

        for rule in rules {
            if let Some(o) = BASE_RULES_BY_ID.get(&*rule.rule_id) {
                push_rules.overridden_base_rules.insert(
                    rule.rule_id.clone(),
                    PushRule {
                        actions: o.actions.clone(),
                        ..rule
                    },
                );

                continue;
            }

            match rule.priority_class {
                5 => push_rules.override_rules.push(rule),
                4 => push_rules.content.push(rule),
                3 => push_rules.room.push(rule),
                2 => push_rules.sender.push(rule),
                1 => push_rules.underride.push(rule),
                _ => {
                    todo!()
                } // TODO: log
            }
        }

        push_rules
    }

    fn rules(&self) -> Vec<PushRule> {
        self.iter().cloned().collect()
    }
}

impl PushRules {
    pub fn iter(&self) -> impl Iterator<Item = &PushRule> {
        BASE_PREPEND_OVERRIDE_RULES
            .iter()
            .chain(self.override_rules.iter())
            .chain(BASE_APPEND_OVERRIDE_RULES.iter())
            .chain(self.content.iter())
            .chain(BASE_APPEND_CONTENT_RULES.iter())
            .chain(self.room.iter())
            .chain(self.sender.iter())
            .chain(self.underride.iter())
            .chain(BASE_APPEND_UNDERRIDE_RULES.iter())
            .map(|rule| {
                self.overridden_base_rules
                    .get(&*rule.rule_id)
                    .unwrap_or(rule)
            })
    }
}

#[derive(Debug, Clone, Default)]
#[pyclass(frozen)]
pub struct FilteredPushRules {
    push_rules: PushRules,
    enabled_map: BTreeMap<String, bool>,
}

#[pymethods]
impl FilteredPushRules {
    #[new]
    fn py_new(push_rules: PushRules, enabled_map: BTreeMap<String, bool>) -> Self {
        Self {
            push_rules,
            enabled_map,
        }
    }

    fn rules(&self) -> Vec<(PushRule, bool)> {
        self.iter().map(|(r, e)| (r.clone(), e)).collect()
    }
}

impl FilteredPushRules {
    fn iter(&self) -> impl Iterator<Item = (&PushRule, bool)> {
        self.push_rules.iter().map(|r| {
            let enabled = *self
                .enabled_map
                .get(&*r.rule_id)
                .unwrap_or(&r.default_enabled);
            (r, enabled)
        })
    }
}

#[pyclass]
pub struct PushRuleEvaluator {
    flattened_keys: BTreeMap<String, String>,
    split_body: HashSet<String>,
    room_member_count: u64,
    power_levels: BTreeMap<String, BTreeMap<String, u64>>,
    relations: BTreeMap<String, BTreeSet<(String, String)>>,
    relation_match_enabled: bool,
    sender_power_level: u64,
}

#[pymethods]
impl PushRuleEvaluator {
    #[new]
    fn py_new(
        flattened_keys: BTreeMap<String, String>,
        room_member_count: u64,
        sender_power_level: u64,
        power_levels: BTreeMap<String, BTreeMap<String, u64>>,
    ) -> Result<Self, Error> {
        let split_body = flattened_keys
            .get("content.body")
            .map(|s| &**s)
            .unwrap_or_default()
            .split_whitespace()
            .map(|s| s.to_owned())
            .collect();

        // TODO
        let relations = BTreeMap::new();
        let relation_match_enabled = false;

        Ok(PushRuleEvaluator {
            flattened_keys,
            split_body,
            room_member_count,
            power_levels,
            relations,
            relation_match_enabled,
            sender_power_level,
        })
    }

    fn run(
        &self,
        push_rules: &FilteredPushRules,
        user_id: Option<&str>,
        display_name: Option<&str>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        'outer: for (push_rule, enabled) in push_rules.iter() {
            if !enabled {
                continue;
            }

            for condition in push_rule.conditions.iter() {
                if !self.match_condition(condition, user_id, display_name) {
                    continue 'outer;
                }
            }

            actions.extend(
                push_rule
                    .actions
                    .iter()
                    // .filter(|a| **a != Action::DontNotify)
                    .cloned(),
            );

            return actions;
        }

        actions
    }
}

impl PushRuleEvaluator {
    pub fn match_condition(
        &self,
        condition: &Condition,
        user_id: Option<&str>,
        display_name: Option<&str>,
    ) -> bool {
        let result = match condition {
            Condition::EventMatch(event_match) => self
                .match_event_match(event_match, user_id)
                .unwrap_or(false),
            Condition::ContainsDisplayName => {
                if let Some(dn) = display_name {
                    self.split_body.contains(dn)
                } else {
                    false
                }
            }
            Condition::RoomMemberCount { is } => {
                if let Some(is) = is {
                    self.match_member_count(is).unwrap_or(false)
                } else {
                    false
                }
            }
            Condition::SenderNotificationPermission { key } => {
                let required_level = self
                    .power_levels
                    .get("notifications")
                    .and_then(|m| m.get(key.as_ref()))
                    .copied()
                    .unwrap_or(50);

                self.sender_power_level >= required_level
            }
            Condition::RelationMatch => {
                // TODO
                false
            }
        };

        result
    }

    fn match_event_match(
        &self,
        event_match: &EventMatchCondition,
        user_id: Option<&str>,
    ) -> Result<bool, Error> {
        let pattern = if let Some(pattern) = &event_match.pattern {
            pattern
        } else if let Some(pattern_type) = &event_match.pattern_type {
            let user_id = if let Some(user_id) = user_id {
                user_id
            } else {
                return Ok(false);
            };
            match &**pattern_type {
                "user_id" => user_id,
                "user_localpart" => user_id, // TODO
                _ => return Ok(false),
            }
        } else {
            return Ok(false);
        };

        let pattern = pattern.to_ascii_lowercase();

        if event_match.key == "content.body" {
            // TODO: Handle globs
            Ok(self.split_body.contains(&pattern))
        } else if let Some(value) = self.flattened_keys.get(&*event_match.key) {
            // TODO: Handle globs.
            Ok(value.contains(&pattern))
        } else {
            Ok(false)
        }
    }

    fn match_member_count(&self, is: &str) -> Result<bool, Error> {
        let captures = INEQUALITY_EXPR.captures(is).context("bad is clause")?;
        let ineq = captures.get(1).map(|m| m.as_str()).unwrap_or("==");
        let rhs: u64 = captures
            .get(2)
            .context("missing number")?
            .as_str()
            .parse()?;

        let matches = match ineq {
            "" | "==" => self.room_member_count == rhs,
            "<" => self.room_member_count < rhs,
            ">" => self.room_member_count > rhs,
            ">=" => self.room_member_count >= rhs,
            "<=" => self.room_member_count <= rhs,
            _ => false,
        };

        Ok(matches)
    }
}

const HIGHLIGHT_ACTION: Action = Action::SetTweak(SetTweak {
    set_tweak: Cow::Borrowed("highlight"),
    value: None,
});

const HIGHLIGHT_FALSE_ACTION: Action = Action::SetTweak(SetTweak {
    set_tweak: Cow::Borrowed("highlight"),
    value: Some(TweakValue::Other(Value::Bool(false))),
});

const SOUND_ACTION: Action = Action::SetTweak(SetTweak {
    set_tweak: Cow::Borrowed("sound"),
    value: Some(TweakValue::String(Cow::Borrowed("default"))),
});

const RING_ACTION: Action = Action::SetTweak(SetTweak {
    set_tweak: Cow::Borrowed("sound"),
    value: Some(TweakValue::String(Cow::Borrowed("ring"))),
});

pub const BASE_PREPEND_OVERRIDE_RULES: &[PushRule] = &[PushRule {
    rule_id: Cow::Borrowed("global/override/.m.rule.master"),
    priority_class: 5,
    conditions: Cow::Borrowed(&[]),
    actions: Cow::Borrowed(&[Action::DontNotify]),
    default: true,
    default_enabled: false,
}];

pub const BASE_APPEND_OVERRIDE_RULES: &[PushRule] = &[
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.suppress_notices"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[Condition::EventMatch(EventMatchCondition {
            key: Cow::Borrowed("content.msgtype"),
            pattern: Some(Cow::Borrowed("m.notice")),
            pattern_type: None,
        })]),
        actions: Cow::Borrowed(&[Action::DontNotify]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.invite_for_me"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[
            Condition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("m.room.member")),
                pattern_type: None,
            }),
            Condition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("content.membership"),
                pattern: Some(Cow::Borrowed("invite")),
                pattern_type: None,
            }),
            Condition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("state_key"),
                pattern: None,
                pattern_type: Some(Cow::Borrowed("user_id")),
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_FALSE_ACTION, SOUND_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.member_event"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[Condition::EventMatch(EventMatchCondition {
            key: Cow::Borrowed("type"),
            pattern: Some(Cow::Borrowed("m.room.member")),
            pattern_type: None,
        })]),
        actions: Cow::Borrowed(&[Action::DontNotify]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.contains_display_name"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[Condition::ContainsDisplayName]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_ACTION, SOUND_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.roomnotif"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[
            Condition::SenderNotificationPermission {
                key: Cow::Borrowed("room"),
            },
            Condition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("content.body"),
                pattern: Some(Cow::Borrowed("@room")),
                pattern_type: None,
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_ACTION, SOUND_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.tombstone"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[
            Condition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("m.room.tombstone")),
                pattern_type: None,
            }),
            Condition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("state_key"),
                pattern: Some(Cow::Borrowed("")),
                pattern_type: None,
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.reaction"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[Condition::EventMatch(EventMatchCondition {
            key: Cow::Borrowed("type"),
            pattern: Some(Cow::Borrowed("m.reaction")),
            pattern_type: None,
        })]),
        actions: Cow::Borrowed(&[Action::DontNotify]),
        default: true,
        default_enabled: true,
    },
    // TODO: org.matrix.msc3786.rule.room.server_acl
];

pub const BASE_APPEND_CONTENT_RULES: &[PushRule] = &[PushRule {
    rule_id: Cow::Borrowed("global/override/.m.rule.contains_user_name"),
    priority_class: 4,
    conditions: Cow::Borrowed(&[Condition::EventMatch(EventMatchCondition {
        key: Cow::Borrowed("content.body"),
        pattern: None,
        pattern_type: Some(Cow::Borrowed("user_localpart")),
    })]),
    actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_ACTION, SOUND_ACTION]),
    default: true,
    default_enabled: true,
}];

pub const BASE_APPEND_UNDERRIDE_RULES: &[PushRule] = &[
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.call"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[Condition::EventMatch(EventMatchCondition {
            key: Cow::Borrowed("type"),
            pattern: Some(Cow::Borrowed("m.call.invite")),
            pattern_type: None,
        })]),
        actions: Cow::Borrowed(&[Action::Notify, RING_ACTION, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.room_one_to_one"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("m.room.message")),
                pattern_type: None,
            }),
            Condition::RoomMemberCount {
                is: Some(Cow::Borrowed("2")),
            },
        ]),
        actions: Cow::Borrowed(&[Action::Notify, SOUND_ACTION, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.encrypted_room_one_to_one"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("m.room.encrypted")),
                pattern_type: None,
            }),
            Condition::RoomMemberCount {
                is: Some(Cow::Borrowed("2")),
            },
        ]),
        actions: Cow::Borrowed(&[Action::Notify, SOUND_ACTION, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    // TODO: org.matrix.msc3772.thread_reply
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.message"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[Condition::EventMatch(EventMatchCondition {
            key: Cow::Borrowed("type"),
            pattern: Some(Cow::Borrowed("m.room.message")),
            pattern_type: None,
        })]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.encrypted"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[Condition::EventMatch(EventMatchCondition {
            key: Cow::Borrowed("type"),
            pattern: Some(Cow::Borrowed("m.room.encrypted")),
            pattern_type: None,
        })]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.im.vector.jitsi"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("im.vector.modular.widgets")),
                pattern_type: None,
            }),
            Condition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("content.type"),
                pattern: Some(Cow::Borrowed("jitsi")),
                pattern_type: None,
            }),
            Condition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("state_key"),
                pattern: Some(Cow::Borrowed("*")),
                pattern_type: None,
            }),
        ]),
        actions: Cow::Borrowed(&[HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
];

lazy_static! {
    static ref BASE_RULES_BY_ID: HashMap<&'static str, &'static PushRule> =
        BASE_PREPEND_OVERRIDE_RULES
            .iter()
            .chain(BASE_APPEND_OVERRIDE_RULES.iter())
            .chain(BASE_APPEND_CONTENT_RULES.iter())
            .chain(BASE_APPEND_UNDERRIDE_RULES.iter())
            .map(|rule| { (&*rule.rule_id, rule) })
            .collect();
}

#[test]
fn test_erialize_condition() {
    let condition = Condition::EventMatch(EventMatchCondition {
        key: "content.body".into(),
        pattern: Some("coffee".into()),
        pattern_type: None,
    });

    let json = serde_json::to_string(&condition).unwrap();
    assert_eq!(
        json,
        r#"{"kind":"event_match","key":"content.body","pattern":"coffee"}"#
    )
}

#[test]
fn test_deserialize_condition() {
    let json = r#"{"kind":"event_match","key":"content.body","pattern":"coffee"}"#;

    let _: Condition = serde_json::from_str(json).unwrap();
}

#[test]
fn test_deserialize_action() {
    let _: Action = serde_json::from_str(r#""notify""#).unwrap();
    let _: Action = serde_json::from_str(r#""dont_notify""#).unwrap();
    let _: Action = serde_json::from_str(r#""coalesce""#).unwrap();
    let _: Action = serde_json::from_str(r#"{"set_tweak": "highlight"}"#).unwrap();
}

#[test]
fn push_rule_evaluator() {
    let mut flattened_keys = BTreeMap::new();
    flattened_keys.insert("content.body".to_string(), "foo bar bob hello".to_string());
    let evaluator = PushRuleEvaluator::py_new(flattened_keys, 10, 0, BTreeMap::new()).unwrap();

    let result = evaluator.run(&FilteredPushRules::default(), None, Some("bob"));
    assert_eq!(result.len(), 3);
}
