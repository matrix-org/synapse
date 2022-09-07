//! An implementation of Matrix push rules.
//!
//! The `Cow<_>` type is used extensively within this module to allow creating
//! the base rules as constants (in Rust constants can't require explicit
//! allocation atm).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use anyhow::{Context, Error};
use lazy_static::lazy_static;
use log::{info, warn};
use pyo3::prelude::*;
use pythonize::pythonize;
use regex::{Regex, RegexBuilder};
use serde::de::Error as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use self::utils::{glob_to_regex, GlobMatchType};

mod base_rules;
mod utils;

lazy_static! {
    static ref INEQUALITY_EXPR: Regex = Regex::new(r"^([=<>]*)([0-9]*)$").expect("valid regex");
    static ref WORD_BOUNDARY_EXPR: Regex = Regex::new(r"\W*\b\W*").expect("valid regex");
    static ref WILDCARD_RUN: Regex = Regex::new(r"([^\?\*]*)([\?\*]*)").expect("valid regex");
}

/// Called when registering modules with python.
pub fn register_module(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    let child_module = PyModule::new(py, "push")?;
    child_module.add_class::<PushRule>()?;
    child_module.add_class::<PushRules>()?;
    child_module.add_class::<PushRuleEvaluator>()?;
    child_module.add_class::<FilteredPushRules>()?;
    m.add_submodule(child_module)?;

    // We need to manually add the module to sys.modules to make `from
    // synapse.synapse_rust import push` work.
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

    // This picks saves any other fields that may have been added as clients.
    // These get added when we convert the `Action` to a python object.
    #[serde(flatten)]
    other_keys: Value,
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
    RelationMatch {
        rel_type: Cow<'static, str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sender: Option<Cow<'static, str>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sender_type: Option<Cow<'static, str>>,
    },
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
            if let Some(&o) = base_rules::BASE_RULES_BY_ID.get(&*rule.rule_id) {
                push_rules.overridden_base_rules.insert(
                    rule.rule_id.clone(),
                    PushRule {
                        actions: rule.actions.clone(),
                        ..o.clone()
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
                    warn!(
                        "Unrecognized priority class for rule {}: {}",
                        rule.rule_id, rule.priority_class
                    );
                }
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
        base_rules::BASE_PREPEND_OVERRIDE_RULES
            .iter()
            .chain(self.override_rules.iter())
            .chain(base_rules::BASE_APPEND_OVERRIDE_RULES.iter())
            .chain(self.content.iter())
            .chain(base_rules::BASE_APPEND_CONTENT_RULES.iter())
            .chain(self.room.iter())
            .chain(self.sender.iter())
            .chain(self.underride.iter())
            .chain(base_rules::BASE_APPEND_UNDERRIDE_RULES.iter())
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
    body: String,
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
        relations: BTreeMap<String, BTreeSet<(String, String)>>,
        relation_match_enabled: bool,
    ) -> Result<Self, Error> {
        let body = flattened_keys
            .get("content.body")
            .cloned()
            .unwrap_or_default();

        Ok(PushRuleEvaluator {
            flattened_keys,
            body,
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
                match self.match_condition(condition, user_id, display_name) {
                    Ok(true) => {}
                    Ok(false) => continue 'outer,
                    Err(err) => {
                        warn!("Condition match failed {err}");
                        continue 'outer;
                    }
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
    ) -> Result<bool, Error> {
        let result = match condition {
            Condition::EventMatch(event_match) => self.match_event_match(event_match, user_id)?,
            Condition::ContainsDisplayName => {
                if let Some(dn) = display_name {
                    let matcher = glob_to_regex(dn, GlobMatchType::Word)?;
                    matcher.is_match(&self.body)
                } else {
                    false
                }
            }
            Condition::RoomMemberCount { is } => {
                if let Some(is) = is {
                    self.match_member_count(is)?
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
            Condition::RelationMatch {
                rel_type,
                sender,
                sender_type,
            } => {
                if !self.relation_match_enabled {
                    return Ok(false);
                }

                let sender_pattern = if let Some(sender) = sender {
                    sender
                } else if let Some(sender_type) = sender_type {
                    if sender_type == "user_id" {
                        if let Some(user_id) = user_id {
                            user_id
                        } else {
                            return Ok(false);
                        }
                    } else {
                        warn!("Unrecognized sender_type:  {sender_type}");
                        return Ok(false);
                    }
                } else {
                    warn!("relation_match condition missing sender or sender_type");
                    return Ok(false);
                };

                let relations = if let Some(relations) = self.relations.get(&**rel_type) {
                    relations
                } else {
                    return Ok(false);
                };

                for (relation_sender, event_type) in relations {
                    // TODO: glob
                    if relation_sender == sender_pattern && rel_type == event_type {
                        return Ok(true);
                    }
                }

                false
            }
        };

        Ok(result)
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
                "user_localpart" => utils::get_localpart_from_id(user_id)?, // TODO
                _ => return Ok(false),
            }
        } else {
            return Ok(false);
        };

        if event_match.key == "content.body" {
            let compiled_pattern = glob_to_regex(pattern, GlobMatchType::Word)?;
            Ok(compiled_pattern.is_match(&self.body))
        } else if let Some(value) = self.flattened_keys.get(&*event_match.key) {
            let compiled_pattern = glob_to_regex(pattern, GlobMatchType::Whole)?;
            Ok(compiled_pattern.is_match(value))
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

#[test]
fn split_string() {
    let split_body: Vec<_> = WORD_BOUNDARY_EXPR
        .split("this is. A. TEST!!")
        .filter(|s| *s != "")
        .collect();

    assert_eq!(split_body, ["this", "is", "A", "TEST"]);
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
    let evaluator = PushRuleEvaluator::py_new(
        flattened_keys,
        10,
        0,
        BTreeMap::new(),
        BTreeMap::new(),
        true,
    )
    .unwrap();

    let result = evaluator.run(&FilteredPushRules::default(), None, Some("bob"));
    assert_eq!(result.len(), 3);
}
