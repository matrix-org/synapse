//! An implementation of Matrix push rules.
//!
//! The `Cow<_>` type is used extensively within this module to allow creating
//! the base rules as constants (in Rust constants can't require explicit
//! allocation atm).

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, Error};
use lazy_static::lazy_static;
use log::warn;
use pyo3::prelude::*;
use pythonize::pythonize;
use regex::Regex;
use serde::de::Error as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use self::evaluator::PushRuleEvaluator;

mod base_rules;
mod evaluator;
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SetTweak {
    set_tweak: Cow<'static, str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<TweakValue>,

    // This picks saves any other fields that may have been added as clients.
    // These get added when we convert the `Action` to a python object.
    #[serde(flatten)]
    other_keys: Value,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
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
    msc3786_enabled: bool,
    msc3772_enabled: bool,
}

#[pymethods]
impl FilteredPushRules {
    #[new]
    fn py_new(
        push_rules: PushRules,
        enabled_map: BTreeMap<String, bool>,
        msc3786_enabled: bool,
        msc3772_enabled: bool,
    ) -> Self {
        Self {
            push_rules,
            enabled_map,
            msc3786_enabled,
            msc3772_enabled,
        }
    }

    fn rules(&self) -> Vec<(PushRule, bool)> {
        self.iter().map(|(r, e)| (r.clone(), e)).collect()
    }
}

impl FilteredPushRules {
    fn iter(&self) -> impl Iterator<Item = (&PushRule, bool)> {
        self.push_rules
            .iter()
            .filter(|rule| {
                // Ignore disabled experimental push rules
                if !self.msc3786_enabled
                    && rule.rule_id == "global/override/.org.matrix.msc3786.rule.room.server_acl"
                {
                    return false;
                }

                if !self.msc3772_enabled
                    && rule.rule_id == "global/underride/.org.matrix.msc3772.thread_reply"
                {
                    return false;
                }

                true
            })
            .map(|r| {
                let enabled = *self
                    .enabled_map
                    .get(&*r.rule_id)
                    .unwrap_or(&r.default_enabled);
                (r, enabled)
            })
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
