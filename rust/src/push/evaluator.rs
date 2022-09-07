use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Error};
use log::{info, warn};
use pyo3::prelude::*;

use super::{
    utils::{get_localpart_from_id, glob_to_regex, GlobMatchType},
    Action, Condition, EventMatchCondition, FilteredPushRules, INEQUALITY_EXPR,
};

#[pyclass]
pub struct PushRuleEvaluator {
    flattened_keys: BTreeMap<String, String>,
    body: String,
    room_member_count: u64,
    notification_power_levels: BTreeMap<String, i64>,
    relations: BTreeMap<String, BTreeSet<(String, String)>>,
    relation_match_enabled: bool,
    sender_power_level: i64,
}

#[pymethods]
impl PushRuleEvaluator {
    #[new]
    fn py_new(
        flattened_keys: BTreeMap<String, String>,
        room_member_count: u64,
        sender_power_level: i64,
        notification_power_levels: BTreeMap<String, i64>,
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
            notification_power_levels,
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
                    .notification_power_levels
                    .get(key.as_ref())
                    .copied()
                    .unwrap_or(50);

                info!(
                    "Power level {required_level} vs {}",
                    self.sender_power_level
                );

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

                let sender_compiled_pattern = glob_to_regex(sender_pattern, GlobMatchType::Whole)?;
                let rel_type_compiled_pattern = glob_to_regex(rel_type, GlobMatchType::Whole)?;

                for (relation_sender, event_type) in relations {
                    if sender_compiled_pattern.is_match(&relation_sender)
                        && rel_type_compiled_pattern.is_match(event_type)
                    {
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
                "user_localpart" => get_localpart_from_id(user_id)?,
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
