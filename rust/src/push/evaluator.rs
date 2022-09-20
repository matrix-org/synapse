use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Error};
use lazy_static::lazy_static;
use log::warn;
use pyo3::prelude::*;
use regex::Regex;

use super::{
    utils::{get_localpart_from_id, glob_to_regex, GlobMatchType},
    Action, Condition, EventMatchCondition, FilteredPushRules, KnownCondition,
};

lazy_static! {
    static ref INEQUALITY_EXPR: Regex = Regex::new(r"^([=<>]*)([0-9]*)$").expect("valid regex");
}

/// Allows running a set of push rules against a particular event.
#[pyclass]
pub struct PushRuleEvaluator {
    /// A mapping of "flattened" keys to string values in the event, e.g.
    /// includes things like "type" and "content.msgtype".
    flattened_keys: BTreeMap<String, String>,

    /// The "content.body", if any.
    body: String,

    /// The number of users in the room.
    room_member_count: u64,

    /// The `notifications` section of the current power levels in the room.
    notification_power_levels: BTreeMap<String, i64>,

    /// The relations related to the event as a mapping from relation type to
    /// set of sender/event type 2-tuples.
    relations: BTreeMap<String, BTreeSet<(String, String)>>,

    /// Is running "relation" conditions enabled?
    relation_match_enabled: bool,

    /// The power level of the sender of the event
    sender_power_level: i64,
}

#[pymethods]
impl PushRuleEvaluator {
    /// Create a new `PushRuleEvaluator`. See struct docstring for details.
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

    /// Run the evaluator with the given push rules, for the given user ID and
    /// display name of the user.
    ///
    /// Passing in None will skip evaluating rules matching user ID and display
    /// name.
    ///
    /// Returns the set of actions, if any, that match (filtering out any
    /// `dont_notify` actions).
    fn run(
        &self,
        push_rules: &FilteredPushRules,
        user_id: Option<&str>,
        display_name: Option<&str>,
    ) -> Vec<Action> {
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

            let actions = push_rule
                .actions
                .iter()
                // Filter out "dont_notify" actions, as we don't store them.
                .filter(|a| **a != Action::DontNotify)
                .cloned()
                .collect();

            return actions;
        }

        Vec::new()
    }

    /// Check if the given condition matches.
    fn matches(
        &self,
        condition: Condition,
        user_id: Option<&str>,
        display_name: Option<&str>,
    ) -> bool {
        match self.match_condition(&condition, user_id, display_name) {
            Ok(true) => true,
            Ok(false) => false,
            Err(err) => {
                warn!("Condition match failed {err}");
                true
            }
        }
    }
}

impl PushRuleEvaluator {
    /// Match a given `Condition` for a push rule.
    pub fn match_condition(
        &self,
        condition: &Condition,
        user_id: Option<&str>,
        display_name: Option<&str>,
    ) -> Result<bool, Error> {
        let known_condition = match condition {
            Condition::Known(known) => known,
            Condition::Unknown(_) => {
                return Ok(false);
            }
        };

        let result = match known_condition {
            KnownCondition::EventMatch(event_match) => {
                self.match_event_match(event_match, user_id)?
            }
            KnownCondition::ContainsDisplayName => {
                if let Some(dn) = display_name {
                    if !dn.is_empty() {
                        let matcher = glob_to_regex(dn, GlobMatchType::Word)?;
                        matcher.is_match(&self.body)
                    } else {
                        // We specifically ignore empty display names, as otherwise
                        // they would always match.
                        false
                    }
                } else {
                    false
                }
            }
            KnownCondition::RoomMemberCount { is } => {
                if let Some(is) = is {
                    self.match_member_count(is)?
                } else {
                    false
                }
            }
            KnownCondition::SenderNotificationPermission { key } => {
                let required_level = self
                    .notification_power_levels
                    .get(key.as_ref())
                    .copied()
                    .unwrap_or(50);

                self.sender_power_level >= required_level
            }
            KnownCondition::RelationMatch {
                rel_type,
                event_type_pattern,
                sender,
                sender_type,
            } => {
                if !self.relation_match_enabled {
                    return Ok(false);
                }

                let relations = if let Some(relations) = self.relations.get(&**rel_type) {
                    relations
                } else {
                    return Ok(false);
                };

                let sender_pattern = if let Some(sender) = sender {
                    Some(sender.as_ref())
                } else if let Some(sender_type) = sender_type {
                    if sender_type == "user_id" {
                        if let Some(user_id) = user_id {
                            Some(user_id)
                        } else {
                            return Ok(false);
                        }
                    } else {
                        warn!("Unrecognized sender_type: {sender_type}");
                        return Ok(false);
                    }
                } else {
                    None
                };

                let sender_compiled_pattern = if let Some(pattern) = sender_pattern {
                    Some(glob_to_regex(pattern, GlobMatchType::Whole)?)
                } else {
                    None
                };

                let type_compiled_pattern = if let Some(pattern) = event_type_pattern {
                    Some(glob_to_regex(pattern, GlobMatchType::Whole)?)
                } else {
                    None
                };

                for (relation_sender, event_type) in relations {
                    if let Some(pattern) = &sender_compiled_pattern {
                        if !pattern.is_match(relation_sender) {
                            continue;
                        }
                    }

                    if let Some(pattern) = &type_compiled_pattern {
                        if !pattern.is_match(event_type) {
                            continue;
                        }
                    }

                    return Ok(true);
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

        // For the content.body we match against "words", but for everything
        // else we match against the entire value.
        let match_type = if event_match.key == "content.body" {
            GlobMatchType::Word
        } else {
            GlobMatchType::Whole
        };

        if let Some(value) = self.flattened_keys.get(&*event_match.key) {
            let compiled_pattern = glob_to_regex(pattern, match_type)?;
            Ok(compiled_pattern.is_match(value))
        } else {
            Ok(false)
        }
    }

    /// Match the member count against an 'is' condition
    fn match_member_count(&self, is: &str) -> Result<bool, Error> {
        // The 'is' condition can be things like '>2', '==3' or event just '4'.
        let captures = INEQUALITY_EXPR.captures(is).context("bad 'is' clause")?;
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
