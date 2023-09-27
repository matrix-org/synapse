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

use std::borrow::Cow;
use std::collections::BTreeMap;

use anyhow::{Context, Error};
use lazy_static::lazy_static;
use log::warn;
use pyo3::prelude::*;
use regex::Regex;

use super::{
    utils::{get_glob_matcher, get_localpart_from_id, GlobMatchType},
    Action, Condition, EventPropertyIsCondition, FilteredPushRules, KnownCondition,
    SimpleJsonValue,
};
use crate::push::{EventMatchPatternType, JsonValue};

lazy_static! {
    /// Used to parse the `is` clause in the room member count condition.
    static ref INEQUALITY_EXPR: Regex = Regex::new(r"^([=<>]*)([0-9]+)$").expect("valid regex");

    /// Used to determine which MSC3931 room version feature flags are actually known to
    /// the push evaluator.
    static ref KNOWN_RVER_FLAGS: Vec<String> = vec![
        RoomVersionFeatures::ExtensibleEvents.as_str().to_string(),
    ];

    /// The "safe" rule IDs which are not affected by MSC3932's behaviour (room versions which
    /// declare Extensible Events support ultimately *disable* push rules which do not declare
    /// *any* MSC3931 room_version_supports condition).
    static ref SAFE_EXTENSIBLE_EVENTS_RULE_IDS: Vec<String> = vec![
        "global/override/.m.rule.master".to_string(),
        "global/override/.m.rule.roomnotif".to_string(),
        "global/content/.m.rule.contains_user_name".to_string(),
    ];
}

enum RoomVersionFeatures {
    ExtensibleEvents,
}

impl RoomVersionFeatures {
    fn as_str(&self) -> &'static str {
        match self {
            RoomVersionFeatures::ExtensibleEvents => "org.matrix.msc3932.extensible_events",
        }
    }
}

/// Allows running a set of push rules against a particular event.
#[pyclass]
pub struct PushRuleEvaluator {
    /// A mapping of "flattened" keys to simple JSON values in the event, e.g.
    /// includes things like "type" and "content.msgtype".
    flattened_keys: BTreeMap<String, JsonValue>,

    /// The "content.body", if any.
    body: String,

    /// True if the event has a m.mentions property. (Note that this is a separate
    /// flag instead of checking flattened_keys since the m.mentions property
    /// might be an empty map and not appear in flattened_keys.
    has_mentions: bool,

    /// The number of users in the room.
    room_member_count: u64,

    /// The `notifications` section of the current power levels in the room.
    notification_power_levels: BTreeMap<String, i64>,

    /// The power level of the sender of the event, or None if event is an
    /// outlier.
    sender_power_level: Option<i64>,

    /// The related events, indexed by relation type. Flattened in the same manner as
    /// `flattened_keys`.
    related_events_flattened: BTreeMap<String, BTreeMap<String, JsonValue>>,

    /// If msc3664, push rules for related events, is enabled.
    related_event_match_enabled: bool,

    /// If MSC3931 is applicable, the feature flags for the room version.
    room_version_feature_flags: Vec<String>,

    /// If MSC3931 (room version feature flags) is enabled. Usually controlled by the same
    /// flag as MSC1767 (extensible events core).
    msc3931_enabled: bool,
}

#[pymethods]
impl PushRuleEvaluator {
    /// Create a new `PushRuleEvaluator`. See struct docstring for details.
    #[allow(clippy::too_many_arguments)]
    #[new]
    #[pyo3(signature = (
        flattened_keys,
        has_mentions,
        room_member_count,
        sender_power_level,
        notification_power_levels,
        related_events_flattened,
        related_event_match_enabled,
        room_version_feature_flags,
        msc3931_enabled,
    ))]
    pub fn py_new(
        flattened_keys: BTreeMap<String, JsonValue>,
        has_mentions: bool,
        room_member_count: u64,
        sender_power_level: Option<i64>,
        notification_power_levels: BTreeMap<String, i64>,
        related_events_flattened: BTreeMap<String, BTreeMap<String, JsonValue>>,
        related_event_match_enabled: bool,
        room_version_feature_flags: Vec<String>,
        msc3931_enabled: bool,
    ) -> Result<Self, Error> {
        let body = match flattened_keys.get("content.body") {
            Some(JsonValue::Value(SimpleJsonValue::Str(s))) => s.clone().into_owned(),
            _ => String::new(),
        };

        Ok(PushRuleEvaluator {
            flattened_keys,
            body,
            has_mentions,
            room_member_count,
            notification_power_levels,
            sender_power_level,
            related_events_flattened,
            related_event_match_enabled,
            room_version_feature_flags,
            msc3931_enabled,
        })
    }

    /// Run the evaluator with the given push rules, for the given user ID and
    /// display name of the user.
    ///
    /// Passing in None will skip evaluating rules matching user ID and display
    /// name.
    ///
    /// Returns the set of actions, if any, that match (filtering out any
    /// `dont_notify` and `coalesce` actions).
    pub fn run(
        &self,
        push_rules: &FilteredPushRules,
        user_id: Option<&str>,
        display_name: Option<&str>,
    ) -> Vec<Action> {
        'outer: for (push_rule, enabled) in push_rules.iter() {
            if !enabled {
                continue;
            }

            let rule_id = &push_rule.rule_id().to_string();

            // For backwards-compatibility the legacy mention rules are disabled
            // if the event contains the 'm.mentions' property.
            if self.has_mentions
                && (rule_id == "global/override/.m.rule.contains_display_name"
                    || rule_id == "global/content/.m.rule.contains_user_name"
                    || rule_id == "global/override/.m.rule.roomnotif")
            {
                continue;
            }

            let extev_flag = &RoomVersionFeatures::ExtensibleEvents.as_str().to_string();
            let supports_extensible_events = self.room_version_feature_flags.contains(extev_flag);
            let safe_from_rver_condition = SAFE_EXTENSIBLE_EVENTS_RULE_IDS.contains(rule_id);
            let mut has_rver_condition = false;

            for condition in push_rule.conditions.iter() {
                has_rver_condition |= matches!(
                    condition,
                    // per MSC3932, we just need *any* room version condition to match
                    Condition::Known(KnownCondition::RoomVersionSupports { feature: _ }),
                );

                match self.match_condition(condition, user_id, display_name) {
                    Ok(true) => {}
                    Ok(false) => continue 'outer,
                    Err(err) => {
                        warn!("Condition match failed {err}");
                        continue 'outer;
                    }
                }
            }

            // MSC3932: Disable push rules in extensible event-supporting room versions if they
            // don't describe *any* MSC3931 room version condition, unless the rule is on the
            // safe list.
            if !has_rver_condition && !safe_from_rver_condition && supports_extensible_events {
                continue;
            }

            let actions = push_rule
                .actions
                .iter()
                // Filter out "dont_notify" and "coalesce" actions, as we don't store them
                // (since they result in no action by the pushers).
                .filter(|a| **a != Action::DontNotify && **a != Action::Coalesce)
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
                false
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
            KnownCondition::EventMatch(event_match) => self.match_event_match(
                &self.flattened_keys,
                &event_match.key,
                &event_match.pattern,
            )?,
            KnownCondition::EventMatchType(event_match) => {
                // The `pattern_type` can either be "user_id" or "user_localpart",
                // either way if we don't have a `user_id` then the condition can't
                // match.
                let user_id = if let Some(user_id) = user_id {
                    user_id
                } else {
                    return Ok(false);
                };

                let pattern = match &*event_match.pattern_type {
                    EventMatchPatternType::UserId => user_id,
                    EventMatchPatternType::UserLocalpart => get_localpart_from_id(user_id)?,
                };

                self.match_event_match(&self.flattened_keys, &event_match.key, pattern)?
            }
            KnownCondition::EventPropertyIs(event_property_is) => {
                self.match_event_property_is(event_property_is)?
            }
            KnownCondition::RelatedEventMatch(event_match) => self.match_related_event_match(
                &event_match.rel_type.clone(),
                event_match.include_fallbacks,
                event_match.key.clone(),
                event_match.pattern.clone(),
            )?,
            KnownCondition::RelatedEventMatchType(event_match) => {
                // The `pattern_type` can either be "user_id" or "user_localpart",
                // either way if we don't have a `user_id` then the condition can't
                // match.
                let user_id = if let Some(user_id) = user_id {
                    user_id
                } else {
                    return Ok(false);
                };

                let pattern = match &*event_match.pattern_type {
                    EventMatchPatternType::UserId => user_id,
                    EventMatchPatternType::UserLocalpart => get_localpart_from_id(user_id)?,
                };

                self.match_related_event_match(
                    &event_match.rel_type.clone(),
                    event_match.include_fallbacks,
                    Some(event_match.key.clone()),
                    Some(Cow::Borrowed(pattern)),
                )?
            }
            KnownCondition::EventPropertyContains(event_property_is) => self
                .match_event_property_contains(
                    event_property_is.key.clone(),
                    event_property_is.value.clone(),
                )?,
            KnownCondition::ExactEventPropertyContainsType(exact_event_match) => {
                // The `pattern_type` can either be "user_id" or "user_localpart",
                // either way if we don't have a `user_id` then the condition can't
                // match.
                let user_id = if let Some(user_id) = user_id {
                    user_id
                } else {
                    return Ok(false);
                };

                let pattern = match &*exact_event_match.value_type {
                    EventMatchPatternType::UserId => user_id.to_owned(),
                    EventMatchPatternType::UserLocalpart => {
                        get_localpart_from_id(user_id)?.to_owned()
                    }
                };

                self.match_event_property_contains(
                    exact_event_match.key.clone(),
                    Cow::Borrowed(&SimpleJsonValue::Str(Cow::Owned(pattern))),
                )?
            }
            KnownCondition::ContainsDisplayName => {
                if let Some(dn) = display_name {
                    if !dn.is_empty() {
                        get_glob_matcher(dn, GlobMatchType::Word)?.is_match(&self.body)?
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
                if let Some(sender_power_level) = &self.sender_power_level {
                    let required_level = self
                        .notification_power_levels
                        .get(key.as_ref())
                        .copied()
                        .unwrap_or(50);

                    *sender_power_level >= required_level
                } else {
                    false
                }
            }
            KnownCondition::RoomVersionSupports { feature } => {
                if !self.msc3931_enabled {
                    false
                } else {
                    let flag = feature.to_string();
                    KNOWN_RVER_FLAGS.contains(&flag)
                        && self.room_version_feature_flags.contains(&flag)
                }
            }
        };

        Ok(result)
    }

    /// Evaluates a `event_match` condition.
    fn match_event_match(
        &self,
        flattened_event: &BTreeMap<String, JsonValue>,
        key: &str,
        pattern: &str,
    ) -> Result<bool, Error> {
        let haystack = if let Some(JsonValue::Value(SimpleJsonValue::Str(haystack))) =
            flattened_event.get(key)
        {
            haystack
        } else {
            return Ok(false);
        };

        // For the content.body we match against "words", but for everything
        // else we match against the entire value.
        let match_type = if key == "content.body" {
            GlobMatchType::Word
        } else {
            GlobMatchType::Whole
        };

        let mut compiled_pattern = get_glob_matcher(pattern, match_type)?;
        compiled_pattern.is_match(haystack)
    }

    /// Evaluates a `event_property_is` condition.
    fn match_event_property_is(
        &self,
        event_property_is: &EventPropertyIsCondition,
    ) -> Result<bool, Error> {
        let value = &event_property_is.value;

        let haystack = if let Some(JsonValue::Value(haystack)) =
            self.flattened_keys.get(&*event_property_is.key)
        {
            haystack
        } else {
            return Ok(false);
        };

        Ok(haystack == &**value)
    }

    /// Evaluates a `related_event_match` condition. (MSC3664)
    fn match_related_event_match(
        &self,
        rel_type: &str,
        include_fallbacks: Option<bool>,
        key: Option<Cow<str>>,
        pattern: Option<Cow<str>>,
    ) -> Result<bool, Error> {
        // First check if related event matching is enabled...
        if !self.related_event_match_enabled {
            return Ok(false);
        }

        // get the related event, fail if there is none.
        let event = if let Some(event) = self.related_events_flattened.get(rel_type) {
            event
        } else {
            return Ok(false);
        };

        // If we are not matching fallbacks, don't match if our special key indicating this is a
        // fallback relation is not present.
        if !include_fallbacks.unwrap_or(false) && event.contains_key("im.vector.is_falling_back") {
            return Ok(false);
        }

        match (key, pattern) {
            // if we have no key, accept the event as matching.
            (None, _) => Ok(true),
            // There was a key, so we *must* have a pattern to go with it.
            (Some(_), None) => Ok(false),
            // If there is a key & pattern, check if they're in the flattened event (given by rel_type).
            (Some(key), Some(pattern)) => self.match_event_match(event, &key, &pattern),
        }
    }

    /// Evaluates a `event_property_contains` condition.
    fn match_event_property_contains(
        &self,
        key: Cow<str>,
        value: Cow<SimpleJsonValue>,
    ) -> Result<bool, Error> {
        let haystack = if let Some(JsonValue::Array(haystack)) = self.flattened_keys.get(&*key) {
            haystack
        } else {
            return Ok(false);
        };

        Ok(haystack.contains(&value))
    }

    /// Match the member count against an 'is' condition
    /// The `is` condition can be things like '>2', '==3' or even just '4'.
    fn match_member_count(&self, is: &str) -> Result<bool, Error> {
        let captures = INEQUALITY_EXPR.captures(is).context("bad 'is' clause")?;
        let ineq = captures.get(1).map_or("==", |m| m.as_str());
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
    flattened_keys.insert(
        "content.body".to_string(),
        JsonValue::Value(SimpleJsonValue::Str(Cow::Borrowed("foo bar bob hello"))),
    );
    let evaluator = PushRuleEvaluator::py_new(
        flattened_keys,
        false,
        10,
        Some(0),
        BTreeMap::new(),
        BTreeMap::new(),
        true,
        vec![],
        true,
    )
    .unwrap();

    let result = evaluator.run(&FilteredPushRules::default(), None, Some("bob"));
    assert_eq!(result.len(), 3);
}

#[test]
fn test_requires_room_version_supports_condition() {
    use std::borrow::Cow;

    use crate::push::{PushRule, PushRules};

    let mut flattened_keys = BTreeMap::new();
    flattened_keys.insert(
        "content.body".to_string(),
        JsonValue::Value(SimpleJsonValue::Str(Cow::Borrowed("foo bar bob hello"))),
    );
    let flags = vec![RoomVersionFeatures::ExtensibleEvents.as_str().to_string()];
    let evaluator = PushRuleEvaluator::py_new(
        flattened_keys,
        false,
        10,
        Some(0),
        BTreeMap::new(),
        BTreeMap::new(),
        false,
        flags,
        true,
    )
    .unwrap();

    // first test: are the master and contains_user_name rules excluded from the "requires room
    // version condition" check?
    let mut result = evaluator.run(
        &FilteredPushRules::default(),
        Some("@bob:example.org"),
        None,
    );
    assert_eq!(result.len(), 3);

    // second test: if an appropriate push rule is in play, does it get handled?
    let custom_rule = PushRule {
        rule_id: Cow::from("global/underride/.org.example.extensible"),
        priority_class: 1, // underride
        conditions: Cow::from(vec![Condition::Known(
            KnownCondition::RoomVersionSupports {
                feature: Cow::from(RoomVersionFeatures::ExtensibleEvents.as_str().to_string()),
            },
        )]),
        actions: Cow::from(vec![Action::Notify]),
        default: false,
        default_enabled: true,
    };
    let rules = PushRules::new(vec![custom_rule]);
    result = evaluator.run(
        &FilteredPushRules::py_new(rules, BTreeMap::new(), true, false, true, false),
        None,
        None,
    );
    assert_eq!(result.len(), 1);
}
