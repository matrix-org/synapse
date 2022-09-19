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

//! Contains the definitions of the "base" push rules.

use std::borrow::Cow;
use std::collections::HashMap;

use lazy_static::lazy_static;
use serde_json::Value;

use super::KnownCondition;
use crate::push::Action;
use crate::push::Condition;
use crate::push::EventMatchCondition;
use crate::push::PushRule;
use crate::push::SetTweak;
use crate::push::TweakValue;

const HIGHLIGHT_ACTION: Action = Action::SetTweak(SetTweak {
    set_tweak: Cow::Borrowed("highlight"),
    value: None,
    other_keys: Value::Null,
});

const HIGHLIGHT_FALSE_ACTION: Action = Action::SetTweak(SetTweak {
    set_tweak: Cow::Borrowed("highlight"),
    value: Some(TweakValue::Other(Value::Bool(false))),
    other_keys: Value::Null,
});

const SOUND_ACTION: Action = Action::SetTweak(SetTweak {
    set_tweak: Cow::Borrowed("sound"),
    value: Some(TweakValue::String(Cow::Borrowed("default"))),
    other_keys: Value::Null,
});

const RING_ACTION: Action = Action::SetTweak(SetTweak {
    set_tweak: Cow::Borrowed("sound"),
    value: Some(TweakValue::String(Cow::Borrowed("ring"))),
    other_keys: Value::Null,
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
        conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::EventMatch(
            EventMatchCondition {
                key: Cow::Borrowed("content.msgtype"),
                pattern: Some(Cow::Borrowed("m.notice")),
                pattern_type: None,
            },
        ))]),
        actions: Cow::Borrowed(&[Action::DontNotify]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.invite_for_me"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("m.room.member")),
                pattern_type: None,
            })),
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("content.membership"),
                pattern: Some(Cow::Borrowed("invite")),
                pattern_type: None,
            })),
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("state_key"),
                pattern: None,
                pattern_type: Some(Cow::Borrowed("user_id")),
            })),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_FALSE_ACTION, SOUND_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.member_event"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::EventMatch(
            EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("m.room.member")),
                pattern_type: None,
            },
        ))]),
        actions: Cow::Borrowed(&[Action::DontNotify]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.contains_display_name"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::ContainsDisplayName)]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_ACTION, SOUND_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.roomnotif"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::SenderNotificationPermission {
                key: Cow::Borrowed("room"),
            }),
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("content.body"),
                pattern: Some(Cow::Borrowed("@room")),
                pattern_type: None,
            })),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.tombstone"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("m.room.tombstone")),
                pattern_type: None,
            })),
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("state_key"),
                pattern: Some(Cow::Borrowed("")),
                pattern_type: None,
            })),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.reaction"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::EventMatch(
            EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("m.reaction")),
                pattern_type: None,
            },
        ))]),
        actions: Cow::Borrowed(&[Action::DontNotify]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.org.matrix.msc3786.rule.room.server_acl"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("m.room.server_acl")),
                pattern_type: None,
            })),
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("state_key"),
                pattern: Some(Cow::Borrowed("")),
                pattern_type: None,
            })),
        ]),
        actions: Cow::Borrowed(&[]),
        default: true,
        default_enabled: true,
    },
];

pub const BASE_APPEND_CONTENT_RULES: &[PushRule] = &[PushRule {
    rule_id: Cow::Borrowed("global/content/.m.rule.contains_user_name"),
    priority_class: 4,
    conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::EventMatch(
        EventMatchCondition {
            key: Cow::Borrowed("content.body"),
            pattern: None,
            pattern_type: Some(Cow::Borrowed("user_localpart")),
        },
    ))]),
    actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_ACTION, SOUND_ACTION]),
    default: true,
    default_enabled: true,
}];

pub const BASE_APPEND_UNDERRIDE_RULES: &[PushRule] = &[
    PushRule {
        rule_id: Cow::Borrowed("global/underride/.m.rule.call"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::EventMatch(
            EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("m.call.invite")),
                pattern_type: None,
            },
        ))]),
        actions: Cow::Borrowed(&[Action::Notify, RING_ACTION, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/underride/.m.rule.room_one_to_one"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("m.room.message")),
                pattern_type: None,
            })),
            Condition::Known(KnownCondition::RoomMemberCount {
                is: Some(Cow::Borrowed("2")),
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, SOUND_ACTION, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/underride/.m.rule.encrypted_room_one_to_one"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("m.room.encrypted")),
                pattern_type: None,
            })),
            Condition::Known(KnownCondition::RoomMemberCount {
                is: Some(Cow::Borrowed("2")),
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, SOUND_ACTION, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/underride/.org.matrix.msc3772.thread_reply"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::RelationMatch {
            rel_type: Cow::Borrowed("m.thread"),
            sender: None,
            sender_type: Some(Cow::Borrowed("user_id")),
        })]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/underride/.m.rule.message"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::EventMatch(
            EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("m.room.message")),
                pattern_type: None,
            },
        ))]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/underride/.m.rule.encrypted"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::EventMatch(
            EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("m.room.encrypted")),
                pattern_type: None,
            },
        ))]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/underride/.im.vector.jitsi"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("im.vector.modular.widgets")),
                pattern_type: None,
            })),
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("content.type"),
                pattern: Some(Cow::Borrowed("jitsi")),
                pattern_type: None,
            })),
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("state_key"),
                pattern: Some(Cow::Borrowed("*")),
                pattern_type: None,
            })),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
];

lazy_static! {
    pub static ref BASE_RULES_BY_ID: HashMap<&'static str, &'static PushRule> =
        BASE_PREPEND_OVERRIDE_RULES
            .iter()
            .chain(BASE_APPEND_OVERRIDE_RULES.iter())
            .chain(BASE_APPEND_CONTENT_RULES.iter())
            .chain(BASE_APPEND_UNDERRIDE_RULES.iter())
            .map(|rule| { (&*rule.rule_id, rule) })
            .collect();
}
