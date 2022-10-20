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
    // Disable notifications for auto-accepted room invites
    // NOTE: this rule must be a higher prio than .m.rule.invite_for_me because
    // that will also match the same events.
    PushRule {
        rule_id: Cow::Borrowed("global/override/.com.beeper.suppress_auto_invite"),
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
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("content.fi.mau.will_auto_accept"),
                pattern: Some(Cow::Borrowed("true")),
                pattern_type: None,
            })),
        ]),
        actions: Cow::Borrowed(&[Action::DontNotify]),
        default: true,
        default_enabled: true,
    },
    // We don't want to notify on edits in Beeper land. Not only can this be confusing
    // in real time (2 notifications, one message) but it's also especially confusing
    // when a bridge needs to edit a previously backfilled message.
    PushRule {
        rule_id: Cow::Borrowed("global/override/.com.beeper.suppress_edits"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("content.m.relates_to.rel_type"),
                pattern: Some(Cow::Borrowed("m.replace")),
                pattern_type: None,
            })),
        ]),
        actions: Cow::Borrowed(&[Action::DontNotify]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.com.beeper.suppress_send_message_status"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("com.beeper.message_send_status")),
                pattern_type: None,
            })),
        ]),
        actions: Cow::Borrowed(&[Action::DontNotify]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.com.beeper.suppress_power_levels"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("cm.room.power_levels")),
                pattern_type: None,
            })),
        ]),
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
    // NOTE: upstream has a blanket rule that blocks all notifications for reactions,
    // this is a modified rule that blocks reactions to *other users* events. This means
    // any user supplied "noisy" rules don't accidentally trigger notifications for reactions
    // to other users messages.
    PushRule {
        rule_id: Cow::Borrowed("global/override/.com.beeper.reaction"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("m.reaction")),
                pattern_type: None,
            })),
            Condition::Known(KnownCondition::InverseRelatedEventMatch(EventMatchCondition {
                key: Cow::Borrowed("sender"),
                pattern: None,
                pattern_type: Some(Cow::Borrowed("user_id")),
            })),
        ]),
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
    // Beeper change: this rule is moved down from override. This means room
    // rules take precedence, so if you enable bot notifications (by modifying
    // this rule) notifications will not be sent for muted rooms.
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
            event_type_pattern: None,
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
    // Enable notifications for reactions to your own messages *in rooms with less
    // than 20 members*.
    PushRule {
        rule_id: Cow::Borrowed("global/override/.com.beeper.reaction"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[

            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Some(Cow::Borrowed("m.reaction")),
                pattern_type: None,
            })),
            Condition::Known(KnownCondition::RoomMemberCount {
                is: Some(Cow::Borrowed("<20")),
            }),
            Condition::Known(KnownCondition::RelatedEventMatch(EventMatchCondition {
                key: Cow::Borrowed("sender"),
                pattern: None,
                pattern_type: Some(Cow::Borrowed("user_id")),
            })),
        ]),
        actions: Cow::Borrowed(&[Action::DontNotify]),
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
