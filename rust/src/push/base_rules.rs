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
use crate::push::RelatedEventMatchCondition;
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
        rule_id: Cow::Borrowed("global/override/.im.nheko.msc3664.reply"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::RelatedEventMatch(
            RelatedEventMatchCondition {
                key: Some(Cow::Borrowed("sender")),
                pattern: None,
                pattern_type: Some(Cow::Borrowed("user_id")),
                rel_type: Cow::Borrowed("m.in_reply_to"),
                include_fallbacks: None,
            },
        ))]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_ACTION, SOUND_ACTION]),
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
        rule_id: Cow::Borrowed("global/override/.m.rule.room.server_acl"),
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
        rule_id: Cow::Borrowed(
            "global/underride/.org.matrix.msc3933.rule.extensible.encrypted_room_one_to_one",
        ),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                // MSC3933: Type changed from template rule - see MSC.
                pattern: Some(Cow::Borrowed("org.matrix.msc1767.encrypted")),
                pattern_type: None,
            })),
            Condition::Known(KnownCondition::RoomMemberCount {
                is: Some(Cow::Borrowed("2")),
            }),
            // MSC3933: Add condition on top of template rule - see MSC.
            Condition::Known(KnownCondition::RoomVersionSupports {
                // RoomVersionFeatures::ExtensibleEvents.as_str(), ideally
                feature: Cow::Borrowed("org.matrix.msc3932.extensible_events"),
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, SOUND_ACTION, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed(
            "global/underride/.org.matrix.msc3933.rule.extensible.message.room_one_to_one",
        ),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                // MSC3933: Type changed from template rule - see MSC.
                pattern: Some(Cow::Borrowed("org.matrix.msc1767.message")),
                pattern_type: None,
            })),
            Condition::Known(KnownCondition::RoomMemberCount {
                is: Some(Cow::Borrowed("2")),
            }),
            // MSC3933: Add condition on top of template rule - see MSC.
            Condition::Known(KnownCondition::RoomVersionSupports {
                // RoomVersionFeatures::ExtensibleEvents.as_str(), ideally
                feature: Cow::Borrowed("org.matrix.msc3932.extensible_events"),
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, SOUND_ACTION, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed(
            "global/underride/.org.matrix.msc3933.rule.extensible.file.room_one_to_one",
        ),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                // MSC3933: Type changed from template rule - see MSC.
                pattern: Some(Cow::Borrowed("org.matrix.msc1767.file")),
                pattern_type: None,
            })),
            Condition::Known(KnownCondition::RoomMemberCount {
                is: Some(Cow::Borrowed("2")),
            }),
            // MSC3933: Add condition on top of template rule - see MSC.
            Condition::Known(KnownCondition::RoomVersionSupports {
                // RoomVersionFeatures::ExtensibleEvents.as_str(), ideally
                feature: Cow::Borrowed("org.matrix.msc3932.extensible_events"),
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, SOUND_ACTION, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed(
            "global/underride/.org.matrix.msc3933.rule.extensible.image.room_one_to_one",
        ),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                // MSC3933: Type changed from template rule - see MSC.
                pattern: Some(Cow::Borrowed("org.matrix.msc1767.image")),
                pattern_type: None,
            })),
            Condition::Known(KnownCondition::RoomMemberCount {
                is: Some(Cow::Borrowed("2")),
            }),
            // MSC3933: Add condition on top of template rule - see MSC.
            Condition::Known(KnownCondition::RoomVersionSupports {
                // RoomVersionFeatures::ExtensibleEvents.as_str(), ideally
                feature: Cow::Borrowed("org.matrix.msc3932.extensible_events"),
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, SOUND_ACTION, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed(
            "global/underride/.org.matrix.msc3933.rule.extensible.video.room_one_to_one",
        ),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                // MSC3933: Type changed from template rule - see MSC.
                pattern: Some(Cow::Borrowed("org.matrix.msc1767.video")),
                pattern_type: None,
            })),
            Condition::Known(KnownCondition::RoomMemberCount {
                is: Some(Cow::Borrowed("2")),
            }),
            // MSC3933: Add condition on top of template rule - see MSC.
            Condition::Known(KnownCondition::RoomVersionSupports {
                // RoomVersionFeatures::ExtensibleEvents.as_str(), ideally
                feature: Cow::Borrowed("org.matrix.msc3932.extensible_events"),
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, SOUND_ACTION, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed(
            "global/underride/.org.matrix.msc3933.rule.extensible.audio.room_one_to_one",
        ),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                // MSC3933: Type changed from template rule - see MSC.
                pattern: Some(Cow::Borrowed("org.matrix.msc1767.audio")),
                pattern_type: None,
            })),
            Condition::Known(KnownCondition::RoomMemberCount {
                is: Some(Cow::Borrowed("2")),
            }),
            // MSC3933: Add condition on top of template rule - see MSC.
            Condition::Known(KnownCondition::RoomVersionSupports {
                // RoomVersionFeatures::ExtensibleEvents.as_str(), ideally
                feature: Cow::Borrowed("org.matrix.msc3932.extensible_events"),
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, SOUND_ACTION, HIGHLIGHT_FALSE_ACTION]),
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
        rule_id: Cow::Borrowed("global/underride/.org.matrix.msc1767.rule.extensible.encrypted"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                // MSC3933: Type changed from template rule - see MSC.
                pattern: Some(Cow::Borrowed("m.encrypted")),
                pattern_type: None,
            })),
            // MSC3933: Add condition on top of template rule - see MSC.
            Condition::Known(KnownCondition::RoomVersionSupports {
                // RoomVersionFeatures::ExtensibleEvents.as_str(), ideally
                feature: Cow::Borrowed("org.matrix.msc3932.extensible_events"),
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/underride/.org.matrix.msc1767.rule.extensible.message"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                // MSC3933: Type changed from template rule - see MSC.
                pattern: Some(Cow::Borrowed("m.message")),
                pattern_type: None,
            })),
            // MSC3933: Add condition on top of template rule - see MSC.
            Condition::Known(KnownCondition::RoomVersionSupports {
                // RoomVersionFeatures::ExtensibleEvents.as_str(), ideally
                feature: Cow::Borrowed("org.matrix.msc3932.extensible_events"),
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/underride/.org.matrix.msc1767.rule.extensible.file"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                // MSC3933: Type changed from template rule - see MSC.
                pattern: Some(Cow::Borrowed("m.file")),
                pattern_type: None,
            })),
            // MSC3933: Add condition on top of template rule - see MSC.
            Condition::Known(KnownCondition::RoomVersionSupports {
                // RoomVersionFeatures::ExtensibleEvents.as_str(), ideally
                feature: Cow::Borrowed("org.matrix.msc3932.extensible_events"),
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/underride/.org.matrix.msc1767.rule.extensible.image"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                // MSC3933: Type changed from template rule - see MSC.
                pattern: Some(Cow::Borrowed("m.image")),
                pattern_type: None,
            })),
            // MSC3933: Add condition on top of template rule - see MSC.
            Condition::Known(KnownCondition::RoomVersionSupports {
                // RoomVersionFeatures::ExtensibleEvents.as_str(), ideally
                feature: Cow::Borrowed("org.matrix.msc3932.extensible_events"),
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/underride/.org.matrix.msc1767.rule.extensible.video"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                // MSC3933: Type changed from template rule - see MSC.
                pattern: Some(Cow::Borrowed("m.video")),
                pattern_type: None,
            })),
            // MSC3933: Add condition on top of template rule - see MSC.
            Condition::Known(KnownCondition::RoomVersionSupports {
                // RoomVersionFeatures::ExtensibleEvents.as_str(), ideally
                feature: Cow::Borrowed("org.matrix.msc3932.extensible_events"),
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/underride/.org.matrix.msc1767.rule.extensible.audio"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                // MSC3933: Type changed from template rule - see MSC.
                pattern: Some(Cow::Borrowed("m.audio")),
                pattern_type: None,
            })),
            // MSC3933: Add condition on top of template rule - see MSC.
            Condition::Known(KnownCondition::RoomVersionSupports {
                // RoomVersionFeatures::ExtensibleEvents.as_str(), ideally
                feature: Cow::Borrowed("org.matrix.msc3932.extensible_events"),
            }),
        ]),
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
