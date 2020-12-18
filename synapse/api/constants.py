# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
# Copyright 2018-2019 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Contains constants from the specification."""

# the "depth" field on events is limited to 2**63 - 1
MAX_DEPTH = 2 ** 63 - 1

# the maximum length for a room alias is 255 characters
MAX_ALIAS_LENGTH = 255

# the maximum length for a user id is 255 characters
MAX_USERID_LENGTH = 255


class Membership:

    """Represents the membership states of a user in a room."""

    INVITE = "invite"
    JOIN = "join"
    KNOCK = "knock"
    LEAVE = "leave"
    BAN = "ban"
    LIST = (INVITE, JOIN, KNOCK, LEAVE, BAN)


class PresenceState:
    """Represents the presence state of a user."""

    OFFLINE = "offline"
    UNAVAILABLE = "unavailable"
    ONLINE = "online"


class JoinRules:
    PUBLIC = "public"
    KNOCK = "knock"
    INVITE = "invite"
    PRIVATE = "private"


class LoginType:
    PASSWORD = "m.login.password"
    EMAIL_IDENTITY = "m.login.email.identity"
    MSISDN = "m.login.msisdn"
    RECAPTCHA = "m.login.recaptcha"
    TERMS = "m.login.terms"
    SSO = "m.login.sso"
    DUMMY = "m.login.dummy"


class EventTypes:
    Member = "m.room.member"
    Create = "m.room.create"
    Tombstone = "m.room.tombstone"
    JoinRules = "m.room.join_rules"
    PowerLevels = "m.room.power_levels"
    Aliases = "m.room.aliases"
    Redaction = "m.room.redaction"
    ThirdPartyInvite = "m.room.third_party_invite"
    RelatedGroups = "m.room.related_groups"

    RoomHistoryVisibility = "m.room.history_visibility"
    CanonicalAlias = "m.room.canonical_alias"
    Encrypted = "m.room.encrypted"
    RoomAvatar = "m.room.avatar"
    RoomEncryption = "m.room.encryption"
    GuestAccess = "m.room.guest_access"

    # These are used for validation
    Message = "m.room.message"
    Topic = "m.room.topic"
    Name = "m.room.name"

    ServerACL = "m.room.server_acl"
    Pinned = "m.room.pinned_events"

    Retention = "m.room.retention"

    Presence = "m.presence"

    Dummy = "org.matrix.dummy_event"


class RejectedReason:
    AUTH_ERROR = "auth_error"


class RoomCreationPreset:
    PRIVATE_CHAT = "private_chat"
    PUBLIC_CHAT = "public_chat"
    TRUSTED_PRIVATE_CHAT = "trusted_private_chat"


class ThirdPartyEntityKind:
    USER = "user"
    LOCATION = "location"


ServerNoticeMsgType = "m.server_notice"
ServerNoticeLimitReached = "m.server_notice.usage_limit_reached"


class UserTypes:
    """Allows for user type specific behaviour. With the benefit of hindsight
    'admin' and 'guest' users should also be UserTypes. Normal users are type None
    """

    SUPPORT = "support"
    BOT = "bot"
    ALL_USER_TYPES = (SUPPORT, BOT)


class RelationTypes:
    """The types of relations known to this server.
    """

    ANNOTATION = "m.annotation"
    REPLACE = "m.replace"
    REFERENCE = "m.reference"


class LimitBlockingTypes:
    """Reasons that a server may be blocked"""

    MONTHLY_ACTIVE_USER = "monthly_active_user"
    HS_DISABLED = "hs_disabled"


class EventContentFields:
    """Fields found in events' content, regardless of type."""

    # Labels for the event, cf https://github.com/matrix-org/matrix-doc/pull/2326
    LABELS = "org.matrix.labels"

    # Timestamp to delete the event after
    # cf https://github.com/matrix-org/matrix-doc/pull/2228
    SELF_DESTRUCT_AFTER = "org.matrix.self_destruct_after"


class RoomEncryptionAlgorithms:
    MEGOLM_V1_AES_SHA2 = "m.megolm.v1.aes-sha2"
    DEFAULT = MEGOLM_V1_AES_SHA2


class AccountDataTypes:
    DIRECT = "m.direct"
    IGNORED_USER_LIST = "m.ignored_user_list"


class HistoryVisibility:
    INVITED = "invited"
    JOINED = "joined"
    SHARED = "shared"
    WORLD_READABLE = "world_readable"
