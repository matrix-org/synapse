# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
# Copyright 2018 New Vector Ltd.
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
MAX_DEPTH = 2**63 - 1


class Membership(object):

    """Represents the membership states of a user in a room."""
    INVITE = u"invite"
    JOIN = u"join"
    KNOCK = u"knock"
    LEAVE = u"leave"
    BAN = u"ban"
    LIST = (INVITE, JOIN, KNOCK, LEAVE, BAN)


class PresenceState(object):
    """Represents the presence state of a user."""
    OFFLINE = u"offline"
    UNAVAILABLE = u"unavailable"
    ONLINE = u"online"


class JoinRules(object):
    PUBLIC = u"public"
    KNOCK = u"knock"
    INVITE = u"invite"
    PRIVATE = u"private"


class LoginType(object):
    PASSWORD = u"m.login.password"
    EMAIL_IDENTITY = u"m.login.email.identity"
    MSISDN = u"m.login.msisdn"
    RECAPTCHA = u"m.login.recaptcha"
    DUMMY = u"m.login.dummy"

    # Only for C/S API v1
    APPLICATION_SERVICE = u"m.login.application_service"
    SHARED_SECRET = u"org.matrix.login.shared_secret"


class EventTypes(object):
    Member = "m.room.member"
    Create = "m.room.create"
    JoinRules = "m.room.join_rules"
    PowerLevels = "m.room.power_levels"
    Aliases = "m.room.aliases"
    Redaction = "m.room.redaction"
    ThirdPartyInvite = "m.room.third_party_invite"

    RoomHistoryVisibility = "m.room.history_visibility"
    CanonicalAlias = "m.room.canonical_alias"
    RoomAvatar = "m.room.avatar"
    GuestAccess = "m.room.guest_access"

    # These are used for validation
    Message = "m.room.message"
    Topic = "m.room.topic"
    Name = "m.room.name"

    ServerACL = "m.room.server_acl"
    Pinned = "m.room.pinned_events"


class RejectedReason(object):
    AUTH_ERROR = "auth_error"
    REPLACED = "replaced"
    NOT_ANCESTOR = "not_ancestor"


class RoomCreationPreset(object):
    PRIVATE_CHAT = "private_chat"
    PUBLIC_CHAT = "public_chat"
    TRUSTED_PRIVATE_CHAT = "trusted_private_chat"


class ThirdPartyEntityKind(object):
    USER = "user"
    LOCATION = "location"


class RoomVersions(object):
    V1 = "1"
    VDH_TEST = "vdh-test-version"


# the version we will give rooms which are created on this server
DEFAULT_ROOM_VERSION = RoomVersions.V1

# vdh-test-version is a placeholder to get room versioning support working and tested
# until we have a working v2.
KNOWN_ROOM_VERSIONS = {RoomVersions.V1, RoomVersions.VDH_TEST}

ServerNoticeMsgType = "m.server_notice"
ServerNoticeLimitReached = "m.server_notice.usage_limit_reached"
