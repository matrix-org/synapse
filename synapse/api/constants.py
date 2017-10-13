# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
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


class Membership(object):

    """Represents the membership states of a user in a room."""
    INVITE = "invite"
    JOIN = "join"
    KNOCK = "knock"
    LEAVE = "leave"
    BAN = "ban"
    LIST = (INVITE, JOIN, KNOCK, LEAVE, BAN)


class PresenceState(object):
    """Represents the presence state of a user."""
    OFFLINE = "offline"
    UNAVAILABLE = "unavailable"
    ONLINE = "online"


class JoinRules(object):
    PUBLIC = "public"
    KNOCK = "knock"
    INVITE = "invite"
    PRIVATE = "private"


class LoginType(object):
    PASSWORD = "m.login.password"
    EMAIL_IDENTITY = "m.login.email.identity"
    MSISDN = "m.login.msisdn"
    RECAPTCHA = "m.login.recaptcha"
    DUMMY = "m.login.dummy"

    # Only for C/S API v1
    APPLICATION_SERVICE = "m.login.application_service"
    SHARED_SECRET = "org.matrix.login.shared_secret"


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
