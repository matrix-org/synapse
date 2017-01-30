# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

from synapse.api.errors import SynapseError

from collections import namedtuple


Requester = namedtuple("Requester", [
    "user", "access_token_id", "is_guest", "device_id", "app_service",
])
"""
Represents the user making a request

Attributes:
    user (UserID):  id of the user making the request
    access_token_id (int|None):  *ID* of the access token used for this
        request, or None if it came via the appservice API or similar
    is_guest (bool):  True if the user making this request is a guest user
    device_id (str|None):  device_id which was set at authentication time
    app_service (ApplicationService|None):  the AS requesting on behalf of the user
"""


def create_requester(user_id, access_token_id=None, is_guest=False,
                     device_id=None, app_service=None):
    """
    Create a new ``Requester`` object

    Args:
        user_id (str|UserID):  id of the user making the request
        access_token_id (int|None):  *ID* of the access token used for this
            request, or None if it came via the appservice API or similar
        is_guest (bool):  True if the user making this request is a guest user
        device_id (str|None):  device_id which was set at authentication time
        app_service (ApplicationService|None):  the AS requesting on behalf of the user

    Returns:
        Requester
    """
    if not isinstance(user_id, UserID):
        user_id = UserID.from_string(user_id)
    return Requester(user_id, access_token_id, is_guest, device_id, app_service)


def get_domain_from_id(string):
    try:
        return string.split(":", 1)[1]
    except IndexError:
        raise SynapseError(400, "Invalid ID: %r" % (string,))


class DomainSpecificString(
        namedtuple("DomainSpecificString", ("localpart", "domain"))
):
    """Common base class among ID/name strings that have a local part and a
    domain name, prefixed with a sigil.

    Has the fields:

        'localpart' : The local part of the name (without the leading sigil)
        'domain' : The domain part of the name
    """

    # Deny iteration because it will bite you if you try to create a singleton
    # set by:
    #    users = set(user)
    def __iter__(self):
        raise ValueError("Attempted to iterate a %s" % (type(self).__name__,))

    # Because this class is a namedtuple of strings and booleans, it is deeply
    # immutable.
    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self

    @classmethod
    def from_string(cls, s):
        """Parse the string given by 's' into a structure object."""
        if len(s) < 1 or s[0] != cls.SIGIL:
            raise SynapseError(400, "Expected %s string to start with '%s'" % (
                cls.__name__, cls.SIGIL,
            ))

        parts = s[1:].split(':', 1)
        if len(parts) != 2:
            raise SynapseError(
                400, "Expected %s of the form '%slocalname:domain'" % (
                    cls.__name__, cls.SIGIL,
                )
            )

        domain = parts[1]

        # This code will need changing if we want to support multiple domain
        # names on one HS
        return cls(localpart=parts[0], domain=domain)

    def to_string(self):
        """Return a string encoding the fields of the structure object."""
        return "%s%s:%s" % (self.SIGIL, self.localpart, self.domain)

    @classmethod
    def is_valid(cls, s):
        try:
            cls.from_string(s)
            return True
        except:
            return False

    __str__ = to_string

    @classmethod
    def create(cls, localpart, domain,):
        return cls(localpart=localpart, domain=domain)


class UserID(DomainSpecificString):
    """Structure representing a user ID."""
    SIGIL = "@"


class RoomAlias(DomainSpecificString):
    """Structure representing a room name."""
    SIGIL = "#"


class RoomID(DomainSpecificString):
    """Structure representing a room id. """
    SIGIL = "!"


class EventID(DomainSpecificString):
    """Structure representing an event id. """
    SIGIL = "$"


class StreamToken(
    namedtuple("Token", (
        "room_key",
        "presence_key",
        "typing_key",
        "receipt_key",
        "account_data_key",
        "push_rules_key",
        "to_device_key",
        "device_list_key",
    ))
):
    _SEPARATOR = "_"

    @classmethod
    def from_string(cls, string):
        try:
            keys = string.split(cls._SEPARATOR)
            while len(keys) < len(cls._fields):
                # i.e. old token from before receipt_key
                keys.append("0")
            return cls(*keys)
        except:
            raise SynapseError(400, "Invalid Token")

    def to_string(self):
        return self._SEPARATOR.join([str(k) for k in self])

    @property
    def room_stream_id(self):
        # TODO(markjh): Awful hack to work around hacks in the presence tests
        # which assume that the keys are integers.
        if type(self.room_key) is int:
            return self.room_key
        else:
            return int(self.room_key[1:].split("-")[-1])

    def is_after(self, other):
        """Does this token contain events that the other doesn't?"""
        return (
            (other.room_stream_id < self.room_stream_id)
            or (int(other.presence_key) < int(self.presence_key))
            or (int(other.typing_key) < int(self.typing_key))
            or (int(other.receipt_key) < int(self.receipt_key))
            or (int(other.account_data_key) < int(self.account_data_key))
            or (int(other.push_rules_key) < int(self.push_rules_key))
            or (int(other.to_device_key) < int(self.to_device_key))
            or (int(other.device_list_key) < int(self.device_list_key))
        )

    def copy_and_advance(self, key, new_value):
        """Advance the given key in the token to a new value if and only if the
        new value is after the old value.
        """
        new_token = self.copy_and_replace(key, new_value)
        if key == "room_key":
            new_id = new_token.room_stream_id
            old_id = self.room_stream_id
        else:
            new_id = int(getattr(new_token, key))
            old_id = int(getattr(self, key))
        if old_id < new_id:
            return new_token
        else:
            return self

    def copy_and_replace(self, key, new_value):
        d = self._asdict()
        d[key] = new_value
        return StreamToken(**d)


StreamToken.START = StreamToken(
    *(["s0"] + ["0"] * (len(StreamToken._fields) - 1))
)


class RoomStreamToken(namedtuple("_StreamToken", "topological stream")):
    """Tokens are positions between events. The token "s1" comes after event 1.

            s0    s1
            |     |
        [0] V [1] V [2]

    Tokens can either be a point in the live event stream or a cursor going
    through historic events.

    When traversing the live event stream events are ordered by when they
    arrived at the homeserver.

    When traversing historic events the events are ordered by their depth in
    the event graph "topological_ordering" and then by when they arrived at the
    homeserver "stream_ordering".

    Live tokens start with an "s" followed by the "stream_ordering" id of the
    event it comes after. Historic tokens start with a "t" followed by the
    "topological_ordering" id of the event it comes after, followed by "-",
    followed by the "stream_ordering" id of the event it comes after.
    """
    __slots__ = []

    @classmethod
    def parse(cls, string):
        try:
            if string[0] == 's':
                return cls(topological=None, stream=int(string[1:]))
            if string[0] == 't':
                parts = string[1:].split('-', 1)
                return cls(topological=int(parts[0]), stream=int(parts[1]))
        except:
            pass
        raise SynapseError(400, "Invalid token %r" % (string,))

    @classmethod
    def parse_stream_token(cls, string):
        try:
            if string[0] == 's':
                return cls(topological=None, stream=int(string[1:]))
        except:
            pass
        raise SynapseError(400, "Invalid token %r" % (string,))

    def __str__(self):
        if self.topological is not None:
            return "t%d-%d" % (self.topological, self.stream)
        else:
            return "s%d" % (self.stream,)


class ThirdPartyInstanceID(
        namedtuple("ThirdPartyInstanceID", ("appservice_id", "network_id"))
):
    # Deny iteration because it will bite you if you try to create a singleton
    # set by:
    #    users = set(user)
    def __iter__(self):
        raise ValueError("Attempted to iterate a %s" % (type(self).__name__,))

    # Because this class is a namedtuple of strings, it is deeply immutable.
    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self

    @classmethod
    def from_string(cls, s):
        bits = s.split("|", 2)
        if len(bits) != 2:
            raise SynapseError(400, "Invalid ID %r" % (s,))

        return cls(appservice_id=bits[0], network_id=bits[1])

    def to_string(self):
        return "%s|%s" % (self.appservice_id, self.network_id,)

    __str__ = to_string

    @classmethod
    def create(cls, appservice_id, network_id,):
        return cls(appservice_id=appservice_id, network_id=network_id)
