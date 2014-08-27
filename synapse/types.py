# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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


class DomainSpecificString(
        namedtuple("DomainSpecificString", ("localpart", "domain", "is_mine"))
):
    """Common base class among ID/name strings that have a local part and a
    domain name, prefixed with a sigil.

    Has the fields:

        'localpart' : The local part of the name (without the leading sigil)
        'domain' : The domain part of the name
        'is_mine' : Boolean indicating if the domain name is recognised by the
            HomeServer as being its own
    """

    # Deny iteration because it will bite you if you try to create a singleton
    # set by:
    #    users = set(user)
    def __iter__(self):
        raise ValueError("Attempted to iterate a %s" % (type(self).__name__))

    # Because this class is a namedtuple of strings and booleans, it is deeply
    # immutable.
    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self

    @classmethod
    def from_string(cls, s, hs):
        """Parse the string given by 's' into a structure object."""
        if s[0] != cls.SIGIL:
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
        is_mine = domain == hs.hostname
        return cls(localpart=parts[0], domain=domain, is_mine=is_mine)

    def to_string(self):
        """Return a string encoding the fields of the structure object."""
        return "%s%s:%s" % (self.SIGIL, self.localpart, self.domain)

    @classmethod
    def create_local(cls, localpart, hs):
        """Create a structure on the local domain"""
        return cls(localpart=localpart, domain=hs.hostname, is_mine=True)


class UserID(DomainSpecificString):
    """Structure representing a user ID."""
    SIGIL = "@"


class RoomAlias(DomainSpecificString):
    """Structure representing a room name."""
    SIGIL = "#"


class RoomID(DomainSpecificString):
    """Structure representing a room id. """
    SIGIL = "!"


class StreamToken(
    namedtuple(
        "Token",
        ("events_key", "presence_key")
    )
):
    _SEPARATOR = "_"

    @classmethod
    def from_string(cls, string):
        try:
            events_key, presence_key = string.split(cls._SEPARATOR)

            return cls(
                events_key=events_key,
                presence_key=presence_key,
            )
        except:
            raise SynapseError(400, "Invalid Token")

    def to_string(self):
        return "".join([
            str(self.events_key),
            self._SEPARATOR,
            str(self.presence_key),
        ])

    def copy_and_replace(self, key, new_value):
        d = self._asdict()
        d[key] = new_value
        return StreamToken(**d)
