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
        ("events_type", "topological_key", "stream_key", "presence_key")
    )
):
    _SEPARATOR = "_"

    _TOPOLOGICAL_PREFIX = "t"
    _STREAM_PREFIX = "s"

    _TOPOLOGICAL_SEPERATOR = "-"

    TOPOLOGICAL_TYPE = "topo"
    STREAM_TYPE = "stream"

    @classmethod
    def from_string(cls, string):
        try:
            events_part, presence_part = string.split(cls._SEPARATOR)

            presence_key = int(presence_part)

            topo_length = len(cls._TOPOLOGICAL_PREFIX)
            stream_length = len(cls._STREAM_PREFIX)
            if events_part[:topo_length] == cls._TOPOLOGICAL_PREFIX:
                # topological event token
                topo_tok = events_part[topo_length:]
                topo_key, stream_key = topo_tok.split(
                    cls._TOPOLOGICAL_SEPERATOR, 1
                )

                topo_key = int(topo_key)
                stream_key = int(stream_key)

                events_type = cls.TOPOLOGICAL_TYPE
            elif events_part[:stream_length] == cls._STREAM_PREFIX:
                topo_key = None
                stream_key = int(events_part[stream_length:])

                events_type = cls.STREAM_TYPE
            else:
                raise

            return cls(
                events_type=events_type,
                topological_key=topo_key,
                stream_key=stream_key,
                presence_key=presence_key,
            )
        except:
            raise SynapseError(400, "Invalid Token")

    def to_string(self):
        if self.events_type == self.TOPOLOGICAL_TYPE:
            return "".join([
                self._TOPOLOGICAL_PREFIX,
                str(self.topological_key),
                self._TOPOLOGICAL_SEPERATOR,
                str(self.stream_key),
                self._SEPARATOR,
                str(self.presence_key),
            ])
        elif self.events_type == self.STREAM_TYPE:
            return "".join([
                self._STREAM_PREFIX,
                str(self.stream_key),
                self._SEPARATOR,
                str(self.presence_key),
            ])

        raise RuntimeError("Unrecognized event type: %s", self.events_type)
