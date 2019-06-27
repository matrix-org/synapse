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

import attr

from twisted.internet import defer

from synapse.api.constants import MAX_DEPTH
from synapse.api.errors import UnsupportedRoomVersionError
from synapse.api.room_versions import (
    KNOWN_EVENT_FORMAT_VERSIONS,
    KNOWN_ROOM_VERSIONS,
    EventFormatVersions,
)
from synapse.crypto.event_signing import add_hashes_and_signatures
from synapse.types import EventID
from synapse.util.stringutils import random_string

from . import _EventInternalMetadata, event_type_from_format_version


@attr.s(slots=True, cmp=False, frozen=True)
class EventBuilder(object):
    """A format independent event builder used to build up the event content
    before signing the event.

    (Note that while objects of this class are frozen, the
    content/unsigned/internal_metadata fields are still mutable)

    Attributes:
        format_version (int): Event format version
        room_id (str)
        type (str)
        sender (str)
        content (dict)
        unsigned (dict)
        internal_metadata (_EventInternalMetadata)

        _state (StateHandler)
        _auth (synapse.api.Auth)
        _store (DataStore)
        _clock (Clock)
        _hostname (str): The hostname of the server creating the event
        _signing_key: The signing key to use to sign the event as the server
    """

    _state = attr.ib()
    _auth = attr.ib()
    _store = attr.ib()
    _clock = attr.ib()
    _hostname = attr.ib()
    _signing_key = attr.ib()

    format_version = attr.ib()

    room_id = attr.ib()
    type = attr.ib()
    sender = attr.ib()

    content = attr.ib(default=attr.Factory(dict))
    unsigned = attr.ib(default=attr.Factory(dict))

    # These only exist on a subset of events, so they raise AttributeError if
    # someone tries to get them when they don't exist.
    _state_key = attr.ib(default=None)
    _redacts = attr.ib(default=None)
    _origin_server_ts = attr.ib(default=None)

    internal_metadata = attr.ib(
        default=attr.Factory(lambda: _EventInternalMetadata({}))
    )

    @property
    def state_key(self):
        if self._state_key is not None:
            return self._state_key

        raise AttributeError("state_key")

    def is_state(self):
        return self._state_key is not None

    @defer.inlineCallbacks
    def build(self, prev_event_ids):
        """Transform into a fully signed and hashed event

        Args:
            prev_event_ids (list[str]): The event IDs to use as the prev events

        Returns:
            Deferred[FrozenEvent]
        """

        state_ids = yield self._state.get_current_state_ids(
            self.room_id, prev_event_ids
        )
        auth_ids = yield self._auth.compute_auth_events(self, state_ids)

        if self.format_version == EventFormatVersions.V1:
            auth_events = yield self._store.add_event_hashes(auth_ids)
            prev_events = yield self._store.add_event_hashes(prev_event_ids)
        else:
            auth_events = auth_ids
            prev_events = prev_event_ids

        old_depth = yield self._store.get_max_depth_of(prev_event_ids)
        depth = old_depth + 1

        # we cap depth of generated events, to ensure that they are not
        # rejected by other servers (and so that they can be persisted in
        # the db)
        depth = min(depth, MAX_DEPTH)

        event_dict = {
            "auth_events": auth_events,
            "prev_events": prev_events,
            "type": self.type,
            "room_id": self.room_id,
            "sender": self.sender,
            "content": self.content,
            "unsigned": self.unsigned,
            "depth": depth,
            "prev_state": [],
        }

        if self.is_state():
            event_dict["state_key"] = self._state_key

        if self._redacts is not None:
            event_dict["redacts"] = self._redacts

        if self._origin_server_ts is not None:
            event_dict["origin_server_ts"] = self._origin_server_ts

        defer.returnValue(
            create_local_event_from_event_dict(
                clock=self._clock,
                hostname=self._hostname,
                signing_key=self._signing_key,
                format_version=self.format_version,
                event_dict=event_dict,
                internal_metadata_dict=self.internal_metadata.get_dict(),
            )
        )


class EventBuilderFactory(object):
    def __init__(self, hs):
        self.clock = hs.get_clock()
        self.hostname = hs.hostname
        self.signing_key = hs.config.signing_key[0]

        self.store = hs.get_datastore()
        self.state = hs.get_state_handler()
        self.auth = hs.get_auth()

    def new(self, room_version, key_values):
        """Generate an event builder appropriate for the given room version

        Deprecated: use for_room_version with a RoomVersion object instead

        Args:
            room_version (str): Version of the room that we're creating an event builder
                for
            key_values (dict): Fields used as the basis of the new event

        Returns:
            EventBuilder
        """
        v = KNOWN_ROOM_VERSIONS.get(room_version)
        if not v:
            # this can happen if support is withdrawn for a room version
            raise UnsupportedRoomVersionError()
        return self.for_room_version(v, key_values)

    def for_room_version(self, room_version, key_values):
        """Generate an event builder appropriate for the given room version

        Args:
            room_version (synapse.api.room_versions.RoomVersion):
                Version of the room that we're creating an event builder for
            key_values (dict): Fields used as the basis of the new event

        Returns:
            EventBuilder
        """
        return EventBuilder(
            store=self.store,
            state=self.state,
            auth=self.auth,
            clock=self.clock,
            hostname=self.hostname,
            signing_key=self.signing_key,
            format_version=room_version.event_format,
            type=key_values["type"],
            state_key=key_values.get("state_key"),
            room_id=key_values["room_id"],
            sender=key_values["sender"],
            content=key_values.get("content", {}),
            unsigned=key_values.get("unsigned", {}),
            redacts=key_values.get("redacts", None),
            origin_server_ts=key_values.get("origin_server_ts", None),
        )


def create_local_event_from_event_dict(
    clock,
    hostname,
    signing_key,
    format_version,
    event_dict,
    internal_metadata_dict=None,
):
    """Takes a fully formed event dict, ensuring that fields like `origin`
    and `origin_server_ts` have correct values for a locally produced event,
    then signs and hashes it.

    Args:
        clock (Clock)
        hostname (str)
        signing_key
        format_version (int)
        event_dict (dict)
        internal_metadata_dict (dict|None)

    Returns:
        FrozenEvent
    """

    if format_version not in KNOWN_EVENT_FORMAT_VERSIONS:
        raise Exception("No event format defined for version %r" % (format_version,))

    if internal_metadata_dict is None:
        internal_metadata_dict = {}

    time_now = int(clock.time_msec())

    if format_version == EventFormatVersions.V1:
        event_dict["event_id"] = _create_event_id(clock, hostname)

    event_dict["origin"] = hostname
    event_dict.setdefault("origin_server_ts", time_now)

    event_dict.setdefault("unsigned", {})
    age = event_dict["unsigned"].pop("age", 0)
    event_dict["unsigned"].setdefault("age_ts", time_now - age)

    event_dict.setdefault("signatures", {})

    add_hashes_and_signatures(event_dict, hostname, signing_key)
    return event_type_from_format_version(format_version)(
        event_dict, internal_metadata_dict=internal_metadata_dict
    )


# A counter used when generating new event IDs
_event_id_counter = 0


def _create_event_id(clock, hostname):
    """Create a new event ID

    Args:
        clock (Clock)
        hostname (str): The server name for the event ID

    Returns:
        str
    """

    global _event_id_counter

    i = str(_event_id_counter)
    _event_id_counter += 1

    local_part = str(int(clock.time())) + i + random_string(5)

    e_id = EventID(local_part, hostname)

    return e_id.to_string()
