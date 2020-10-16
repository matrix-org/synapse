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
from typing import Any, Dict, List, Optional, Tuple, Union

import attr
from nacl.signing import SigningKey

from synapse.api.auth import Auth
from synapse.api.constants import MAX_DEPTH
from synapse.api.errors import UnsupportedRoomVersionError
from synapse.api.room_versions import (
    KNOWN_EVENT_FORMAT_VERSIONS,
    KNOWN_ROOM_VERSIONS,
    EventFormatVersions,
    RoomVersion,
)
from synapse.crypto.event_signing import add_hashes_and_signatures
from synapse.events import EventBase, _EventInternalMetadata, make_event_from_dict
from synapse.state import StateHandler
from synapse.storage.databases.main import DataStore
from synapse.types import EventID, JsonDict
from synapse.util import Clock
from synapse.util.stringutils import random_string


@attr.s(slots=True, cmp=False, frozen=True)
class EventBuilder:
    """A format independent event builder used to build up the event content
    before signing the event.

    (Note that while objects of this class are frozen, the
    content/unsigned/internal_metadata fields are still mutable)

    Attributes:
        room_version: Version of the target room
        room_id
        type
        sender
        content
        unsigned
        internal_metadata

        _state
        _auth
        _store
        _clock
        _hostname: The hostname of the server creating the event
        _signing_key: The signing key to use to sign the event as the server
    """

    _state = attr.ib(type=StateHandler)
    _auth = attr.ib(type=Auth)
    _store = attr.ib(type=DataStore)
    _clock = attr.ib(type=Clock)
    _hostname = attr.ib(type=str)
    _signing_key = attr.ib(type=SigningKey)

    room_version = attr.ib(type=RoomVersion)

    room_id = attr.ib(type=str)
    type = attr.ib(type=str)
    sender = attr.ib(type=str)

    content = attr.ib(default=attr.Factory(dict), type=JsonDict)
    unsigned = attr.ib(default=attr.Factory(dict), type=JsonDict)

    # These only exist on a subset of events, so they raise AttributeError if
    # someone tries to get them when they don't exist.
    _state_key = attr.ib(default=None, type=Optional[str])
    _redacts = attr.ib(default=None, type=Optional[str])
    _origin_server_ts = attr.ib(default=None, type=Optional[int])

    internal_metadata = attr.ib(
        default=attr.Factory(lambda: _EventInternalMetadata({})),
        type=_EventInternalMetadata,
    )

    @property
    def state_key(self):
        if self._state_key is not None:
            return self._state_key

        raise AttributeError("state_key")

    def is_state(self):
        return self._state_key is not None

    async def build(
        self, prev_event_ids: List[str], auth_event_ids: Optional[List[str]],
    ) -> EventBase:
        """Transform into a fully signed and hashed event

        Args:
            prev_event_ids: The event IDs to use as the prev events
            auth_event_ids: The event IDs to use as the auth events.
                Should normally be set to None, which will cause them to be calculated
                based on the room state at the prev_events.

        Returns:
            The signed and hashed event.
        """
        if auth_event_ids is None:
            state_ids = await self._state.get_current_state_ids(
                self.room_id, prev_event_ids
            )
            auth_event_ids = self._auth.compute_auth_events(self, state_ids)

        format_version = self.room_version.event_format
        if format_version == EventFormatVersions.V1:
            # The types of auth/prev events changes between event versions.
            auth_events = await self._store.add_event_hashes(
                auth_event_ids
            )  # type: Union[List[str], List[Tuple[str, Dict[str, str]]]]
            prev_events = await self._store.add_event_hashes(
                prev_event_ids
            )  # type: Union[List[str], List[Tuple[str, Dict[str, str]]]]
        else:
            auth_events = auth_event_ids
            prev_events = prev_event_ids

        old_depth = await self._store.get_max_depth_of(prev_event_ids)
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
        }  # type: Dict[str, Any]

        if self.is_state():
            event_dict["state_key"] = self._state_key

        if self._redacts is not None:
            event_dict["redacts"] = self._redacts

        if self._origin_server_ts is not None:
            event_dict["origin_server_ts"] = self._origin_server_ts

        return create_local_event_from_event_dict(
            clock=self._clock,
            hostname=self._hostname,
            signing_key=self._signing_key,
            room_version=self.room_version,
            event_dict=event_dict,
            internal_metadata_dict=self.internal_metadata.get_dict(),
        )


class EventBuilderFactory:
    def __init__(self, hs):
        self.clock = hs.get_clock()
        self.hostname = hs.hostname
        self.signing_key = hs.signing_key

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
            room_version=room_version,
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
    clock: Clock,
    hostname: str,
    signing_key: SigningKey,
    room_version: RoomVersion,
    event_dict: JsonDict,
    internal_metadata_dict: Optional[JsonDict] = None,
) -> EventBase:
    """Takes a fully formed event dict, ensuring that fields like `origin`
    and `origin_server_ts` have correct values for a locally produced event,
    then signs and hashes it.
    """

    format_version = room_version.event_format
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

    add_hashes_and_signatures(room_version, event_dict, hostname, signing_key)
    return make_event_from_dict(
        event_dict, room_version, internal_metadata_dict=internal_metadata_dict
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
