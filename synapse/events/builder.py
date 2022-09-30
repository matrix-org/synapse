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
import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple, Union

import attr
from signedjson.types import SigningKey

from synapse.api.constants import MAX_DEPTH
from synapse.api.room_versions import (
    KNOWN_EVENT_FORMAT_VERSIONS,
    EventFormatVersions,
    RoomVersion,
)
from synapse.crypto.event_signing import add_hashes_and_signatures
from synapse.event_auth import auth_types_for_event
from synapse.events import EventBase, _EventInternalMetadata, make_event_from_dict
from synapse.state import StateHandler
from synapse.storage.databases.main import DataStore
from synapse.storage.state import StateFilter
from synapse.types import EventID, JsonDict
from synapse.util import Clock
from synapse.util.stringutils import random_string

if TYPE_CHECKING:
    from synapse.handlers.event_auth import EventAuthHandler
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


@attr.s(slots=True, cmp=False, frozen=True, auto_attribs=True)
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

    _state: StateHandler
    _event_auth_handler: "EventAuthHandler"
    _store: DataStore
    _clock: Clock
    _hostname: str
    _signing_key: SigningKey

    room_version: RoomVersion

    room_id: str
    type: str
    sender: str

    content: JsonDict = attr.Factory(dict)
    unsigned: JsonDict = attr.Factory(dict)

    # These only exist on a subset of events, so they raise AttributeError if
    # someone tries to get them when they don't exist.
    _state_key: Optional[str] = None
    _redacts: Optional[str] = None
    _origin_server_ts: Optional[int] = None

    internal_metadata: _EventInternalMetadata = attr.Factory(
        lambda: _EventInternalMetadata({})
    )

    @property
    def state_key(self) -> str:
        if self._state_key is not None:
            return self._state_key

        raise AttributeError("state_key")

    def is_state(self) -> bool:
        return self._state_key is not None

    async def build(
        self,
        prev_event_ids: List[str],
        auth_event_ids: Optional[List[str]],
        depth: Optional[int] = None,
    ) -> EventBase:
        """Transform into a fully signed and hashed event

        Args:
            prev_event_ids: The event IDs to use as the prev events
            auth_event_ids: The event IDs to use as the auth events.
                Should normally be set to None, which will cause them to be calculated
                based on the room state at the prev_events.
            depth: Override the depth used to order the event in the DAG.
                Should normally be set to None, which will cause the depth to be calculated
                based on the prev_events.

        Returns:
            The signed and hashed event.
        """
        if auth_event_ids is None:
            state_ids = await self._state.compute_state_after_events(
                self.room_id,
                prev_event_ids,
                state_filter=StateFilter.from_types(
                    auth_types_for_event(self.room_version, self)
                ),
            )
            auth_event_ids = self._event_auth_handler.compute_auth_events(
                self, state_ids
            )

        format_version = self.room_version.event_format
        # The types of auth/prev events changes between event versions.
        prev_events: Union[List[str], List[Tuple[str, Dict[str, str]]]]
        auth_events: Union[List[str], List[Tuple[str, Dict[str, str]]]]
        if format_version == EventFormatVersions.ROOM_V1_V2:
            auth_events = await self._store.add_event_hashes(auth_event_ids)
            prev_events = await self._store.add_event_hashes(prev_event_ids)
        else:
            auth_events = auth_event_ids
            prev_events = prev_event_ids

        # Otherwise, progress the depth as normal
        if depth is None:
            (
                _,
                most_recent_prev_event_depth,
            ) = await self._store.get_max_depth_of(prev_event_ids)

            depth = most_recent_prev_event_depth + 1

        # we cap depth of generated events, to ensure that they are not
        # rejected by other servers (and so that they can be persisted in
        # the db)
        depth = min(depth, MAX_DEPTH)

        event_dict: Dict[str, Any] = {
            "auth_events": auth_events,
            "prev_events": prev_events,
            "type": self.type,
            "room_id": self.room_id,
            "sender": self.sender,
            "content": self.content,
            "unsigned": self.unsigned,
            "depth": depth,
        }

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
    def __init__(self, hs: "HomeServer"):
        self.clock = hs.get_clock()
        self.hostname = hs.hostname
        self.signing_key = hs.signing_key

        self.store = hs.get_datastores().main
        self.state = hs.get_state_handler()
        self._event_auth_handler = hs.get_event_auth_handler()

    def for_room_version(
        self, room_version: RoomVersion, key_values: dict
    ) -> EventBuilder:
        """Generate an event builder appropriate for the given room version

        Args:
            room_version:
                Version of the room that we're creating an event builder for
            key_values: Fields used as the basis of the new event

        Returns:
            EventBuilder
        """
        return EventBuilder(
            store=self.store,
            state=self.state,
            event_auth_handler=self._event_auth_handler,
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

    if format_version == EventFormatVersions.ROOM_V1_V2:
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


def _create_event_id(clock: Clock, hostname: str) -> str:
    """Create a new event ID

    Args:
        clock
        hostname: The server name for the event ID

    Returns:
        The new event ID
    """

    global _event_id_counter

    i = str(_event_id_counter)
    _event_id_counter += 1

    local_part = str(int(clock.time())) + i + random_string(5)

    e_id = EventID(local_part, hostname)

    return e_id.to_string()
