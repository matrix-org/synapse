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

import abc
import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

from synapse.api.constants import Membership
from synapse.events import EventBase
from synapse.types import JsonDict, RoomStreamToken, StateMap, UserID
from synapse.visibility import filter_events_for_client

from ._base import BaseHandler

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class AdminHandler(BaseHandler):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.storage = hs.get_storage()
        self.state_store = self.storage.state

    async def get_whois(self, user: UserID) -> JsonDict:
        connections = []

        sessions = await self.store.get_user_ip_and_agents(user)
        for session in sessions:
            connections.append(
                {
                    "ip": session["ip"],
                    "last_seen": session["last_seen"],
                    "user_agent": session["user_agent"],
                }
            )

        ret = {
            "user_id": user.to_string(),
            "devices": {"": {"sessions": [{"connections": connections}]}},
        }

        return ret

    async def get_user(self, user: UserID) -> Optional[JsonDict]:
        """Function to get user details"""
        ret = await self.store.get_user_by_id(user.to_string())
        if ret:
            profile = await self.store.get_profileinfo(user.localpart)
            threepids = await self.store.user_get_threepids(user.to_string())
            external_ids = [
                ({"auth_provider": auth_provider, "external_id": external_id})
                for auth_provider, external_id in await self.store.get_external_ids_by_user(
                    user.to_string()
                )
            ]
            ret["displayname"] = profile.display_name
            ret["avatar_url"] = profile.avatar_url
            ret["threepids"] = threepids
            ret["external_ids"] = external_ids
        return ret

    async def export_user_data(self, user_id: str, writer: "ExfiltrationWriter") -> Any:
        """Write all data we have on the user to the given writer.

        Args:
            user_id: The user ID to fetch data of.
            writer: The writer to write to.

        Returns:
            Resolves when all data for a user has been written.
            The returned value is that returned by `writer.finished()`.
        """
        # Get all rooms the user is in or has been in
        rooms = await self.store.get_rooms_for_local_user_where_membership_is(
            user_id,
            membership_list=(
                Membership.JOIN,
                Membership.LEAVE,
                Membership.BAN,
                Membership.INVITE,
            ),
        )

        # We only try and fetch events for rooms the user has been in. If
        # they've been e.g. invited to a room without joining then we handle
        # those separately.
        rooms_user_has_been_in = await self.store.get_rooms_user_has_been_in(user_id)

        for index, room in enumerate(rooms):
            room_id = room.room_id

            logger.info(
                "[%s] Handling room %s, %d/%d", user_id, room_id, index + 1, len(rooms)
            )

            forgotten = await self.store.did_forget(user_id, room_id)
            if forgotten:
                logger.info("[%s] User forgot room %d, ignoring", user_id, room_id)
                continue

            if room_id not in rooms_user_has_been_in:
                # If we haven't been in the rooms then the filtering code below
                # won't return anything, so we need to handle these cases
                # explicitly.

                if room.membership == Membership.INVITE:
                    event_id = room.event_id
                    invite = await self.store.get_event(event_id, allow_none=True)
                    if invite:
                        invited_state = invite.unsigned["invite_room_state"]
                        writer.write_invite(room_id, invite, invited_state)

                continue

            # We only want to bother fetching events up to the last time they
            # were joined. We estimate that point by looking at the
            # stream_ordering of the last membership if it wasn't a join.
            if room.membership == Membership.JOIN:
                stream_ordering = self.store.get_room_max_stream_ordering()
            else:
                stream_ordering = room.stream_ordering

            from_key = RoomStreamToken(0, 0)
            to_key = RoomStreamToken(None, stream_ordering)

            # Events that we've processed in this room
            written_events = set()  # type: Set[str]

            # We need to track gaps in the events stream so that we can then
            # write out the state at those events. We do this by keeping track
            # of events whose prev events we haven't seen.

            # Map from event ID to prev events that haven't been processed,
            # dict[str, set[str]].
            event_to_unseen_prevs = {}

            # The reverse mapping to above, i.e. map from unseen event to events
            # that have the unseen event in their prev_events, i.e. the unseen
            # events "children".
            unseen_to_child_events = {}  # type: Dict[str, Set[str]]

            # We fetch events in the room the user could see by fetching *all*
            # events that we have and then filtering, this isn't the most
            # efficient method perhaps but it does guarantee we get everything.
            while True:
                events, _ = await self.store.paginate_room_events(
                    room_id, from_key, to_key, limit=100, direction="f"
                )
                if not events:
                    break

                from_key = events[-1].internal_metadata.after

                events = await filter_events_for_client(self.storage, user_id, events)

                writer.write_events(room_id, events)

                # Update the extremity tracking dicts
                for event in events:
                    # Check if we have any prev events that haven't been
                    # processed yet, and add those to the appropriate dicts.
                    unseen_events = set(event.prev_event_ids()) - written_events
                    if unseen_events:
                        event_to_unseen_prevs[event.event_id] = unseen_events
                        for unseen in unseen_events:
                            unseen_to_child_events.setdefault(unseen, set()).add(
                                event.event_id
                            )

                    # Now check if this event is an unseen prev event, if so
                    # then we remove this event from the appropriate dicts.
                    for child_id in unseen_to_child_events.pop(event.event_id, []):
                        event_to_unseen_prevs[child_id].discard(event.event_id)

                    written_events.add(event.event_id)

                logger.info(
                    "Written %d events in room %s", len(written_events), room_id
                )

            # Extremities are the events who have at least one unseen prev event.
            extremities = (
                event_id
                for event_id, unseen_prevs in event_to_unseen_prevs.items()
                if unseen_prevs
            )
            for event_id in extremities:
                if not event_to_unseen_prevs[event_id]:
                    continue
                state = await self.state_store.get_state_for_event(event_id)
                writer.write_state(room_id, event_id, state)

        return writer.finished()


class ExfiltrationWriter(metaclass=abc.ABCMeta):
    """Interface used to specify how to write exported data."""

    @abc.abstractmethod
    def write_events(self, room_id: str, events: List[EventBase]) -> None:
        """Write a batch of events for a room."""
        raise NotImplementedError()

    @abc.abstractmethod
    def write_state(
        self, room_id: str, event_id: str, state: StateMap[EventBase]
    ) -> None:
        """Write the state at the given event in the room.

        This only gets called for backward extremities rather than for each
        event.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def write_invite(
        self, room_id: str, event: EventBase, state: StateMap[dict]
    ) -> None:
        """Write an invite for the room, with associated invite state.

        Args:
            room_id: The room ID the invite is for.
            event: The invite event.
            state: A subset of the state at the invite, with a subset of the
                event keys (type, state_key content and sender).
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def finished(self) -> Any:
        """Called when all data has successfully been exported and written.

        This functions return value is passed to the caller of
        `export_user_data`.
        """
        raise NotImplementedError()
