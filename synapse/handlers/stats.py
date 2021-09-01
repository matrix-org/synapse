# Copyright 2018-2021 The Matrix.org Foundation C.I.C.
# Copyright 2020 Sorunome
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
from collections import Counter
from typing import TYPE_CHECKING, Any, Dict, Iterable, Optional, Tuple

from typing_extensions import Counter as CounterType

from synapse.api.constants import EventTypes, Membership
from synapse.metrics import event_processing_positions
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class StatsHandler:
    """Handles keeping the *_stats tables updated with a simple time-series of
    information about the users, rooms and media on the server, such that admins
    have some idea of who is consuming their resources.

    Heavily derived from UserDirectoryHandler
    """

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.store = hs.get_datastore()
        self.state = hs.get_state_handler()
        self.server_name = hs.hostname
        self.clock = hs.get_clock()
        self.notifier = hs.get_notifier()
        self.is_mine_id = hs.is_mine_id
        self.stats_bucket_size = hs.config.stats_bucket_size

        self.stats_enabled = hs.config.stats_enabled

        # The current position in the current_state_delta stream
        self.pos = None  # type: Optional[int]

        # Guard to ensure we only process deltas one at a time
        self._is_processing = False

        if self.stats_enabled and hs.config.run_background_tasks:
            self.notifier.add_replication_callback(self.notify_new_event)

            # We kick this off so that we don't have to wait for a change before
            # we start populating stats
            self.clock.call_later(0, self.notify_new_event)

    def notify_new_event(self) -> None:
        """Called when there may be more deltas to process"""
        if not self.stats_enabled or self._is_processing:
            return

        self._is_processing = True

        async def process():
            try:
                await self._unsafe_process()
            finally:
                self._is_processing = False

        run_as_background_process("stats.notify_new_event", process)

    async def _unsafe_process(self) -> None:
        # If self.pos is None then means we haven't fetched it from DB
        if self.pos is None:
            self.pos = await self.store.get_stats_positions()

        # Loop round handling deltas until we're up to date

        while True:
            # Be sure to read the max stream_ordering *before* checking if there are any outstanding
            # deltas, since there is otherwise a chance that we could miss updates which arrive
            # after we check the deltas.
            room_max_stream_ordering = self.store.get_room_max_stream_ordering()
            if self.pos == room_max_stream_ordering:
                break

            logger.debug(
                "Processing room stats %s->%s", self.pos, room_max_stream_ordering
            )
            max_pos, deltas = await self.store.get_current_state_deltas(
                self.pos, room_max_stream_ordering
            )

            if deltas:
                logger.debug("Handling %d state deltas", len(deltas))
                room_deltas, user_deltas = await self._handle_deltas(deltas)
            else:
                room_deltas = {}
                user_deltas = {}

            # Then count deltas for total_events and total_event_bytes.
            (
                room_count,
                user_count,
            ) = await self.store.get_changes_room_total_events_and_bytes(
                self.pos, max_pos
            )

            for room_id, fields in room_count.items():
                room_deltas.setdefault(room_id, Counter()).update(fields)

            for user_id, fields in user_count.items():
                user_deltas.setdefault(user_id, Counter()).update(fields)

            logger.debug("room_deltas: %s", room_deltas)
            logger.debug("user_deltas: %s", user_deltas)

            # Always call this so that we update the stats position.
            await self.store.bulk_update_stats_delta(
                self.clock.time_msec(),
                updates={"room": room_deltas, "user": user_deltas},
                stream_id=max_pos,
            )

            logger.debug("Handled room stats to %s -> %s", self.pos, max_pos)

            event_processing_positions.labels("stats").set(max_pos)

            self.pos = max_pos

    async def _handle_deltas(
        self, deltas: Iterable[JsonDict]
    ) -> Tuple[Dict[str, CounterType[str]], Dict[str, CounterType[str]]]:
        """Called with the state deltas to process

        Returns:
            Two dicts: the room deltas and the user deltas,
            mapping from room/user ID to changes in the various fields.
        """

        room_to_stats_deltas = {}  # type: Dict[str, CounterType[str]]
        user_to_stats_deltas = {}  # type: Dict[str, CounterType[str]]

        room_to_state_updates = {}  # type: Dict[str, Dict[str, Any]]

        for delta in deltas:
            typ = delta["type"]
            state_key = delta["state_key"]
            room_id = delta["room_id"]
            event_id = delta["event_id"]
            stream_id = delta["stream_id"]
            prev_event_id = delta["prev_event_id"]

            logger.debug("Handling: %r, %r %r, %s", room_id, typ, state_key, event_id)

            token = await self.store.get_earliest_token_for_stats("room", room_id)

            # If the earliest token to begin from is larger than our current
            # stream ID, skip processing this delta.
            if token is not None and token >= stream_id:
                logger.debug(
                    "Ignoring: %s as earlier than this room's initial ingestion event",
                    event_id,
                )
                continue

            if event_id is None and prev_event_id is None:
                logger.error(
                    "event ID is None and so is the previous event ID. stream_id: %s",
                    stream_id,
                )
                continue

            event_content = {}  # type: JsonDict

            sender = None
            if event_id is not None:
                event = await self.store.get_event(event_id, allow_none=True)
                if event:
                    event_content = event.content or {}
                    sender = event.sender

            # All the values in this dict are deltas (RELATIVE changes)
            room_stats_delta = room_to_stats_deltas.setdefault(room_id, Counter())

            room_state = room_to_state_updates.setdefault(room_id, {})

            if prev_event_id is None:
                # this state event doesn't overwrite another,
                # so it is a new effective/current state event
                room_stats_delta["current_state_events"] += 1

            if typ == EventTypes.Member:
                # we could use StateDeltasHandler._get_key_change here but it's
                # a bit inefficient given we're not testing for a specific
                # result; might as well just grab the prev_membership and
                # membership strings and compare them.
                # We take None rather than leave as a previous membership
                # in the absence of a previous event because we do not want to
                # reduce the leave count when a new-to-the-room user joins.
                prev_membership = None
                if prev_event_id is not None:
                    prev_event = await self.store.get_event(
                        prev_event_id, allow_none=True
                    )
                    if prev_event:
                        prev_event_content = prev_event.content
                        prev_membership = prev_event_content.get(
                            "membership", Membership.LEAVE
                        )

                membership = event_content.get("membership", Membership.LEAVE)

                if prev_membership is None:
                    logger.debug("No previous membership for this user.")
                elif membership == prev_membership:
                    pass  # noop
                elif prev_membership == Membership.JOIN:
                    room_stats_delta["joined_members"] -= 1
                elif prev_membership == Membership.INVITE:
                    room_stats_delta["invited_members"] -= 1
                elif prev_membership == Membership.LEAVE:
                    room_stats_delta["left_members"] -= 1
                elif prev_membership == Membership.BAN:
                    room_stats_delta["banned_members"] -= 1
                elif prev_membership == Membership.KNOCK:
                    room_stats_delta["knocked_members"] -= 1
                else:
                    raise ValueError(
                        "%r is not a valid prev_membership" % (prev_membership,)
                    )

                if membership == prev_membership:
                    pass  # noop
                elif membership == Membership.JOIN:
                    room_stats_delta["joined_members"] += 1
                elif membership == Membership.INVITE:
                    room_stats_delta["invited_members"] += 1

                    if sender and self.is_mine_id(sender):
                        user_to_stats_deltas.setdefault(sender, Counter())[
                            "invites_sent"
                        ] += 1

                elif membership == Membership.LEAVE:
                    room_stats_delta["left_members"] += 1
                elif membership == Membership.BAN:
                    room_stats_delta["banned_members"] += 1
                elif membership == Membership.KNOCK:
                    room_stats_delta["knocked_members"] += 1
                else:
                    raise ValueError("%r is not a valid membership" % (membership,))

                user_id = state_key
                if self.is_mine_id(user_id):
                    # this accounts for transitions like leave → ban and so on.
                    has_changed_joinedness = (prev_membership == Membership.JOIN) != (
                        membership == Membership.JOIN
                    )

                    if has_changed_joinedness:
                        membership_delta = +1 if membership == Membership.JOIN else -1

                        user_to_stats_deltas.setdefault(user_id, Counter())[
                            "joined_rooms"
                        ] += membership_delta

                        room_stats_delta["local_users_in_room"] += membership_delta

            elif typ == EventTypes.Create:
                room_state["is_federatable"] = (
                    event_content.get("m.federate", True) is True
                )
                if sender and self.is_mine_id(sender):
                    user_to_stats_deltas.setdefault(sender, Counter())[
                        "rooms_created"
                    ] += 1
            elif typ == EventTypes.JoinRules:
                room_state["join_rules"] = event_content.get("join_rule")
            elif typ == EventTypes.RoomHistoryVisibility:
                room_state["history_visibility"] = event_content.get(
                    "history_visibility"
                )
            elif typ == EventTypes.RoomEncryption:
                room_state["encryption"] = event_content.get("algorithm")
            elif typ == EventTypes.Name:
                room_state["name"] = event_content.get("name")
            elif typ == EventTypes.Topic:
                room_state["topic"] = event_content.get("topic")
            elif typ == EventTypes.RoomAvatar:
                room_state["avatar"] = event_content.get("url")
            elif typ == EventTypes.CanonicalAlias:
                room_state["canonical_alias"] = event_content.get("alias")
            elif typ == EventTypes.GuestAccess:
                room_state["guest_access"] = event_content.get("guest_access")

        for room_id, state in room_to_state_updates.items():
            logger.debug("Updating room_stats_state for %s: %s", room_id, state)
            await self.store.update_room_state(room_id, state)

        return room_to_stats_deltas, user_to_stats_deltas
