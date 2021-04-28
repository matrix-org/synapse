# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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
from typing import TYPE_CHECKING, Optional, Tuple

from twisted.internet import defer

from synapse.api.constants import EduTypes, EventTypes, Membership
from synapse.api.errors import SynapseError
from synapse.events.validator import EventValidator
from synapse.handlers.presence import format_user_presence_state
from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.storage.roommember import RoomsForUser
from synapse.streams.config import PaginationConfig
from synapse.types import JsonDict, Requester, RoomStreamToken, StreamToken, UserID
from synapse.util import unwrapFirstError
from synapse.util.async_helpers import concurrently_execute
from synapse.util.caches.response_cache import ResponseCache
from synapse.visibility import filter_events_for_client

from ._base import BaseHandler

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


class InitialSyncHandler(BaseHandler):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.hs = hs
        self.state = hs.get_state_handler()
        self.clock = hs.get_clock()
        self.validator = EventValidator()
        self.snapshot_cache = ResponseCache(
            hs.get_clock(), "initial_sync_cache"
        )  # type: ResponseCache[Tuple[str, Optional[StreamToken], Optional[StreamToken], str, Optional[int], bool, bool]]
        self._event_serializer = hs.get_event_client_serializer()
        self.storage = hs.get_storage()
        self.state_store = self.storage.state

    async def snapshot_all_rooms(
        self,
        user_id: str,
        pagin_config: PaginationConfig,
        as_client_event: bool = True,
        include_archived: bool = False,
    ) -> JsonDict:
        """Retrieve a snapshot of all rooms the user is invited or has joined.

        This snapshot may include messages for all rooms where the user is
        joined, depending on the pagination config.

        Args:
            user_id: The ID of the user making the request.
            pagin_config: The pagination config used to determine how many
                messages *PER ROOM* to return.
            as_client_event: True to get events in client-server format.
            include_archived: True to get rooms that the user has left
        Returns:
            A JsonDict with the same format as the response to `/intialSync`
            API
        """
        key = (
            user_id,
            pagin_config.from_token,
            pagin_config.to_token,
            pagin_config.direction,
            pagin_config.limit,
            as_client_event,
            include_archived,
        )

        return await self.snapshot_cache.wrap(
            key,
            self._snapshot_all_rooms,
            user_id,
            pagin_config,
            as_client_event,
            include_archived,
        )

    async def _snapshot_all_rooms(
        self,
        user_id: str,
        pagin_config: PaginationConfig,
        as_client_event: bool = True,
        include_archived: bool = False,
    ) -> JsonDict:

        memberships = [Membership.INVITE, Membership.JOIN]
        if include_archived:
            memberships.append(Membership.LEAVE)

        room_list = await self.store.get_rooms_for_local_user_where_membership_is(
            user_id=user_id, membership_list=memberships
        )

        user = UserID.from_string(user_id)

        rooms_ret = []

        now_token = self.hs.get_event_sources().get_current_token()

        presence_stream = self.hs.get_event_sources().sources["presence"]
        presence, _ = await presence_stream.get_new_events(
            user, from_key=None, include_offline=False
        )

        joined_rooms = [r.room_id for r in room_list if r.membership == Membership.JOIN]
        receipt = await self.store.get_linearized_receipts_for_rooms(
            joined_rooms,
            to_key=int(now_token.receipt_key),
        )

        tags_by_room = await self.store.get_tags_for_user(user_id)

        account_data, account_data_by_room = await self.store.get_account_data_for_user(
            user_id
        )

        public_room_ids = await self.store.get_public_room_ids()

        limit = pagin_config.limit
        if limit is None:
            limit = 10

        async def handle_room(event: RoomsForUser):
            d = {
                "room_id": event.room_id,
                "membership": event.membership,
                "visibility": (
                    "public" if event.room_id in public_room_ids else "private"
                ),
            }

            if event.membership == Membership.INVITE:
                time_now = self.clock.time_msec()
                d["inviter"] = event.sender

                invite_event = await self.store.get_event(event.event_id)
                d["invite"] = await self._event_serializer.serialize_event(
                    invite_event, time_now, as_client_event
                )

            rooms_ret.append(d)

            if event.membership not in (Membership.JOIN, Membership.LEAVE):
                return

            try:
                if event.membership == Membership.JOIN:
                    room_end_token = now_token.room_key
                    deferred_room_state = run_in_background(
                        self.state_handler.get_current_state, event.room_id
                    )
                elif event.membership == Membership.LEAVE:
                    room_end_token = RoomStreamToken(
                        None,
                        event.stream_ordering,
                    )
                    deferred_room_state = run_in_background(
                        self.state_store.get_state_for_events, [event.event_id]
                    )
                    deferred_room_state.addCallback(
                        lambda states: states[event.event_id]
                    )

                (messages, token), current_state = await make_deferred_yieldable(
                    defer.gatherResults(
                        [
                            run_in_background(
                                self.store.get_recent_events_for_room,
                                event.room_id,
                                limit=limit,
                                end_token=room_end_token,
                            ),
                            deferred_room_state,
                        ]
                    )
                ).addErrback(unwrapFirstError)

                messages = await filter_events_for_client(
                    self.storage, user_id, messages
                )

                start_token = now_token.copy_and_replace("room_key", token)
                end_token = now_token.copy_and_replace("room_key", room_end_token)
                time_now = self.clock.time_msec()

                d["messages"] = {
                    "chunk": (
                        await self._event_serializer.serialize_events(
                            messages, time_now=time_now, as_client_event=as_client_event
                        )
                    ),
                    "start": await start_token.to_string(self.store),
                    "end": await end_token.to_string(self.store),
                }

                d["state"] = await self._event_serializer.serialize_events(
                    current_state.values(),
                    time_now=time_now,
                    as_client_event=as_client_event,
                )

                account_data_events = []
                tags = tags_by_room.get(event.room_id)
                if tags:
                    account_data_events.append(
                        {"type": "m.tag", "content": {"tags": tags}}
                    )

                account_data = account_data_by_room.get(event.room_id, {})
                for account_data_type, content in account_data.items():
                    account_data_events.append(
                        {"type": account_data_type, "content": content}
                    )

                d["account_data"] = account_data_events
            except Exception:
                logger.exception("Failed to get snapshot")

        await concurrently_execute(handle_room, room_list, 10)

        account_data_events = []
        for account_data_type, content in account_data.items():
            account_data_events.append({"type": account_data_type, "content": content})

        now = self.clock.time_msec()

        ret = {
            "rooms": rooms_ret,
            "presence": [
                {
                    "type": "m.presence",
                    "content": format_user_presence_state(event, now),
                }
                for event in presence
            ],
            "account_data": account_data_events,
            "receipts": receipt,
            "end": await now_token.to_string(self.store),
        }

        return ret

    async def room_initial_sync(
        self, requester: Requester, room_id: str, pagin_config: PaginationConfig
    ) -> JsonDict:
        """Capture the a snapshot of a room. If user is currently a member of
        the room this will be what is currently in the room. If the user left
        the room this will be what was in the room when they left.

        Args:
            requester: The user to get a snapshot for.
            room_id: The room to get a snapshot of.
            pagin_config: The pagination config used to determine how many
                messages to return.
        Raises:
            AuthError if the user wasn't in the room.
        Returns:
            A JSON serialisable dict with the snapshot of the room.
        """

        blocked = await self.store.is_room_blocked(room_id)
        if blocked:
            raise SynapseError(403, "This room has been blocked on this server")

        user_id = requester.user.to_string()

        (
            membership,
            member_event_id,
        ) = await self.auth.check_user_in_room_or_world_readable(
            room_id,
            user_id,
            allow_departed_users=True,
        )
        is_peeking = member_event_id is None

        if membership == Membership.JOIN:
            result = await self._room_initial_sync_joined(
                user_id, room_id, pagin_config, membership, is_peeking
            )
        elif membership == Membership.LEAVE:
            # The member_event_id will always be available if membership is set
            # to leave.
            assert member_event_id

            result = await self._room_initial_sync_parted(
                user_id, room_id, pagin_config, membership, member_event_id, is_peeking
            )

        account_data_events = []
        tags = await self.store.get_tags_for_room(user_id, room_id)
        if tags:
            account_data_events.append({"type": "m.tag", "content": {"tags": tags}})

        account_data = await self.store.get_account_data_for_room(user_id, room_id)
        for account_data_type, content in account_data.items():
            account_data_events.append({"type": account_data_type, "content": content})

        result["account_data"] = account_data_events

        return result

    async def _room_initial_sync_parted(
        self,
        user_id: str,
        room_id: str,
        pagin_config: PaginationConfig,
        membership: str,
        member_event_id: str,
        is_peeking: bool,
    ) -> JsonDict:
        room_state = await self.state_store.get_state_for_event(member_event_id)

        limit = pagin_config.limit if pagin_config else None
        if limit is None:
            limit = 10

        leave_position = await self.store.get_position_for_event(member_event_id)
        stream_token = leave_position.to_room_stream_token()

        messages, token = await self.store.get_recent_events_for_room(
            room_id, limit=limit, end_token=stream_token
        )

        messages = await filter_events_for_client(
            self.storage, user_id, messages, is_peeking=is_peeking
        )

        start_token = StreamToken.START.copy_and_replace("room_key", token)
        end_token = StreamToken.START.copy_and_replace("room_key", stream_token)

        time_now = self.clock.time_msec()

        return {
            "membership": membership,
            "room_id": room_id,
            "messages": {
                "chunk": (
                    await self._event_serializer.serialize_events(messages, time_now)
                ),
                "start": await start_token.to_string(self.store),
                "end": await end_token.to_string(self.store),
            },
            "state": (
                await self._event_serializer.serialize_events(
                    room_state.values(), time_now
                )
            ),
            "presence": [],
            "receipts": [],
        }

    async def _room_initial_sync_joined(
        self,
        user_id: str,
        room_id: str,
        pagin_config: PaginationConfig,
        membership: str,
        is_peeking: bool,
    ) -> JsonDict:
        current_state = await self.state.get_current_state(room_id=room_id)

        # TODO: These concurrently
        time_now = self.clock.time_msec()
        state = await self._event_serializer.serialize_events(
            current_state.values(), time_now
        )

        now_token = self.hs.get_event_sources().get_current_token()

        limit = pagin_config.limit if pagin_config else None
        if limit is None:
            limit = 10

        room_members = [
            m
            for m in current_state.values()
            if m.type == EventTypes.Member
            and m.content["membership"] == Membership.JOIN
        ]

        presence_handler = self.hs.get_presence_handler()

        async def get_presence():
            # If presence is disabled, return an empty list
            if not self.hs.config.use_presence:
                return []

            states = await presence_handler.get_states(
                [m.user_id for m in room_members]
            )

            return [
                {
                    "type": EduTypes.Presence,
                    "content": format_user_presence_state(s, time_now),
                }
                for s in states
            ]

        async def get_receipts():
            receipts = await self.store.get_linearized_receipts_for_room(
                room_id, to_key=now_token.receipt_key
            )
            if not receipts:
                receipts = []
            return receipts

        presence, receipts, (messages, token) = await make_deferred_yieldable(
            defer.gatherResults(
                [
                    run_in_background(get_presence),
                    run_in_background(get_receipts),
                    run_in_background(
                        self.store.get_recent_events_for_room,
                        room_id,
                        limit=limit,
                        end_token=now_token.room_key,
                    ),
                ],
                consumeErrors=True,
            ).addErrback(unwrapFirstError)
        )

        messages = await filter_events_for_client(
            self.storage, user_id, messages, is_peeking=is_peeking
        )

        start_token = now_token.copy_and_replace("room_key", token)
        end_token = now_token

        time_now = self.clock.time_msec()

        ret = {
            "room_id": room_id,
            "messages": {
                "chunk": (
                    await self._event_serializer.serialize_events(messages, time_now)
                ),
                "start": await start_token.to_string(self.store),
                "end": await end_token.to_string(self.store),
            },
            "state": state,
            "presence": presence,
            "receipts": receipts,
        }
        if not is_peeking:
            ret["membership"] = membership

        return ret
