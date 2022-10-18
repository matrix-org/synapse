# Copyright 2016-2020 The Matrix.org Foundation C.I.C.
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
import abc
import logging
import random
from http import HTTPStatus
from typing import TYPE_CHECKING, Iterable, List, Optional, Set, Tuple

from synapse import types
from synapse.api.constants import (
    AccountDataTypes,
    EventContentFields,
    EventTypes,
    GuestAccess,
    Membership,
)
from synapse.api.errors import AuthError, Codes, ShadowBanError, SynapseError
from synapse.api.ratelimiting import Ratelimiter
from synapse.event_auth import get_named_level, get_power_level_event
from synapse.events import EventBase
from synapse.events.snapshot import EventContext
from synapse.handlers.profile import MAX_AVATAR_URL_LEN, MAX_DISPLAYNAME_LEN
from synapse.logging import opentracing
from synapse.module_api import NOT_SPAM
from synapse.storage.state import StateFilter
from synapse.types import (
    JsonDict,
    Requester,
    RoomAlias,
    RoomID,
    StateMap,
    UserID,
    create_requester,
    get_domain_from_id,
)
from synapse.util.async_helpers import Linearizer
from synapse.util.distributor import user_left_room

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


class RoomMemberHandler(metaclass=abc.ABCMeta):
    # TODO(paul): This handler currently contains a messy conflation of
    #   low-level API that works on UserID objects and so on, and REST-level
    #   API that takes ID strings and returns pagination chunks. These concerns
    #   ought to be separated out a lot better.

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.store = hs.get_datastores().main
        self._storage_controllers = hs.get_storage_controllers()
        self.auth = hs.get_auth()
        self.state_handler = hs.get_state_handler()
        self.config = hs.config
        self._server_name = hs.hostname

        self.federation_handler = hs.get_federation_handler()
        self.directory_handler = hs.get_directory_handler()
        self.identity_handler = hs.get_identity_handler()
        self.registration_handler = hs.get_registration_handler()
        self.profile_handler = hs.get_profile_handler()
        self.event_creation_handler = hs.get_event_creation_handler()
        self.account_data_handler = hs.get_account_data_handler()
        self.event_auth_handler = hs.get_event_auth_handler()

        self.member_linearizer: Linearizer = Linearizer(name="member")
        self.member_as_limiter = Linearizer(max_count=10, name="member_as_limiter")

        self.clock = hs.get_clock()
        self.spam_checker = hs.get_spam_checker()
        self.third_party_event_rules = hs.get_third_party_event_rules()
        self._server_notices_mxid = self.config.servernotices.server_notices_mxid
        self._enable_lookup = hs.config.registration.enable_3pid_lookup
        self.allow_per_room_profiles = self.config.server.allow_per_room_profiles

        self._join_rate_limiter_local = Ratelimiter(
            store=self.store,
            clock=self.clock,
            rate_hz=hs.config.ratelimiting.rc_joins_local.per_second,
            burst_count=hs.config.ratelimiting.rc_joins_local.burst_count,
        )
        # Tracks joins from local users to rooms this server isn't a member of.
        # I.e. joins this server makes by requesting /make_join /send_join from
        # another server.
        self._join_rate_limiter_remote = Ratelimiter(
            store=self.store,
            clock=self.clock,
            rate_hz=hs.config.ratelimiting.rc_joins_remote.per_second,
            burst_count=hs.config.ratelimiting.rc_joins_remote.burst_count,
        )
        # TODO: find a better place to keep this Ratelimiter.
        #   It needs to be
        #    - written to by event persistence code
        #    - written to by something which can snoop on replication streams
        #    - read by the RoomMemberHandler to rate limit joins from local users
        #    - read by the FederationServer to rate limit make_joins and send_joins from
        #      other homeservers
        #   I wonder if a homeserver-wide collection of rate limiters might be cleaner?
        self._join_rate_per_room_limiter = Ratelimiter(
            store=self.store,
            clock=self.clock,
            rate_hz=hs.config.ratelimiting.rc_joins_per_room.per_second,
            burst_count=hs.config.ratelimiting.rc_joins_per_room.burst_count,
        )

        # Ratelimiter for invites, keyed by room (across all issuers, all
        # recipients).
        self._invites_per_room_limiter = Ratelimiter(
            store=self.store,
            clock=self.clock,
            rate_hz=hs.config.ratelimiting.rc_invites_per_room.per_second,
            burst_count=hs.config.ratelimiting.rc_invites_per_room.burst_count,
        )

        # Ratelimiter for invites, keyed by recipient (across all rooms, all
        # issuers).
        self._invites_per_recipient_limiter = Ratelimiter(
            store=self.store,
            clock=self.clock,
            rate_hz=hs.config.ratelimiting.rc_invites_per_user.per_second,
            burst_count=hs.config.ratelimiting.rc_invites_per_user.burst_count,
        )

        # Ratelimiter for invites, keyed by issuer (across all rooms, all
        # recipients).
        self._invites_per_issuer_limiter = Ratelimiter(
            store=self.store,
            clock=self.clock,
            rate_hz=hs.config.ratelimiting.rc_invites_per_issuer.per_second,
            burst_count=hs.config.ratelimiting.rc_invites_per_issuer.burst_count,
        )

        self._third_party_invite_limiter = Ratelimiter(
            store=self.store,
            clock=self.clock,
            rate_hz=hs.config.ratelimiting.rc_third_party_invite.per_second,
            burst_count=hs.config.ratelimiting.rc_third_party_invite.burst_count,
        )

        self.request_ratelimiter = hs.get_request_ratelimiter()
        hs.get_notifier().add_new_join_in_room_callback(self._on_user_joined_room)

    def _on_user_joined_room(self, event_id: str, room_id: str) -> None:
        """Notify the rate limiter that a room join has occurred.

        Use this to inform the RoomMemberHandler about joins that have either
        - taken place on another homeserver, or
        - on another worker in this homeserver.
        Joins actioned by this worker should use the usual `ratelimit` method, which
        checks the limit and increments the counter in one go.
        """
        self._join_rate_per_room_limiter.record_action(requester=None, key=room_id)

    @abc.abstractmethod
    async def _remote_join(
        self,
        requester: Requester,
        remote_room_hosts: List[str],
        room_id: str,
        user: UserID,
        content: dict,
    ) -> Tuple[str, int]:
        """Try and join a room that this server is not in

        Args:
            requester: The user making the request, according to the access token.
            remote_room_hosts: List of servers that can be used to join via.
            room_id: Room that we are trying to join
            user: User who is trying to join
            content: A dict that should be used as the content of the join event.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    async def remote_knock(
        self,
        remote_room_hosts: List[str],
        room_id: str,
        user: UserID,
        content: dict,
    ) -> Tuple[str, int]:
        """Try and knock on a room that this server is not in

        Args:
            remote_room_hosts: List of servers that can be used to knock via.
            room_id: Room that we are trying to knock on.
            user: User who is trying to knock.
            content: A dict that should be used as the content of the knock event.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    async def remote_reject_invite(
        self,
        invite_event_id: str,
        txn_id: Optional[str],
        requester: Requester,
        content: JsonDict,
    ) -> Tuple[str, int]:
        """
        Rejects an out-of-band invite we have received from a remote server

        Args:
            invite_event_id: ID of the invite to be rejected
            txn_id: optional transaction ID supplied by the client
            requester: user making the rejection request, according to the access token
            content: additional content to include in the rejection event.
               Normally an empty dict.

        Returns:
            event id, stream_id of the leave event
        """
        raise NotImplementedError()

    @abc.abstractmethod
    async def remote_rescind_knock(
        self,
        knock_event_id: str,
        txn_id: Optional[str],
        requester: Requester,
        content: JsonDict,
    ) -> Tuple[str, int]:
        """Rescind a local knock made on a remote room.

        Args:
            knock_event_id: The ID of the knock event to rescind.
            txn_id: An optional transaction ID supplied by the client.
            requester: The user making the request, according to the access token.
            content: The content of the generated leave event.

        Returns:
            A tuple containing (event_id, stream_id of the leave event).
        """
        raise NotImplementedError()

    @abc.abstractmethod
    async def _user_left_room(self, target: UserID, room_id: str) -> None:
        """Notifies distributor on master process that the user has left the
        room.

        Args:
            target
            room_id
        """
        raise NotImplementedError()

    @abc.abstractmethod
    async def forget(self, user: UserID, room_id: str) -> None:
        raise NotImplementedError()

    async def ratelimit_multiple_invites(
        self,
        requester: Optional[Requester],
        room_id: Optional[str],
        n_invites: int,
        update: bool = True,
    ) -> None:
        """Ratelimit more than one invite sent by the given requester in the given room.

        Args:
            requester: The requester sending the invites.
            room_id: The room the invites are being sent in.
            n_invites: The amount of invites to ratelimit for.
            update: Whether to update the ratelimiter's cache.

        Raises:
            LimitExceededError: The requester can't send that many invites in the room.
        """
        await self._invites_per_room_limiter.ratelimit(
            requester,
            room_id,
            update=update,
            n_actions=n_invites,
        )

    async def ratelimit_invite(
        self,
        requester: Optional[Requester],
        room_id: Optional[str],
        invitee_user_id: str,
    ) -> None:
        """Ratelimit invites by room and by target user.

        If room ID is missing then we just rate limit by target user.
        """
        if room_id:
            await self._invites_per_room_limiter.ratelimit(requester, room_id)

        await self._invites_per_recipient_limiter.ratelimit(requester, invitee_user_id)
        if requester is not None:
            await self._invites_per_issuer_limiter.ratelimit(requester)

    async def _local_membership_update(
        self,
        requester: Requester,
        target: UserID,
        room_id: str,
        membership: str,
        allow_no_prev_events: bool = False,
        prev_event_ids: Optional[List[str]] = None,
        state_event_ids: Optional[List[str]] = None,
        depth: Optional[int] = None,
        txn_id: Optional[str] = None,
        ratelimit: bool = True,
        content: Optional[dict] = None,
        require_consent: bool = True,
        outlier: bool = False,
        historical: bool = False,
        origin_server_ts: Optional[int] = None,
    ) -> Tuple[str, int]:
        """
        Internal membership update function to get an existing event or create
        and persist a new event for the new membership change.

        Args:
            requester:
            target:
            room_id:
            membership:

            allow_no_prev_events: Whether to allow this event to be created an empty
                list of prev_events. Normally this is prohibited just because most
                events should have a prev_event and we should only use this in special
                cases like MSC2716.
            prev_event_ids: The event IDs to use as the prev events
            state_event_ids:
                The full state at a given event. This is used particularly by the MSC2716
                /batch_send endpoint. One use case is the historical `state_events_at_start`;
                since each is marked as an `outlier`, the `EventContext.for_outlier()` won't
                have any `state_ids` set and therefore can't derive any state even though the
                prev_events are set so we need to set them ourself via this argument.
                This should normally be left as None, which will cause the auth_event_ids
                to be calculated based on the room state at the prev_events.
            depth: Override the depth used to order the event in the DAG.
                Should normally be set to None, which will cause the depth to be calculated
                based on the prev_events.

            txn_id:
            ratelimit:
            content:
            require_consent:

            outlier: Indicates whether the event is an `outlier`, i.e. if
                it's from an arbitrary point and floating in the DAG as
                opposed to being inline with the current DAG.
            historical: Indicates whether the message is being inserted
                back in time around some existing events. This is used to skip
                a few checks and mark the event as backfilled.
            origin_server_ts: The origin_server_ts to use if a new event is created. Uses
                the current timestamp if set to None.

        Returns:
            Tuple of event ID and stream ordering position
        """

        user_id = target.to_string()

        if content is None:
            content = {}

        content["membership"] = membership
        if requester.is_guest:
            content["kind"] = "guest"

        # Check if we already have an event with a matching transaction ID. (We
        # do this check just before we persist an event as well, but may as well
        # do it up front for efficiency.)
        if txn_id and requester.access_token_id:
            existing_event_id = await self.store.get_event_id_from_transaction_id(
                room_id,
                requester.user.to_string(),
                requester.access_token_id,
                txn_id,
            )
            if existing_event_id:
                event_pos = await self.store.get_position_for_event(existing_event_id)
                return existing_event_id, event_pos.stream

        event, context = await self.event_creation_handler.create_event(
            requester,
            {
                "type": EventTypes.Member,
                "content": content,
                "room_id": room_id,
                "sender": requester.user.to_string(),
                "state_key": user_id,
                # For backwards compatibility:
                "membership": membership,
                "origin_server_ts": origin_server_ts,
            },
            txn_id=txn_id,
            allow_no_prev_events=allow_no_prev_events,
            prev_event_ids=prev_event_ids,
            state_event_ids=state_event_ids,
            depth=depth,
            require_consent=require_consent,
            outlier=outlier,
            historical=historical,
        )

        prev_state_ids = await context.get_prev_state_ids(
            StateFilter.from_types([(EventTypes.Member, None)])
        )

        prev_member_event_id = prev_state_ids.get((EventTypes.Member, user_id), None)

        if event.membership == Membership.JOIN:
            newly_joined = True
            if prev_member_event_id:
                prev_member_event = await self.store.get_event(prev_member_event_id)
                newly_joined = prev_member_event.membership != Membership.JOIN

            # Only rate-limit if the user actually joined the room, otherwise we'll end
            # up blocking profile updates.
            if newly_joined and ratelimit:
                await self._join_rate_limiter_local.ratelimit(requester)
                await self._join_rate_per_room_limiter.ratelimit(
                    requester, key=room_id, update=False
                )
        with opentracing.start_active_span("handle_new_client_event"):
            result_event = await self.event_creation_handler.handle_new_client_event(
                requester,
                events_and_context=[(event, context)],
                extra_users=[target],
                ratelimit=ratelimit,
            )

        if event.membership == Membership.LEAVE:
            if prev_member_event_id:
                prev_member_event = await self.store.get_event(prev_member_event_id)
                if prev_member_event.membership == Membership.JOIN:
                    await self._user_left_room(target, room_id)

        # we know it was persisted, so should have a stream ordering
        assert result_event.internal_metadata.stream_ordering
        return result_event.event_id, result_event.internal_metadata.stream_ordering

    async def copy_room_tags_and_direct_to_room(
        self, old_room_id: str, new_room_id: str, user_id: str
    ) -> None:
        """Copies the tags and direct room state from one room to another.

        Args:
            old_room_id: The room ID of the old room.
            new_room_id: The room ID of the new room.
            user_id: The user's ID.
        """
        # Retrieve user account data for predecessor room
        user_account_data, _ = await self.store.get_account_data_for_user(user_id)

        # Copy direct message state if applicable
        direct_rooms = user_account_data.get(AccountDataTypes.DIRECT, {})

        # Check which key this room is under
        if isinstance(direct_rooms, dict):
            for key, room_id_list in direct_rooms.items():
                if old_room_id in room_id_list and new_room_id not in room_id_list:
                    # Add new room_id to this key
                    direct_rooms[key].append(new_room_id)

                    # Save back to user's m.direct account data
                    await self.account_data_handler.add_account_data_for_user(
                        user_id, AccountDataTypes.DIRECT, direct_rooms
                    )
                    break

        # Copy room tags if applicable
        room_tags = await self.store.get_tags_for_room(user_id, old_room_id)

        # Copy each room tag to the new room
        for tag, tag_content in room_tags.items():
            await self.account_data_handler.add_tag_to_room(
                user_id, new_room_id, tag, tag_content
            )

    async def update_membership(
        self,
        requester: Requester,
        target: UserID,
        room_id: str,
        action: str,
        txn_id: Optional[str] = None,
        remote_room_hosts: Optional[List[str]] = None,
        third_party_signed: Optional[dict] = None,
        ratelimit: bool = True,
        content: Optional[dict] = None,
        new_room: bool = False,
        require_consent: bool = True,
        outlier: bool = False,
        historical: bool = False,
        allow_no_prev_events: bool = False,
        prev_event_ids: Optional[List[str]] = None,
        state_event_ids: Optional[List[str]] = None,
        depth: Optional[int] = None,
        origin_server_ts: Optional[int] = None,
    ) -> Tuple[str, int]:
        """Update a user's membership in a room.

        Params:
            requester: The user who is performing the update.
            target: The user whose membership is being updated.
            room_id: The room ID whose membership is being updated.
            action: The membership change, see synapse.api.constants.Membership.
            txn_id: The transaction ID, if given.
            remote_room_hosts: Remote servers to send the update to.
            third_party_signed: Information from a 3PID invite.
            ratelimit: Whether to rate limit the request.
            content: The content of the created event.
            new_room: Whether the membership update is happening in the context of a room
                creation.
            require_consent: Whether consent is required.
            outlier: Indicates whether the event is an `outlier`, i.e. if
                it's from an arbitrary point and floating in the DAG as
                opposed to being inline with the current DAG.
            historical: Indicates whether the message is being inserted
                back in time around some existing events. This is used to skip
                a few checks and mark the event as backfilled.
            allow_no_prev_events: Whether to allow this event to be created an empty
                list of prev_events. Normally this is prohibited just because most
                events should have a prev_event and we should only use this in special
                cases like MSC2716.
            prev_event_ids: The event IDs to use as the prev events
            state_event_ids:
                The full state at a given event. This is used particularly by the MSC2716
                /batch_send endpoint. One use case is the historical `state_events_at_start`;
                since each is marked as an `outlier`, the `EventContext.for_outlier()` won't
                have any `state_ids` set and therefore can't derive any state even though the
                prev_events are set so we need to set them ourself via this argument.
                This should normally be left as None, which will cause the auth_event_ids
                to be calculated based on the room state at the prev_events.
            depth: Override the depth used to order the event in the DAG.
                Should normally be set to None, which will cause the depth to be calculated
                based on the prev_events.
            origin_server_ts: The origin_server_ts to use if a new event is created. Uses
                the current timestamp if set to None.

        Returns:
            A tuple of the new event ID and stream ID.

        Raises:
            ShadowBanError if a shadow-banned requester attempts to send an invite.
        """
        if action == Membership.INVITE and requester.shadow_banned:
            # We randomly sleep a bit just to annoy the requester.
            await self.clock.sleep(random.randint(1, 10))
            raise ShadowBanError()

        key = (room_id,)

        as_id = object()
        if requester.app_service:
            as_id = requester.app_service.id

        # We first linearise by the application service (to try to limit concurrent joins
        # by application services), and then by room ID.
        async with self.member_as_limiter.queue(as_id):
            async with self.member_linearizer.queue(key):
                with opentracing.start_active_span("update_membership_locked"):
                    result = await self.update_membership_locked(
                        requester,
                        target,
                        room_id,
                        action,
                        txn_id=txn_id,
                        remote_room_hosts=remote_room_hosts,
                        third_party_signed=third_party_signed,
                        ratelimit=ratelimit,
                        content=content,
                        new_room=new_room,
                        require_consent=require_consent,
                        outlier=outlier,
                        historical=historical,
                        allow_no_prev_events=allow_no_prev_events,
                        prev_event_ids=prev_event_ids,
                        state_event_ids=state_event_ids,
                        depth=depth,
                        origin_server_ts=origin_server_ts,
                    )

        return result

    async def update_membership_locked(
        self,
        requester: Requester,
        target: UserID,
        room_id: str,
        action: str,
        txn_id: Optional[str] = None,
        remote_room_hosts: Optional[List[str]] = None,
        third_party_signed: Optional[dict] = None,
        ratelimit: bool = True,
        content: Optional[dict] = None,
        new_room: bool = False,
        require_consent: bool = True,
        outlier: bool = False,
        historical: bool = False,
        allow_no_prev_events: bool = False,
        prev_event_ids: Optional[List[str]] = None,
        state_event_ids: Optional[List[str]] = None,
        depth: Optional[int] = None,
        origin_server_ts: Optional[int] = None,
    ) -> Tuple[str, int]:
        """Helper for update_membership.

        Assumes that the membership linearizer is already held for the room.

        Args:
            requester:
            target:
            room_id:
            action:
            txn_id:
            remote_room_hosts:
            third_party_signed:
            ratelimit:
            content:
            new_room: Whether the membership update is happening in the context of a room
                creation.
            require_consent:
            outlier: Indicates whether the event is an `outlier`, i.e. if
                it's from an arbitrary point and floating in the DAG as
                opposed to being inline with the current DAG.
            historical: Indicates whether the message is being inserted
                back in time around some existing events. This is used to skip
                a few checks and mark the event as backfilled.
            allow_no_prev_events: Whether to allow this event to be created an empty
                list of prev_events. Normally this is prohibited just because most
                events should have a prev_event and we should only use this in special
                cases like MSC2716.
            prev_event_ids: The event IDs to use as the prev events
            state_event_ids:
                The full state at a given event. This is used particularly by the MSC2716
                /batch_send endpoint. One use case is the historical `state_events_at_start`;
                since each is marked as an `outlier`, the `EventContext.for_outlier()` won't
                have any `state_ids` set and therefore can't derive any state even though the
                prev_events are set so we need to set them ourself via this argument.
                This should normally be left as None, which will cause the auth_event_ids
                to be calculated based on the room state at the prev_events.
            depth: Override the depth used to order the event in the DAG.
                Should normally be set to None, which will cause the depth to be calculated
                based on the prev_events.
            origin_server_ts: The origin_server_ts to use if a new event is created. Uses
                the current timestamp if set to None.

        Returns:
            A tuple of the new event ID and stream ID.
        """

        content_specified = bool(content)
        if content is None:
            content = {}
        else:
            # We do a copy here as we potentially change some keys
            # later on.
            content = dict(content)

        # allow the server notices mxid to set room-level profile
        is_requester_server_notices_user = (
            self._server_notices_mxid is not None
            and requester.user.to_string() == self._server_notices_mxid
        )

        if (
            not self.allow_per_room_profiles and not is_requester_server_notices_user
        ) or requester.shadow_banned:
            # Strip profile data, knowing that new profile data will be added to the
            # event's content in event_creation_handler.create_event() using the target's
            # global profile.
            content.pop("displayname", None)
            content.pop("avatar_url", None)

        if len(content.get("displayname") or "") > MAX_DISPLAYNAME_LEN:
            raise SynapseError(
                400,
                f"Displayname is too long (max {MAX_DISPLAYNAME_LEN})",
                errcode=Codes.BAD_JSON,
            )

        if len(content.get("avatar_url") or "") > MAX_AVATAR_URL_LEN:
            raise SynapseError(
                400,
                f"Avatar URL is too long (max {MAX_AVATAR_URL_LEN})",
                errcode=Codes.BAD_JSON,
            )

        if "avatar_url" in content and content.get("avatar_url") is not None:
            if not await self.profile_handler.check_avatar_size_and_mime_type(
                content["avatar_url"],
            ):
                raise SynapseError(403, "This avatar is not allowed", Codes.FORBIDDEN)

        # The event content should *not* include the authorising user as
        # it won't be properly signed. Strip it out since it might come
        # back from a client updating a display name / avatar.
        #
        # This only applies to restricted rooms, but there should be no reason
        # for a client to include it. Unconditionally remove it.
        content.pop(EventContentFields.AUTHORISING_USER, None)

        effective_membership_state = action
        if action in ["kick", "unban"]:
            effective_membership_state = "leave"

        # if this is a join with a 3pid signature, we may need to turn a 3pid
        # invite into a normal invite before we can handle the join.
        if third_party_signed is not None:
            await self.federation_handler.exchange_third_party_invite(
                third_party_signed["sender"],
                target.to_string(),
                room_id,
                third_party_signed,
            )

        if not remote_room_hosts:
            remote_room_hosts = []

        if effective_membership_state not in ("leave", "ban"):
            is_blocked = await self.store.is_room_blocked(room_id)
            if is_blocked:
                raise SynapseError(403, "This room has been blocked on this server")

        if effective_membership_state == Membership.INVITE:
            target_id = target.to_string()
            if ratelimit:
                await self.ratelimit_invite(requester, room_id, target_id)

            # block any attempts to invite the server notices mxid
            if target_id == self._server_notices_mxid:
                raise SynapseError(HTTPStatus.FORBIDDEN, "Cannot invite this user")

            block_invite_result = None

            if (
                self._server_notices_mxid is not None
                and requester.user.to_string() == self._server_notices_mxid
            ):
                # allow the server notices mxid to send invites
                is_requester_admin = True

            else:
                is_requester_admin = await self.auth.is_server_admin(requester)

            if not is_requester_admin:
                if self.config.server.block_non_admin_invites:
                    logger.info(
                        "Blocking invite: user is not admin and non-admin "
                        "invites disabled"
                    )
                    block_invite_result = (Codes.FORBIDDEN, {})

                spam_check = await self.spam_checker.user_may_invite(
                    requester.user.to_string(), target_id, room_id
                )
                if spam_check != NOT_SPAM:
                    logger.info("Blocking invite due to spam checker")
                    block_invite_result = spam_check

            if block_invite_result is not None:
                raise SynapseError(
                    403,
                    "Invites have been disabled on this server",
                    errcode=block_invite_result[0],
                    additional_fields=block_invite_result[1],
                )

        # An empty prev_events list is allowed as long as the auth_event_ids are present
        if prev_event_ids is not None:
            return await self._local_membership_update(
                requester=requester,
                target=target,
                room_id=room_id,
                membership=effective_membership_state,
                txn_id=txn_id,
                ratelimit=ratelimit,
                allow_no_prev_events=allow_no_prev_events,
                prev_event_ids=prev_event_ids,
                state_event_ids=state_event_ids,
                depth=depth,
                content=content,
                require_consent=require_consent,
                outlier=outlier,
                historical=historical,
                origin_server_ts=origin_server_ts,
            )

        latest_event_ids = await self.store.get_prev_events_for_room(room_id)

        state_before_join = await self.state_handler.compute_state_after_events(
            room_id, latest_event_ids
        )

        # TODO: Refactor into dictionary of explicitly allowed transitions
        # between old and new state, with specific error messages for some
        # transitions and generic otherwise
        old_state_id = state_before_join.get((EventTypes.Member, target.to_string()))
        if old_state_id:
            old_state = await self.store.get_event(old_state_id, allow_none=True)
            old_membership = old_state.content.get("membership") if old_state else None
            if action == "unban" and old_membership != "ban":
                raise SynapseError(
                    403,
                    "Cannot unban user who was not banned"
                    " (membership=%s)" % old_membership,
                    errcode=Codes.BAD_STATE,
                )
            if old_membership == "ban" and action not in ["ban", "unban", "leave"]:
                raise SynapseError(
                    403,
                    "Cannot %s user who was banned" % (action,),
                    errcode=Codes.BAD_STATE,
                )

            if old_state:
                same_content = content == old_state.content
                same_membership = old_membership == effective_membership_state
                same_sender = requester.user.to_string() == old_state.sender
                if same_sender and same_membership and same_content:
                    # duplicate event.
                    # we know it was persisted, so must have a stream ordering.
                    assert old_state.internal_metadata.stream_ordering
                    return (
                        old_state.event_id,
                        old_state.internal_metadata.stream_ordering,
                    )

            if old_membership in ["ban", "leave"] and action == "kick":
                raise AuthError(403, "The target user is not in the room")

            # we don't allow people to reject invites to the server notice
            # room, but they can leave it once they are joined.
            if (
                old_membership == Membership.INVITE
                and effective_membership_state == Membership.LEAVE
            ):
                is_blocked = await self.store.is_server_notice_room(room_id)
                if is_blocked:
                    raise SynapseError(
                        HTTPStatus.FORBIDDEN,
                        "You cannot reject this invite",
                        errcode=Codes.CANNOT_LEAVE_SERVER_NOTICE_ROOM,
                    )
        else:
            if action == "kick":
                raise AuthError(403, "The target user is not in the room")

        is_host_in_room = await self._is_host_in_room(state_before_join)

        if effective_membership_state == Membership.JOIN:
            if requester.is_guest:
                guest_can_join = await self._can_guest_join(state_before_join)
                if not guest_can_join:
                    # This should be an auth check, but guests are a local concept,
                    # so don't really fit into the general auth process.
                    raise AuthError(403, "Guest access not allowed")

            # Figure out whether the user is a server admin to determine whether they
            # should be able to bypass the spam checker.
            if (
                self._server_notices_mxid is not None
                and requester.user.to_string() == self._server_notices_mxid
            ):
                # allow the server notices mxid to join rooms
                bypass_spam_checker = True

            else:
                bypass_spam_checker = await self.auth.is_server_admin(requester)

            inviter = await self._get_inviter(target.to_string(), room_id)
            if (
                not bypass_spam_checker
                # We assume that if the spam checker allowed the user to create
                # a room then they're allowed to join it.
                and not new_room
            ):
                spam_check = await self.spam_checker.user_may_join_room(
                    target.to_string(), room_id, is_invited=inviter is not None
                )
                if spam_check != NOT_SPAM:
                    raise SynapseError(
                        403,
                        "Not allowed to join this room",
                        errcode=spam_check[0],
                        additional_fields=spam_check[1],
                    )

            # Check if a remote join should be performed.
            remote_join, remote_room_hosts = await self._should_perform_remote_join(
                target.to_string(),
                room_id,
                remote_room_hosts,
                content,
                is_host_in_room,
                state_before_join,
            )
            if remote_join:
                if ratelimit:
                    await self._join_rate_limiter_remote.ratelimit(
                        requester,
                    )
                    await self._join_rate_per_room_limiter.ratelimit(
                        requester,
                        key=room_id,
                        update=False,
                    )

                inviter = await self._get_inviter(target.to_string(), room_id)
                if inviter and not self.hs.is_mine(inviter):
                    remote_room_hosts.append(inviter.domain)

                content["membership"] = Membership.JOIN

                try:
                    profile = self.profile_handler
                    if not content_specified:
                        content["displayname"] = await profile.get_displayname(target)
                        content["avatar_url"] = await profile.get_avatar_url(target)
                except Exception as e:
                    logger.info(
                        "Failed to get profile information while processing remote join for %r: %s",
                        target,
                        e,
                    )

                if requester.is_guest:
                    content["kind"] = "guest"

                remote_join_response = await self._remote_join(
                    requester, remote_room_hosts, room_id, target, content
                )

                return remote_join_response

        elif effective_membership_state == Membership.LEAVE:
            if not is_host_in_room:
                # Figure out the user's current membership state for the room
                (
                    current_membership_type,
                    current_membership_event_id,
                ) = await self.store.get_local_current_membership_for_user_in_room(
                    target.to_string(), room_id
                )
                if not current_membership_type or not current_membership_event_id:
                    logger.info(
                        "%s sent a leave request to %s, but that is not an active room "
                        "on this server, or there is no pending invite or knock",
                        target,
                        room_id,
                    )

                    raise SynapseError(404, "Not a known room")

                # perhaps we've been invited
                if current_membership_type == Membership.INVITE:
                    invite = await self.store.get_event(current_membership_event_id)
                    logger.info(
                        "%s rejects invite to %s from %s",
                        target,
                        room_id,
                        invite.sender,
                    )

                    if not self.hs.is_mine_id(invite.sender):
                        # send the rejection to the inviter's HS (with fallback to
                        # local event)
                        return await self.remote_reject_invite(
                            invite.event_id,
                            txn_id,
                            requester,
                            content,
                        )

                    # the inviter was on our server, but has now left. Carry on
                    # with the normal rejection codepath, which will also send the
                    # rejection out to any other servers we believe are still in the room.

                    # thanks to overzealous cleaning up of event_forward_extremities in
                    # `delete_old_current_state_events`, it's possible to end up with no
                    # forward extremities here. If that happens, let's just hang the
                    # rejection off the invite event.
                    #
                    # see: https://github.com/matrix-org/synapse/issues/7139
                    if len(latest_event_ids) == 0:
                        latest_event_ids = [invite.event_id]

                # or perhaps this is a remote room that a local user has knocked on
                elif current_membership_type == Membership.KNOCK:
                    knock = await self.store.get_event(current_membership_event_id)
                    return await self.remote_rescind_knock(
                        knock.event_id, txn_id, requester, content
                    )

        elif effective_membership_state == Membership.KNOCK:
            if not is_host_in_room:
                # The knock needs to be sent over federation instead
                remote_room_hosts.append(get_domain_from_id(room_id))

                content["membership"] = Membership.KNOCK

                try:
                    profile = self.profile_handler
                    if "displayname" not in content:
                        content["displayname"] = await profile.get_displayname(target)
                    if "avatar_url" not in content:
                        content["avatar_url"] = await profile.get_avatar_url(target)
                except Exception as e:
                    logger.info(
                        "Failed to get profile information while processing remote knock for %r: %s",
                        target,
                        e,
                    )

                return await self.remote_knock(
                    remote_room_hosts, room_id, target, content
                )

        return await self._local_membership_update(
            requester=requester,
            target=target,
            room_id=room_id,
            membership=effective_membership_state,
            txn_id=txn_id,
            ratelimit=ratelimit,
            prev_event_ids=latest_event_ids,
            state_event_ids=state_event_ids,
            depth=depth,
            content=content,
            require_consent=require_consent,
            outlier=outlier,
            origin_server_ts=origin_server_ts,
        )

    async def _should_perform_remote_join(
        self,
        user_id: str,
        room_id: str,
        remote_room_hosts: List[str],
        content: JsonDict,
        is_host_in_room: bool,
        state_before_join: StateMap[str],
    ) -> Tuple[bool, List[str]]:
        """
        Check whether the server should do a remote join (as opposed to a local
        join) for a user.

        Generally a remote join is used if:

        * The server is not yet in the room.
        * The server is in the room, the room has restricted join rules, the user
          is not joined or invited to the room, and the server does not have
          another user who is capable of issuing invites.

        Args:
            user_id: The user joining the room.
            room_id: The room being joined.
            remote_room_hosts: A list of remote room hosts.
            content: The content to use as the event body of the join. This may
                be modified.
            is_host_in_room: True if the host is in the room.
            state_before_join: The state before the join event (i.e. the resolution of
                the states after its parent events).

        Returns:
            A tuple of:
                True if a remote join should be performed. False if the join can be
                done locally.

                A list of remote room hosts to use. This is an empty list if a
                local join is to be done.
        """
        # If the host isn't in the room, pass through the prospective hosts.
        if not is_host_in_room:
            return True, remote_room_hosts

        # If the host is in the room, but not one of the authorised hosts
        # for restricted join rules, a remote join must be used.
        room_version = await self.store.get_room_version(room_id)

        # If restricted join rules are not being used, a local join can always
        # be used.
        if not await self.event_auth_handler.has_restricted_join_rules(
            state_before_join, room_version
        ):
            return False, []

        # If the user is invited to the room or already joined, the join
        # event can always be issued locally.
        prev_member_event_id = state_before_join.get((EventTypes.Member, user_id), None)
        prev_member_event = None
        if prev_member_event_id:
            prev_member_event = await self.store.get_event(prev_member_event_id)
            if prev_member_event.membership in (
                Membership.JOIN,
                Membership.INVITE,
            ):
                return False, []

        # If the local host has a user who can issue invites, then a local
        # join can be done.
        #
        # If not, generate a new list of remote hosts based on which
        # can issue invites.
        event_map = await self.store.get_events(state_before_join.values())
        current_state = {
            state_key: event_map[event_id]
            for state_key, event_id in state_before_join.items()
        }
        allowed_servers = get_servers_from_users(
            get_users_which_can_issue_invite(current_state)
        )

        # If the local server is not one of allowed servers, then a remote
        # join must be done. Return the list of prospective servers based on
        # which can issue invites.
        if self.hs.hostname not in allowed_servers:
            return True, list(allowed_servers)

        # Ensure the member should be allowed access via membership in a room.
        await self.event_auth_handler.check_restricted_join_rules(
            state_before_join, room_version, user_id, prev_member_event
        )

        # If this is going to be a local join, additional information must
        # be included in the event content in order to efficiently validate
        # the event.
        content[
            EventContentFields.AUTHORISING_USER
        ] = await self.event_auth_handler.get_user_which_could_invite(
            room_id,
            state_before_join,
        )

        return False, []

    async def transfer_room_state_on_room_upgrade(
        self, old_room_id: str, room_id: str
    ) -> None:
        """Upon our server becoming aware of an upgraded room, either by upgrading a room
        ourselves or joining one, we can transfer over information from the previous room.

        Copies user state (tags/push rules) for every local user that was in the old room, as
        well as migrating the room directory state.

        Args:
            old_room_id: The ID of the old room
            room_id: The ID of the new room
        """
        logger.info("Transferring room state from %s to %s", old_room_id, room_id)

        # Find all local users that were in the old room and copy over each user's state
        local_users = await self.store.get_local_users_in_room(old_room_id)
        await self.copy_user_state_on_room_upgrade(old_room_id, room_id, local_users)

        # Add new room to the room directory if the old room was there
        # Remove old room from the room directory
        old_room = await self.store.get_room(old_room_id)
        if old_room is not None and old_room["is_public"]:
            await self.store.set_room_is_public(old_room_id, False)
            await self.store.set_room_is_public(room_id, True)

        # Transfer alias mappings in the room directory
        await self.store.update_aliases_for_room(old_room_id, room_id)

    async def copy_user_state_on_room_upgrade(
        self, old_room_id: str, new_room_id: str, user_ids: Iterable[str]
    ) -> None:
        """Copy user-specific information when they join a new room when that new room is the
        result of a room upgrade

        Args:
            old_room_id: The ID of upgraded room
            new_room_id: The ID of the new room
            user_ids: User IDs to copy state for
        """

        logger.debug(
            "Copying over room tags and push rules from %s to %s for users %s",
            old_room_id,
            new_room_id,
            user_ids,
        )

        for user_id in user_ids:
            try:
                # It is an upgraded room. Copy over old tags
                await self.copy_room_tags_and_direct_to_room(
                    old_room_id, new_room_id, user_id
                )
                # Copy over push rules
                await self.store.copy_push_rules_from_room_to_room_for_user(
                    old_room_id, new_room_id, user_id
                )
            except Exception:
                logger.exception(
                    "Error copying tags and/or push rules from rooms %s to %s for user %s. "
                    "Skipping...",
                    old_room_id,
                    new_room_id,
                    user_id,
                )
                continue

    async def send_membership_event(
        self,
        requester: Optional[Requester],
        event: EventBase,
        context: EventContext,
        ratelimit: bool = True,
    ) -> None:
        """
        Change the membership status of a user in a room.

        Args:
            requester: The local user who requested the membership
                event. If None, certain checks, like whether this homeserver can
                act as the sender, will be skipped.
            event: The membership event.
            context: The context of the event.
            ratelimit: Whether to rate limit this request.
        Raises:
            SynapseError if there was a problem changing the membership.
        """
        target_user = UserID.from_string(event.state_key)
        room_id = event.room_id

        if requester is not None:
            sender = UserID.from_string(event.sender)
            assert (
                sender == requester.user
            ), "Sender (%s) must be same as requester (%s)" % (sender, requester.user)
            assert self.hs.is_mine(sender), "Sender must be our own: %s" % (sender,)
        else:
            requester = types.create_requester(target_user)

        prev_state_ids = await context.get_prev_state_ids(
            StateFilter.from_types([(EventTypes.GuestAccess, None)])
        )
        if event.membership == Membership.JOIN:
            if requester.is_guest:
                guest_can_join = await self._can_guest_join(prev_state_ids)
                if not guest_can_join:
                    # This should be an auth check, but guests are a local concept,
                    # so don't really fit into the general auth process.
                    raise AuthError(403, "Guest access not allowed")

        if event.membership not in (Membership.LEAVE, Membership.BAN):
            is_blocked = await self.store.is_room_blocked(room_id)
            if is_blocked:
                raise SynapseError(403, "This room has been blocked on this server")

        event = await self.event_creation_handler.handle_new_client_event(
            requester,
            events_and_context=[(event, context)],
            extra_users=[target_user],
            ratelimit=ratelimit,
        )

        prev_member_event_id = prev_state_ids.get(
            (EventTypes.Member, event.state_key), None
        )

        if event.membership == Membership.LEAVE:
            if prev_member_event_id:
                prev_member_event = await self.store.get_event(prev_member_event_id)
                if prev_member_event.membership == Membership.JOIN:
                    await self._user_left_room(target_user, room_id)

    async def _can_guest_join(self, current_state_ids: StateMap[str]) -> bool:
        """
        Returns whether a guest can join a room based on its current state.
        """
        guest_access_id = current_state_ids.get((EventTypes.GuestAccess, ""), None)
        if not guest_access_id:
            return False

        guest_access = await self.store.get_event(guest_access_id)

        return bool(
            guest_access
            and guest_access.content
            and guest_access.content.get(EventContentFields.GUEST_ACCESS)
            == GuestAccess.CAN_JOIN
        )

    async def kick_guest_users(self, current_state: Iterable[EventBase]) -> None:
        """Kick any local guest users from the room.

        This is called when the room state changes from guests allowed to not-allowed.

        Params:
            current_state: the current state of the room. We will iterate this to look
               for guest users to kick.
        """
        for member_event in current_state:
            try:
                if member_event.type != EventTypes.Member:
                    continue

                if not self.hs.is_mine_id(member_event.state_key):
                    continue

                if member_event.content["membership"] not in {
                    Membership.JOIN,
                    Membership.INVITE,
                }:
                    continue

                if (
                    "kind" not in member_event.content
                    or member_event.content["kind"] != "guest"
                ):
                    continue

                # We make the user choose to leave, rather than have the
                # event-sender kick them. This is partially because we don't
                # need to worry about power levels, and partially because guest
                # users are a concept which doesn't hugely work over federation,
                # and having homeservers have their own users leave keeps more
                # of that decision-making and control local to the guest-having
                # homeserver.
                target_user = UserID.from_string(member_event.state_key)
                requester = create_requester(
                    target_user, is_guest=True, authenticated_entity=self._server_name
                )
                handler = self.hs.get_room_member_handler()
                await handler.update_membership(
                    requester,
                    target_user,
                    member_event.room_id,
                    "leave",
                    ratelimit=False,
                    require_consent=False,
                )
            except Exception as e:
                logger.exception("Error kicking guest user: %s" % (e,))

    async def lookup_room_alias(
        self, room_alias: RoomAlias
    ) -> Tuple[RoomID, List[str]]:
        """
        Get the room ID associated with a room alias.

        Args:
            room_alias: The alias to look up.
        Returns:
            A tuple of:
                The room ID as a RoomID object.
                Hosts likely to be participating in the room ([str]).
        Raises:
            SynapseError if room alias could not be found.
        """
        directory_handler = self.directory_handler
        mapping = await directory_handler.get_association(room_alias)

        if not mapping:
            raise SynapseError(404, "No such room alias")

        room_id = mapping["room_id"]
        servers = mapping["servers"]

        # put the server which owns the alias at the front of the server list.
        if room_alias.domain in servers:
            servers.remove(room_alias.domain)
        servers.insert(0, room_alias.domain)

        return RoomID.from_string(room_id), servers

    async def _get_inviter(self, user_id: str, room_id: str) -> Optional[UserID]:
        invite = await self.store.get_invite_for_local_user_in_room(
            user_id=user_id, room_id=room_id
        )
        if invite:
            return UserID.from_string(invite.sender)
        return None

    async def do_3pid_invite(
        self,
        room_id: str,
        inviter: UserID,
        medium: str,
        address: str,
        id_server: str,
        requester: Requester,
        txn_id: Optional[str],
        id_access_token: str,
        prev_event_ids: Optional[List[str]] = None,
        depth: Optional[int] = None,
    ) -> Tuple[str, int]:
        """Invite a 3PID to a room.

        Args:
            room_id: The room to invite the 3PID to.
            inviter: The user sending the invite.
            medium: The 3PID's medium.
            address: The 3PID's address.
            id_server: The identity server to use.
            requester: The user making the request.
            txn_id: The transaction ID this is part of, or None if this is not
                part of a transaction.
            id_access_token: Identity server access token.
            depth: Override the depth used to order the event in the DAG.
            prev_event_ids: The event IDs to use as the prev events
                Should normally be set to None, which will cause the depth to be calculated
                based on the prev_events.

        Returns:
            Tuple of event ID and stream ordering position

        Raises:
            ShadowBanError if the requester has been shadow-banned.
        """
        if self.config.server.block_non_admin_invites:
            is_requester_admin = await self.auth.is_server_admin(requester)
            if not is_requester_admin:
                raise SynapseError(
                    403, "Invites have been disabled on this server", Codes.FORBIDDEN
                )

        if requester.shadow_banned:
            # We randomly sleep a bit just to annoy the requester.
            await self.clock.sleep(random.randint(1, 10))
            raise ShadowBanError()

        # We need to rate limit *before* we send out any 3PID invites, so we
        # can't just rely on the standard ratelimiting of events.
        await self._third_party_invite_limiter.ratelimit(requester)

        can_invite = await self.third_party_event_rules.check_threepid_can_be_invited(
            medium, address, room_id
        )
        if not can_invite:
            raise SynapseError(
                403,
                "This third-party identifier can not be invited in this room",
                Codes.FORBIDDEN,
            )

        if not self._enable_lookup:
            raise SynapseError(
                403, "Looking up third-party identifiers is denied from this server"
            )

        invitee = await self.identity_handler.lookup_3pid(
            id_server, medium, address, id_access_token
        )

        if invitee:
            # Note that update_membership with an action of "invite" can raise
            # a ShadowBanError, but this was done above already.
            # We don't check the invite against the spamchecker(s) here (through
            # user_may_invite) because we'll do it further down the line anyway (in
            # update_membership_locked).
            event_id, stream_id = await self.update_membership(
                requester, UserID.from_string(invitee), room_id, "invite", txn_id=txn_id
            )
        else:
            # Check if the spamchecker(s) allow this invite to go through.
            spam_check = await self.spam_checker.user_may_send_3pid_invite(
                inviter_userid=requester.user.to_string(),
                medium=medium,
                address=address,
                room_id=room_id,
            )
            if spam_check != NOT_SPAM:
                raise SynapseError(
                    403,
                    "Cannot send threepid invite",
                    errcode=spam_check[0],
                    additional_fields=spam_check[1],
                )

            event, stream_id = await self._make_and_store_3pid_invite(
                requester,
                id_server,
                medium,
                address,
                room_id,
                inviter,
                txn_id=txn_id,
                id_access_token=id_access_token,
                prev_event_ids=prev_event_ids,
                depth=depth,
            )
            event_id = event.event_id

        return event_id, stream_id

    async def _make_and_store_3pid_invite(
        self,
        requester: Requester,
        id_server: str,
        medium: str,
        address: str,
        room_id: str,
        user: UserID,
        txn_id: Optional[str],
        id_access_token: str,
        prev_event_ids: Optional[List[str]] = None,
        depth: Optional[int] = None,
    ) -> Tuple[EventBase, int]:
        room_state = await self._storage_controllers.state.get_current_state(
            room_id,
            StateFilter.from_types(
                [
                    (EventTypes.Member, user.to_string()),
                    (EventTypes.CanonicalAlias, ""),
                    (EventTypes.Name, ""),
                    (EventTypes.Create, ""),
                    (EventTypes.JoinRules, ""),
                    (EventTypes.RoomAvatar, ""),
                ]
            ),
        )

        inviter_display_name = ""
        inviter_avatar_url = ""
        member_event = room_state.get((EventTypes.Member, user.to_string()))
        if member_event:
            inviter_display_name = member_event.content.get("displayname", "")
            inviter_avatar_url = member_event.content.get("avatar_url", "")

        # if user has no display name, default to their MXID
        if not inviter_display_name:
            inviter_display_name = user.to_string()

        canonical_room_alias = ""
        canonical_alias_event = room_state.get((EventTypes.CanonicalAlias, ""))
        if canonical_alias_event:
            canonical_room_alias = canonical_alias_event.content.get("alias", "")

        room_name = ""
        room_name_event = room_state.get((EventTypes.Name, ""))
        if room_name_event:
            room_name = room_name_event.content.get("name", "")

        room_type = None
        room_create_event = room_state.get((EventTypes.Create, ""))
        if room_create_event:
            room_type = room_create_event.content.get(EventContentFields.ROOM_TYPE)

        room_join_rules = ""
        join_rules_event = room_state.get((EventTypes.JoinRules, ""))
        if join_rules_event:
            room_join_rules = join_rules_event.content.get("join_rule", "")

        room_avatar_url = ""
        room_avatar_event = room_state.get((EventTypes.RoomAvatar, ""))
        if room_avatar_event:
            room_avatar_url = room_avatar_event.content.get("url", "")

        (
            token,
            public_keys,
            fallback_public_key,
            display_name,
        ) = await self.identity_handler.ask_id_server_for_third_party_invite(
            requester=requester,
            id_server=id_server,
            medium=medium,
            address=address,
            room_id=room_id,
            inviter_user_id=user.to_string(),
            room_alias=canonical_room_alias,
            room_avatar_url=room_avatar_url,
            room_join_rules=room_join_rules,
            room_name=room_name,
            room_type=room_type,
            inviter_display_name=inviter_display_name,
            inviter_avatar_url=inviter_avatar_url,
            id_access_token=id_access_token,
        )

        (
            event,
            stream_id,
        ) = await self.event_creation_handler.create_and_send_nonmember_event(
            requester,
            {
                "type": EventTypes.ThirdPartyInvite,
                "content": {
                    "display_name": display_name,
                    "public_keys": public_keys,
                    # For backwards compatibility:
                    "key_validity_url": fallback_public_key["key_validity_url"],
                    "public_key": fallback_public_key["public_key"],
                },
                "room_id": room_id,
                "sender": user.to_string(),
                "state_key": token,
            },
            ratelimit=False,
            txn_id=txn_id,
            prev_event_ids=prev_event_ids,
            depth=depth,
        )
        return event, stream_id

    async def _is_host_in_room(self, current_state_ids: StateMap[str]) -> bool:
        # Have we just created the room, and is this about to be the very
        # first member event?
        create_event_id = current_state_ids.get(("m.room.create", ""))
        if len(current_state_ids) == 1 and create_event_id:
            # We can only get here if we're in the process of creating the room
            return True

        for etype, state_key in current_state_ids:
            if etype != EventTypes.Member or not self.hs.is_mine_id(state_key):
                continue

            event_id = current_state_ids[(etype, state_key)]
            event = await self.store.get_event(event_id, allow_none=True)
            if not event:
                continue

            if event.membership == Membership.JOIN:
                return True

        return False


class RoomMemberMasterHandler(RoomMemberHandler):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.distributor = hs.get_distributor()
        self.distributor.declare("user_left_room")

    async def _is_remote_room_too_complex(
        self, room_id: str, remote_room_hosts: List[str]
    ) -> Optional[bool]:
        """
        Check if complexity of a remote room is too great.

        Args:
            room_id
            remote_room_hosts

        Returns: bool of whether the complexity is too great, or None
            if unable to be fetched
        """
        max_complexity = self.hs.config.server.limit_remote_rooms.complexity
        complexity = await self.federation_handler.get_room_complexity(
            remote_room_hosts, room_id
        )

        if complexity:
            return complexity["v1"] > max_complexity
        return None

    async def _is_local_room_too_complex(self, room_id: str) -> bool:
        """
        Check if the complexity of a local room is too great.

        Args:
            room_id: The room ID to check for complexity.
        """
        max_complexity = self.hs.config.server.limit_remote_rooms.complexity
        complexity = await self.store.get_room_complexity(room_id)

        return complexity["v1"] > max_complexity

    async def _remote_join(
        self,
        requester: Requester,
        remote_room_hosts: List[str],
        room_id: str,
        user: UserID,
        content: dict,
    ) -> Tuple[str, int]:
        """Implements RoomMemberHandler._remote_join"""
        # filter ourselves out of remote_room_hosts: do_invite_join ignores it
        # and if it is the only entry we'd like to return a 404 rather than a
        # 500.
        remote_room_hosts = [
            host for host in remote_room_hosts if host != self.hs.hostname
        ]

        if len(remote_room_hosts) == 0:
            raise SynapseError(
                404,
                "Can't join remote room because no servers "
                "that are in the room have been provided.",
            )

        check_complexity = self.hs.config.server.limit_remote_rooms.enabled
        if (
            check_complexity
            and self.hs.config.server.limit_remote_rooms.admins_can_join
        ):
            check_complexity = not await self.store.is_server_admin(user)

        if check_complexity:
            # Fetch the room complexity
            too_complex = await self._is_remote_room_too_complex(
                room_id, remote_room_hosts
            )
            if too_complex is True:
                raise SynapseError(
                    code=400,
                    msg=self.hs.config.server.limit_remote_rooms.complexity_error,
                    errcode=Codes.RESOURCE_LIMIT_EXCEEDED,
                )

        # We don't do an auth check if we are doing an invite
        # join dance for now, since we're kinda implicitly checking
        # that we are allowed to join when we decide whether or not we
        # need to do the invite/join dance.
        event_id, stream_id = await self.federation_handler.do_invite_join(
            remote_room_hosts, room_id, user.to_string(), content
        )

        # Check the room we just joined wasn't too large, if we didn't fetch the
        # complexity of it before.
        if check_complexity:
            if too_complex is False:
                # We checked, and we're under the limit.
                return event_id, stream_id

            # Check again, but with the local state events
            too_complex = await self._is_local_room_too_complex(room_id)

            if too_complex is False:
                # We're under the limit.
                return event_id, stream_id

            # The room is too large. Leave.
            requester = types.create_requester(
                user, authenticated_entity=self._server_name
            )
            await self.update_membership(
                requester=requester, target=user, room_id=room_id, action="leave"
            )
            raise SynapseError(
                code=400,
                msg=self.hs.config.server.limit_remote_rooms.complexity_error,
                errcode=Codes.RESOURCE_LIMIT_EXCEEDED,
            )

        return event_id, stream_id

    async def remote_reject_invite(
        self,
        invite_event_id: str,
        txn_id: Optional[str],
        requester: Requester,
        content: JsonDict,
    ) -> Tuple[str, int]:
        """
        Rejects an out-of-band invite received from a remote user

        Implements RoomMemberHandler.remote_reject_invite
        """
        invite_event = await self.store.get_event(invite_event_id)
        room_id = invite_event.room_id
        target_user = invite_event.state_key

        # first of all, try doing a rejection via the inviting server
        fed_handler = self.federation_handler
        try:
            inviter_id = UserID.from_string(invite_event.sender)
            event, stream_id = await fed_handler.do_remotely_reject_invite(
                [inviter_id.domain], room_id, target_user, content=content
            )
            return event.event_id, stream_id
        except Exception as e:
            # if we were unable to reject the invite, we will generate our own
            # leave event.
            #
            # The 'except' clause is very broad, but we need to
            # capture everything from DNS failures upwards
            #
            logger.warning("Failed to reject invite: %s", e)

            return await self._generate_local_out_of_band_leave(
                invite_event, txn_id, requester, content
            )

    async def remote_rescind_knock(
        self,
        knock_event_id: str,
        txn_id: Optional[str],
        requester: Requester,
        content: JsonDict,
    ) -> Tuple[str, int]:
        """
        Rescinds a local knock made on a remote room

        Args:
            knock_event_id: The ID of the knock event to rescind.
            txn_id: The transaction ID to use.
            requester: The originator of the request.
            content: The content of the leave event.

        Implements RoomMemberHandler.remote_rescind_knock
        """
        # TODO: We don't yet support rescinding knocks over federation
        # as we don't know which homeserver to send it to. An obvious
        # candidate is the remote homeserver we originally knocked through,
        # however we don't currently store that information.

        # Just rescind the knock locally
        knock_event = await self.store.get_event(knock_event_id)
        return await self._generate_local_out_of_band_leave(
            knock_event, txn_id, requester, content
        )

    async def _generate_local_out_of_band_leave(
        self,
        previous_membership_event: EventBase,
        txn_id: Optional[str],
        requester: Requester,
        content: JsonDict,
    ) -> Tuple[str, int]:
        """Generate a local leave event for a room

        This can be called after we e.g fail to reject an invite via a remote server.
        It generates an out-of-band membership event locally.

        Args:
            previous_membership_event: the previous membership event for this user
            txn_id: optional transaction ID supplied by the client
            requester: user making the request, according to the access token
            content: additional content to include in the leave event.
               Normally an empty dict.

        Returns:
            A tuple containing (event_id, stream_id of the leave event)
        """
        room_id = previous_membership_event.room_id
        target_user = previous_membership_event.state_key

        content["membership"] = Membership.LEAVE

        event_dict = {
            "type": EventTypes.Member,
            "room_id": room_id,
            "sender": target_user,
            "content": content,
            "state_key": target_user,
        }

        # the auth events for the new event are the same as that of the previous event, plus
        # the event itself.
        #
        # the prev_events consist solely of the previous membership event.
        prev_event_ids = [previous_membership_event.event_id]
        auth_event_ids = (
            list(previous_membership_event.auth_event_ids()) + prev_event_ids
        )

        event, context = await self.event_creation_handler.create_event(
            requester,
            event_dict,
            txn_id=txn_id,
            prev_event_ids=prev_event_ids,
            auth_event_ids=auth_event_ids,
            outlier=True,
        )
        event.internal_metadata.out_of_band_membership = True

        result_event = await self.event_creation_handler.handle_new_client_event(
            requester,
            events_and_context=[(event, context)],
            extra_users=[UserID.from_string(target_user)],
        )
        # we know it was persisted, so must have a stream ordering
        assert result_event.internal_metadata.stream_ordering

        return result_event.event_id, result_event.internal_metadata.stream_ordering

    async def remote_knock(
        self,
        remote_room_hosts: List[str],
        room_id: str,
        user: UserID,
        content: dict,
    ) -> Tuple[str, int]:
        """Sends a knock to a room. Attempts to do so via one remote out of a given list.

        Args:
            remote_room_hosts: A list of homeservers to try knocking through.
            room_id: The ID of the room to knock on.
            user: The user to knock on behalf of.
            content: The content of the knock event.

        Returns:
            A tuple of (event ID, stream ID).
        """
        # filter ourselves out of remote_room_hosts
        remote_room_hosts = [
            host for host in remote_room_hosts if host != self.hs.hostname
        ]

        if len(remote_room_hosts) == 0:
            raise SynapseError(404, "No known servers")

        return await self.federation_handler.do_knock(
            remote_room_hosts, room_id, user.to_string(), content=content
        )

    async def _user_left_room(self, target: UserID, room_id: str) -> None:
        """Implements RoomMemberHandler._user_left_room"""
        user_left_room(self.distributor, target, room_id)

    async def forget(self, user: UserID, room_id: str) -> None:
        user_id = user.to_string()

        member = await self._storage_controllers.state.get_current_state_event(
            room_id=room_id, event_type=EventTypes.Member, state_key=user_id
        )
        membership = member.membership if member else None

        if membership is not None and membership not in [
            Membership.LEAVE,
            Membership.BAN,
        ]:
            raise SynapseError(400, "User %s in room %s" % (user_id, room_id))

        # In normal case this call is only required if `membership` is not `None`.
        # But: After the last member had left the room, the background update
        # `_background_remove_left_rooms` is deleting rows related to this room from
        # the table `current_state_events` and `get_current_state_events` is `None`.
        await self.store.forget(user_id, room_id)


def get_users_which_can_issue_invite(auth_events: StateMap[EventBase]) -> List[str]:
    """
    Return the list of users which can issue invites.

    This is done by exploring the joined users and comparing their power levels
    to the necessyar power level to issue an invite.

    Args:
        auth_events: state in force at this point in the room

    Returns:
        The users which can issue invites.
    """
    invite_level = get_named_level(auth_events, "invite", 0)
    users_default_level = get_named_level(auth_events, "users_default", 0)
    power_level_event = get_power_level_event(auth_events)

    # Custom power-levels for users.
    if power_level_event:
        users = power_level_event.content.get("users", {})
    else:
        users = {}

    result = []

    # Check which members are able to invite by ensuring they're joined and have
    # the necessary power level.
    for (event_type, state_key), event in auth_events.items():
        if event_type != EventTypes.Member:
            continue

        if event.membership != Membership.JOIN:
            continue

        # Check if the user has a custom power level.
        if users.get(state_key, users_default_level) >= invite_level:
            result.append(state_key)

    return result


def get_servers_from_users(users: List[str]) -> Set[str]:
    """
    Resolve a list of users into their servers.

    Args:
        users: A list of users.

    Returns:
        A set of servers.
    """
    servers = set()
    for user in users:
        try:
            servers.add(get_domain_from_id(user))
        except SynapseError:
            pass
    return servers
