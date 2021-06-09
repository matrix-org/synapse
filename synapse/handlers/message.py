# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017-2018 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
import random
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Tuple

from canonicaljson import encode_canonical_json

from twisted.internet import defer
from twisted.internet.interfaces import IDelayedCall

from synapse import event_auth
from synapse.api.constants import (
    EventContentFields,
    EventTypes,
    Membership,
    RelationTypes,
    UserTypes,
)
from synapse.api.errors import (
    AuthError,
    Codes,
    ConsentNotGivenError,
    NotFoundError,
    ShadowBanError,
    SynapseError,
)
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS, RoomVersions
from synapse.api.urls import ConsentURIBuilder
from synapse.events import EventBase
from synapse.events.builder import EventBuilder
from synapse.events.snapshot import EventContext
from synapse.events.validator import EventValidator
from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.replication.http.send_event import ReplicationSendEventRestServlet
from synapse.storage.databases.main.events_worker import EventRedactBehaviour
from synapse.storage.state import StateFilter
from synapse.types import Requester, RoomAlias, StreamToken, UserID, create_requester
from synapse.util import json_decoder, json_encoder, log_failure
from synapse.util.async_helpers import Linearizer, unwrapFirstError
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.metrics import measure_func
from synapse.visibility import filter_events_for_client

from ._base import BaseHandler

if TYPE_CHECKING:
    from synapse.events.third_party_rules import ThirdPartyEventRules
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class MessageHandler:
    """Contains some read only APIs to get state about a room"""

    def __init__(self, hs: "HomeServer"):
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.state = hs.get_state_handler()
        self.store = hs.get_datastore()
        self.storage = hs.get_storage()
        self.state_store = self.storage.state
        self._event_serializer = hs.get_event_client_serializer()
        self._ephemeral_events_enabled = hs.config.enable_ephemeral_messages

        # The scheduled call to self._expire_event. None if no call is currently
        # scheduled.
        self._scheduled_expiry = None  # type: Optional[IDelayedCall]

        if not hs.config.worker_app:
            run_as_background_process(
                "_schedule_next_expiry", self._schedule_next_expiry
            )

    async def get_room_data(
        self,
        user_id: str,
        room_id: str,
        event_type: str,
        state_key: str,
    ) -> Optional[EventBase]:
        """Get data from a room.

        Args:
            user_id
            room_id
            event_type
            state_key
        Returns:
            The path data content.
        Raises:
            SynapseError or AuthError if the user is not in the room
        """
        (
            membership,
            membership_event_id,
        ) = await self.auth.check_user_in_room_or_world_readable(
            room_id, user_id, allow_departed_users=True
        )

        if membership == Membership.JOIN:
            data = await self.state.get_current_state(room_id, event_type, state_key)
        elif membership == Membership.LEAVE:
            key = (event_type, state_key)
            # If the membership is not JOIN, then the event ID should exist.
            assert (
                membership_event_id is not None
            ), "check_user_in_room_or_world_readable returned invalid data"
            room_state = await self.state_store.get_state_for_events(
                [membership_event_id], StateFilter.from_types([key])
            )
            data = room_state[membership_event_id].get(key)
        else:
            # check_user_in_room_or_world_readable, if it doesn't raise an AuthError, should
            # only ever return a Membership.JOIN/LEAVE object
            #
            # Safeguard in case it returned something else
            logger.error(
                "Attempted to retrieve data from a room for a user that has never been in it. "
                "This should not have happened."
            )
            raise SynapseError(403, "User not in room", errcode=Codes.FORBIDDEN)

        return data

    async def get_state_events(
        self,
        user_id: str,
        room_id: str,
        state_filter: Optional[StateFilter] = None,
        at_token: Optional[StreamToken] = None,
        is_guest: bool = False,
    ) -> List[dict]:
        """Retrieve all state events for a given room. If the user is
        joined to the room then return the current state. If the user has
        left the room return the state events from when they left. If an explicit
        'at' parameter is passed, return the state events as of that event, if
        visible.

        Args:
            user_id: The user requesting state events.
            room_id: The room ID to get all state events from.
            state_filter: The state filter used to fetch state from the database.
            at_token: the stream token of the at which we are requesting
                the stats. If the user is not allowed to view the state as of that
                stream token, we raise a 403 SynapseError. If None, returns the current
                state based on the current_state_events table.
            is_guest: whether this user is a guest
        Returns:
            A list of dicts representing state events. [{}, {}, {}]
        Raises:
            NotFoundError (404) if the at token does not yield an event

            AuthError (403) if the user doesn't have permission to view
            members of this room.
        """
        state_filter = state_filter or StateFilter.all()

        if at_token:
            # FIXME this claims to get the state at a stream position, but
            # get_recent_events_for_room operates by topo ordering. This therefore
            # does not reliably give you the state at the given stream position.
            # (https://github.com/matrix-org/synapse/issues/3305)
            last_events, _ = await self.store.get_recent_events_for_room(
                room_id, end_token=at_token.room_key, limit=1
            )

            if not last_events:
                raise NotFoundError("Can't find event for token %s" % (at_token,))

            visible_events = await filter_events_for_client(
                self.storage,
                user_id,
                last_events,
                filter_send_to_client=False,
            )

            event = last_events[0]
            if visible_events:
                room_state_events = await self.state_store.get_state_for_events(
                    [event.event_id], state_filter=state_filter
                )
                room_state = room_state_events[
                    event.event_id
                ]  # type: Mapping[Any, EventBase]
            else:
                raise AuthError(
                    403,
                    "User %s not allowed to view events in room %s at token %s"
                    % (user_id, room_id, at_token),
                )
        else:
            (
                membership,
                membership_event_id,
            ) = await self.auth.check_user_in_room_or_world_readable(
                room_id, user_id, allow_departed_users=True
            )

            if membership == Membership.JOIN:
                state_ids = await self.store.get_filtered_current_state_ids(
                    room_id, state_filter=state_filter
                )
                room_state = await self.store.get_events(state_ids.values())
            elif membership == Membership.LEAVE:
                # If the membership is not JOIN, then the event ID should exist.
                assert (
                    membership_event_id is not None
                ), "check_user_in_room_or_world_readable returned invalid data"
                room_state_events = await self.state_store.get_state_for_events(
                    [membership_event_id], state_filter=state_filter
                )
                room_state = room_state_events[membership_event_id]

        now = self.clock.time_msec()
        events = await self._event_serializer.serialize_events(
            room_state.values(),
            now,
            # We don't bother bundling aggregations in when asked for state
            # events, as clients won't use them.
            bundle_aggregations=False,
        )
        return events

    async def get_joined_members(self, requester: Requester, room_id: str) -> dict:
        """Get all the joined members in the room and their profile information.

        If the user has left the room return the state events from when they left.

        Args:
            requester: The user requesting state events.
            room_id: The room ID to get all state events from.
        Returns:
            A dict of user_id to profile info
        """
        user_id = requester.user.to_string()
        if not requester.app_service:
            # We check AS auth after fetching the room membership, as it
            # requires us to pull out all joined members anyway.
            membership, _ = await self.auth.check_user_in_room_or_world_readable(
                room_id, user_id, allow_departed_users=True
            )
            if membership != Membership.JOIN:
                raise NotImplementedError(
                    "Getting joined members after leaving is not implemented"
                )

        users_with_profile = await self.store.get_users_in_room_with_profiles(room_id)

        # If this is an AS, double check that they are allowed to see the members.
        # This can either be because the AS user is in the room or because there
        # is a user in the room that the AS is "interested in"
        if requester.app_service and user_id not in users_with_profile:
            for uid in users_with_profile:
                if requester.app_service.is_interested_in_user(uid):
                    break
            else:
                # Loop fell through, AS has no interested users in room
                raise AuthError(403, "Appservice not in room")

        return {
            user_id: {
                "avatar_url": profile.avatar_url,
                "display_name": profile.display_name,
            }
            for user_id, profile in users_with_profile.items()
        }

    def maybe_schedule_expiry(self, event: EventBase):
        """Schedule the expiry of an event if there's not already one scheduled,
        or if the one running is for an event that will expire after the provided
        timestamp.

        This function needs to invalidate the event cache, which is only possible on
        the master process, and therefore needs to be run on there.

        Args:
            event: The event to schedule the expiry of.
        """

        expiry_ts = event.content.get(EventContentFields.SELF_DESTRUCT_AFTER)
        if not isinstance(expiry_ts, int) or event.is_state():
            return

        # _schedule_expiry_for_event won't actually schedule anything if there's already
        # a task scheduled for a timestamp that's sooner than the provided one.
        self._schedule_expiry_for_event(event.event_id, expiry_ts)

    async def _schedule_next_expiry(self):
        """Retrieve the ID and the expiry timestamp of the next event to be expired,
        and schedule an expiry task for it.

        If there's no event left to expire, set _expiry_scheduled to None so that a
        future call to save_expiry_ts can schedule a new expiry task.
        """
        # Try to get the expiry timestamp of the next event to expire.
        res = await self.store.get_next_event_to_expire()
        if res:
            event_id, expiry_ts = res
            self._schedule_expiry_for_event(event_id, expiry_ts)

    def _schedule_expiry_for_event(self, event_id: str, expiry_ts: int):
        """Schedule an expiry task for the provided event if there's not already one
        scheduled at a timestamp that's sooner than the provided one.

        Args:
            event_id: The ID of the event to expire.
            expiry_ts: The timestamp at which to expire the event.
        """
        if self._scheduled_expiry:
            # If the provided timestamp refers to a time before the scheduled time of the
            # next expiry task, cancel that task and reschedule it for this timestamp.
            next_scheduled_expiry_ts = self._scheduled_expiry.getTime() * 1000
            if expiry_ts < next_scheduled_expiry_ts:
                self._scheduled_expiry.cancel()
            else:
                return

        # Figure out how many seconds we need to wait before expiring the event.
        now_ms = self.clock.time_msec()
        delay = (expiry_ts - now_ms) / 1000

        # callLater doesn't support negative delays, so trim the delay to 0 if we're
        # in that case.
        if delay < 0:
            delay = 0

        logger.info("Scheduling expiry for event %s in %.3fs", event_id, delay)

        self._scheduled_expiry = self.clock.call_later(
            delay,
            run_as_background_process,
            "_expire_event",
            self._expire_event,
            event_id,
        )

    async def _expire_event(self, event_id: str):
        """Retrieve and expire an event that needs to be expired from the database.

        If the event doesn't exist in the database, log it and delete the expiry date
        from the database (so that we don't try to expire it again).
        """
        assert self._ephemeral_events_enabled

        self._scheduled_expiry = None

        logger.info("Expiring event %s", event_id)

        try:
            # Expire the event if we know about it. This function also deletes the expiry
            # date from the database in the same database transaction.
            await self.store.expire_event(event_id)
        except Exception as e:
            logger.error("Could not expire event %s: %r", event_id, e)

        # Schedule the expiry of the next event to expire.
        await self._schedule_next_expiry()


# The duration (in ms) after which rooms should be removed
# `_rooms_to_exclude_from_dummy_event_insertion` (with the effect that we will try
# to generate a dummy event for them once more)
#
_DUMMY_EVENT_ROOM_EXCLUSION_EXPIRY = 7 * 24 * 60 * 60 * 1000


class EventCreationHandler:
    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()
        self.storage = hs.get_storage()
        self.state = hs.get_state_handler()
        self.clock = hs.get_clock()
        self.validator = EventValidator()
        self.profile_handler = hs.get_profile_handler()
        self.event_builder_factory = hs.get_event_builder_factory()
        self.server_name = hs.hostname
        self.notifier = hs.get_notifier()
        self.config = hs.config
        self.require_membership_for_aliases = hs.config.require_membership_for_aliases
        self._events_shard_config = self.config.worker.events_shard_config
        self._instance_name = hs.get_instance_name()

        self.room_invite_state_types = self.hs.config.api.room_prejoin_state

        self.membership_types_to_include_profile_data_in = (
            {Membership.JOIN, Membership.INVITE}
            if self.hs.config.include_profile_data_on_invite
            else {Membership.JOIN}
        )

        self.send_event = ReplicationSendEventRestServlet.make_client(hs)

        # This is only used to get at ratelimit function, and maybe_kick_guest_users
        self.base_handler = BaseHandler(hs)

        # We arbitrarily limit concurrent event creation for a room to 5.
        # This is to stop us from diverging history *too* much.
        self.limiter = Linearizer(max_count=5, name="room_event_creation_limit")

        self.action_generator = hs.get_action_generator()

        self.spam_checker = hs.get_spam_checker()
        self.third_party_event_rules = (
            self.hs.get_third_party_event_rules()
        )  # type: ThirdPartyEventRules

        self._block_events_without_consent_error = (
            self.config.block_events_without_consent_error
        )

        # we need to construct a ConsentURIBuilder here, as it checks that the necessary
        # config options, but *only* if we have a configuration for which we are
        # going to need it.
        if self._block_events_without_consent_error:
            self._consent_uri_builder = ConsentURIBuilder(self.config)

        # Rooms which should be excluded from dummy insertion. (For instance,
        # those without local users who can send events into the room).
        #
        # map from room id to time-of-last-attempt.
        #
        self._rooms_to_exclude_from_dummy_event_insertion = {}  # type: Dict[str, int]
        # The number of forward extremeities before a dummy event is sent.
        self._dummy_events_threshold = hs.config.dummy_events_threshold

        if (
            self.config.run_background_tasks
            and self.config.cleanup_extremities_with_dummy_events
        ):
            self.clock.looping_call(
                lambda: run_as_background_process(
                    "send_dummy_events_to_fill_extremities",
                    self._send_dummy_events_to_fill_extremities,
                ),
                5 * 60 * 1000,
            )

        self._message_handler = hs.get_message_handler()

        self._ephemeral_events_enabled = hs.config.enable_ephemeral_messages

        self._external_cache = hs.get_external_cache()

        # Stores the state groups we've recently added to the joined hosts
        # external cache. Note that the timeout must be significantly less than
        # the TTL on the external cache.
        self._external_cache_joined_hosts_updates = (
            None
        )  # type: Optional[ExpiringCache]
        if self._external_cache.is_enabled():
            self._external_cache_joined_hosts_updates = ExpiringCache(
                "_external_cache_joined_hosts_updates",
                self.clock,
                expiry_ms=30 * 60 * 1000,
            )

    async def create_event(
        self,
        requester: Requester,
        event_dict: dict,
        txn_id: Optional[str] = None,
        prev_event_ids: Optional[List[str]] = None,
        auth_event_ids: Optional[List[str]] = None,
        require_consent: bool = True,
    ) -> Tuple[EventBase, EventContext]:
        """
        Given a dict from a client, create a new event.

        Creates an FrozenEvent object, filling out auth_events, prev_events,
        etc.

        Adds display names to Join membership events.

        Args:
            requester
            event_dict: An entire event
            txn_id
            prev_event_ids:
                the forward extremities to use as the prev_events for the
                new event.

                If None, they will be requested from the database.

            auth_event_ids:
                The event ids to use as the auth_events for the new event.
                Should normally be left as None, which will cause them to be calculated
                based on the room state at the prev_events.

            require_consent: Whether to check if the requester has
                consented to the privacy policy.
        Raises:
            ResourceLimitError if server is blocked to some resource being
            exceeded
        Returns:
            Tuple of created event, Context
        """
        await self.auth.check_auth_blocking(requester=requester)

        if event_dict["type"] == EventTypes.Create and event_dict["state_key"] == "":
            room_version = event_dict["content"]["room_version"]
        else:
            try:
                room_version = await self.store.get_room_version_id(
                    event_dict["room_id"]
                )
            except NotFoundError:
                raise AuthError(403, "Unknown room")

        builder = self.event_builder_factory.new(room_version, event_dict)

        self.validator.validate_builder(builder)

        if builder.type == EventTypes.Member:
            membership = builder.content.get("membership", None)
            target = UserID.from_string(builder.state_key)

            if membership in self.membership_types_to_include_profile_data_in:
                # If event doesn't include a display name, add one.
                profile = self.profile_handler
                content = builder.content

                try:
                    if "displayname" not in content:
                        displayname = await profile.get_displayname(target)
                        if displayname is not None:
                            content["displayname"] = displayname
                    if "avatar_url" not in content:
                        avatar_url = await profile.get_avatar_url(target)
                        if avatar_url is not None:
                            content["avatar_url"] = avatar_url
                except Exception as e:
                    logger.info(
                        "Failed to get profile information for %r: %s", target, e
                    )

        is_exempt = await self._is_exempt_from_privacy_policy(builder, requester)
        if require_consent and not is_exempt:
            await self.assert_accepted_privacy_policy(requester)

        if requester.access_token_id is not None:
            builder.internal_metadata.token_id = requester.access_token_id

        if txn_id is not None:
            builder.internal_metadata.txn_id = txn_id

        event, context = await self.create_new_client_event(
            builder=builder,
            requester=requester,
            prev_event_ids=prev_event_ids,
            auth_event_ids=auth_event_ids,
        )

        # In an ideal world we wouldn't need the second part of this condition. However,
        # this behaviour isn't spec'd yet, meaning we should be able to deactivate this
        # behaviour. Another reason is that this code is also evaluated each time a new
        # m.room.aliases event is created, which includes hitting a /directory route.
        # Therefore not including this condition here would render the similar one in
        # synapse.handlers.directory pointless.
        if builder.type == EventTypes.Aliases and self.require_membership_for_aliases:
            # Ideally we'd do the membership check in event_auth.check(), which
            # describes a spec'd algorithm for authenticating events received over
            # federation as well as those created locally. As of room v3, aliases events
            # can be created by users that are not in the room, therefore we have to
            # tolerate them in event_auth.check().
            prev_state_ids = await context.get_prev_state_ids()
            prev_event_id = prev_state_ids.get((EventTypes.Member, event.sender))
            prev_event = (
                await self.store.get_event(prev_event_id, allow_none=True)
                if prev_event_id
                else None
            )
            if not prev_event or prev_event.membership != Membership.JOIN:
                logger.warning(
                    (
                        "Attempt to send `m.room.aliases` in room %s by user %s but"
                        " membership is %s"
                    ),
                    event.room_id,
                    event.sender,
                    prev_event.membership if prev_event else None,
                )

                raise AuthError(
                    403, "You must be in the room to create an alias for it"
                )

        self.validator.validate_new(event, self.config)

        return (event, context)

    async def _is_exempt_from_privacy_policy(
        self, builder: EventBuilder, requester: Requester
    ) -> bool:
        """ "Determine if an event to be sent is exempt from having to consent
        to the privacy policy

        Args:
            builder: event being created
            requester: user requesting this event

        Returns:
            true if the event can be sent without the user consenting
        """
        # the only thing the user can do is join the server notices room.
        if builder.type == EventTypes.Member:
            membership = builder.content.get("membership", None)
            if membership == Membership.JOIN:
                return await self._is_server_notices_room(builder.room_id)
            elif membership == Membership.LEAVE:
                # the user is always allowed to leave (but not kick people)
                return builder.state_key == requester.user.to_string()
        return False

    async def _is_server_notices_room(self, room_id: str) -> bool:
        if self.config.server_notices_mxid is None:
            return False
        user_ids = await self.store.get_users_in_room(room_id)
        return self.config.server_notices_mxid in user_ids

    async def assert_accepted_privacy_policy(self, requester: Requester) -> None:
        """Check if a user has accepted the privacy policy

        Called when the given user is about to do something that requires
        privacy consent. We see if the user is exempt and otherwise check that
        they have given consent. If they have not, a ConsentNotGiven error is
        raised.

        Args:
            requester: The user making the request

        Returns:
            Returns normally if the user has consented or is exempt

        Raises:
            ConsentNotGivenError: if the user has not given consent yet
        """
        if self._block_events_without_consent_error is None:
            return

        # exempt AS users from needing consent
        if requester.app_service is not None:
            return

        user_id = requester.authenticated_entity
        if not user_id.startswith("@"):
            # The authenticated entity might not be a user, e.g. if it's the
            # server puppetting the user.
            return

        user = UserID.from_string(user_id)

        # exempt the system notices user
        if (
            self.config.server_notices_mxid is not None
            and user_id == self.config.server_notices_mxid
        ):
            return

        u = await self.store.get_user_by_id(user_id)
        assert u is not None
        if u["user_type"] in (UserTypes.SUPPORT, UserTypes.BOT):
            # support and bot users are not required to consent
            return
        if u["appservice_id"] is not None:
            # users registered by an appservice are exempt
            return
        if u["consent_version"] == self.config.user_consent_version:
            return

        consent_uri = self._consent_uri_builder.build_user_consent_uri(user.localpart)
        msg = self._block_events_without_consent_error % {"consent_uri": consent_uri}
        raise ConsentNotGivenError(msg=msg, consent_uri=consent_uri)

    async def deduplicate_state_event(
        self, event: EventBase, context: EventContext
    ) -> Optional[EventBase]:
        """
        Checks whether event is in the latest resolved state in context.

        Args:
            event: The event to check for duplication.
            context: The event context.

        Returns:
            The previous version of the event is returned, if it is found in the
            event context. Otherwise, None is returned.
        """
        prev_state_ids = await context.get_prev_state_ids()
        prev_event_id = prev_state_ids.get((event.type, event.state_key))
        if not prev_event_id:
            return None
        prev_event = await self.store.get_event(prev_event_id, allow_none=True)
        if not prev_event:
            return None

        if prev_event and event.user_id == prev_event.user_id:
            prev_content = encode_canonical_json(prev_event.content)
            next_content = encode_canonical_json(event.content)
            if prev_content == next_content:
                return prev_event
        return None

    async def create_and_send_nonmember_event(
        self,
        requester: Requester,
        event_dict: dict,
        ratelimit: bool = True,
        txn_id: Optional[str] = None,
        ignore_shadow_ban: bool = False,
    ) -> Tuple[EventBase, int]:
        """
        Creates an event, then sends it.

        See self.create_event and self.handle_new_client_event.

        Args:
            requester: The requester sending the event.
            event_dict: An entire event.
            ratelimit: Whether to rate limit this send.
            txn_id: The transaction ID.
            ignore_shadow_ban: True if shadow-banned users should be allowed to
                send this event.

        Returns:
            The event, and its stream ordering (if deduplication happened,
            the previous, duplicate event).

        Raises:
            ShadowBanError if the requester has been shadow-banned.
        """

        if event_dict["type"] == EventTypes.Member:
            raise SynapseError(
                500, "Tried to send member event through non-member codepath"
            )

        if not ignore_shadow_ban and requester.shadow_banned:
            # We randomly sleep a bit just to annoy the requester.
            await self.clock.sleep(random.randint(1, 10))
            raise ShadowBanError()

        # We limit the number of concurrent event sends in a room so that we
        # don't fork the DAG too much. If we don't limit then we can end up in
        # a situation where event persistence can't keep up, causing
        # extremities to pile up, which in turn leads to state resolution
        # taking longer.
        with (await self.limiter.queue(event_dict["room_id"])):
            if txn_id and requester.access_token_id:
                existing_event_id = await self.store.get_event_id_from_transaction_id(
                    event_dict["room_id"],
                    requester.user.to_string(),
                    requester.access_token_id,
                    txn_id,
                )
                if existing_event_id:
                    event = await self.store.get_event(existing_event_id)
                    # we know it was persisted, so must have a stream ordering
                    assert event.internal_metadata.stream_ordering
                    return event, event.internal_metadata.stream_ordering

            event, context = await self.create_event(
                requester, event_dict, txn_id=txn_id
            )

            assert self.hs.is_mine_id(event.sender), "User must be our own: %s" % (
                event.sender,
            )

            spam_error = await self.spam_checker.check_event_for_spam(event)
            if spam_error:
                if not isinstance(spam_error, str):
                    spam_error = "Spam is not permitted here"
                raise SynapseError(403, spam_error, Codes.FORBIDDEN)

            ev = await self.handle_new_client_event(
                requester=requester,
                event=event,
                context=context,
                ratelimit=ratelimit,
                ignore_shadow_ban=ignore_shadow_ban,
            )

        # we know it was persisted, so must have a stream ordering
        assert ev.internal_metadata.stream_ordering
        return ev, ev.internal_metadata.stream_ordering

    @measure_func("create_new_client_event")
    async def create_new_client_event(
        self,
        builder: EventBuilder,
        requester: Optional[Requester] = None,
        prev_event_ids: Optional[List[str]] = None,
        auth_event_ids: Optional[List[str]] = None,
    ) -> Tuple[EventBase, EventContext]:
        """Create a new event for a local client

        Args:
            builder:
            requester:
            prev_event_ids:
                the forward extremities to use as the prev_events for the
                new event.

                If None, they will be requested from the database.

            auth_event_ids:
                The event ids to use as the auth_events for the new event.
                Should normally be left as None, which will cause them to be calculated
                based on the room state at the prev_events.

        Returns:
            Tuple of created event, context
        """

        if prev_event_ids is not None:
            assert (
                len(prev_event_ids) <= 10
            ), "Attempting to create an event with %i prev_events" % (
                len(prev_event_ids),
            )
        else:
            prev_event_ids = await self.store.get_prev_events_for_room(builder.room_id)

        # we now ought to have some prev_events (unless it's a create event).
        #
        # do a quick sanity check here, rather than waiting until we've created the
        # event and then try to auth it (which fails with a somewhat confusing "No
        # create event in auth events")
        assert (
            builder.type == EventTypes.Create or len(prev_event_ids) > 0
        ), "Attempting to create an event with no prev_events"

        event = await builder.build(
            prev_event_ids=prev_event_ids, auth_event_ids=auth_event_ids
        )
        context = await self.state.compute_event_context(event)
        if requester:
            context.app_service = requester.app_service

        third_party_result = await self.third_party_event_rules.check_event_allowed(
            event, context
        )
        if not third_party_result:
            logger.info(
                "Event %s forbidden by third-party rules",
                event,
            )
            raise SynapseError(
                403, "This event is not allowed in this context", Codes.FORBIDDEN
            )
        elif isinstance(third_party_result, dict):
            # the third-party rules want to replace the event. We'll need to build a new
            # event.
            event, context = await self._rebuild_event_after_third_party_rules(
                third_party_result, event
            )

        self.validator.validate_new(event, self.config)

        # If this event is an annotation then we check that that the sender
        # can't annotate the same way twice (e.g. stops users from liking an
        # event multiple times).
        relation = event.content.get("m.relates_to", {})
        if relation.get("rel_type") == RelationTypes.ANNOTATION:
            relates_to = relation["event_id"]
            aggregation_key = relation["key"]

            already_exists = await self.store.has_user_annotated_event(
                relates_to, event.type, aggregation_key, event.sender
            )
            if already_exists:
                raise SynapseError(400, "Can't send same reaction twice")

        logger.debug("Created event %s", event.event_id)

        return (event, context)

    @measure_func("handle_new_client_event")
    async def handle_new_client_event(
        self,
        requester: Requester,
        event: EventBase,
        context: EventContext,
        ratelimit: bool = True,
        extra_users: Optional[List[UserID]] = None,
        ignore_shadow_ban: bool = False,
    ) -> EventBase:
        """Processes a new event.

        This includes deduplicating, checking auth, persisting,
        notifying users, sending to remote servers, etc.

        If called from a worker will hit out to the master process for final
        processing.

        Args:
            requester
            event
            context
            ratelimit
            extra_users: Any extra users to notify about event

            ignore_shadow_ban: True if shadow-banned users should be allowed to
                send this event.

        Return:
            If the event was deduplicated, the previous, duplicate, event. Otherwise,
            `event`.

        Raises:
            ShadowBanError if the requester has been shadow-banned.
        """
        extra_users = extra_users or []

        # we don't apply shadow-banning to membership events here. Invites are blocked
        # higher up the stack, and we allow shadow-banned users to send join and leave
        # events as normal.
        if (
            event.type != EventTypes.Member
            and not ignore_shadow_ban
            and requester.shadow_banned
        ):
            # We randomly sleep a bit just to annoy the requester.
            await self.clock.sleep(random.randint(1, 10))
            raise ShadowBanError()

        if event.is_state():
            prev_event = await self.deduplicate_state_event(event, context)
            if prev_event is not None:
                logger.info(
                    "Not bothering to persist state event %s duplicated by %s",
                    event.event_id,
                    prev_event.event_id,
                )
                return prev_event

        if event.is_state() and (event.type, event.state_key) == (
            EventTypes.Create,
            "",
        ):
            room_version = event.content.get("room_version", RoomVersions.V1.identifier)
        else:
            room_version = await self.store.get_room_version_id(event.room_id)

        if event.internal_metadata.is_out_of_band_membership():
            # the only sort of out-of-band-membership events we expect to see here
            # are invite rejections we have generated ourselves.
            assert event.type == EventTypes.Member
            assert event.content["membership"] == Membership.LEAVE
        else:
            try:
                await self.auth.check_from_context(room_version, event, context)
            except AuthError as err:
                logger.warning("Denying new event %r because %s", event, err)
                raise err

        # Ensure that we can round trip before trying to persist in db
        try:
            dump = json_encoder.encode(event.content)
            json_decoder.decode(dump)
        except Exception:
            logger.exception("Failed to encode content: %r", event.content)
            raise

        # We now persist the event (and update the cache in parallel, since we
        # don't want to block on it).
        result = await make_deferred_yieldable(
            defer.gatherResults(
                [
                    run_in_background(
                        self._persist_event,
                        requester=requester,
                        event=event,
                        context=context,
                        ratelimit=ratelimit,
                        extra_users=extra_users,
                    ),
                    run_in_background(
                        self.cache_joined_hosts_for_event, event, context
                    ).addErrback(log_failure, "cache_joined_hosts_for_event failed"),
                ],
                consumeErrors=True,
            )
        ).addErrback(unwrapFirstError)

        return result[0]

    async def _persist_event(
        self,
        requester: Requester,
        event: EventBase,
        context: EventContext,
        ratelimit: bool = True,
        extra_users: Optional[List[UserID]] = None,
    ) -> EventBase:
        """Actually persists the event. Should only be called by
        `handle_new_client_event`, and see its docstring for documentation of
        the arguments.
        """

        await self.action_generator.handle_push_actions_for_event(event, context)

        try:
            # If we're a worker we need to hit out to the master.
            writer_instance = self._events_shard_config.get_instance(event.room_id)
            if writer_instance != self._instance_name:
                result = await self.send_event(
                    instance_name=writer_instance,
                    event_id=event.event_id,
                    store=self.store,
                    requester=requester,
                    event=event,
                    context=context,
                    ratelimit=ratelimit,
                    extra_users=extra_users,
                )
                stream_id = result["stream_id"]
                event_id = result["event_id"]
                if event_id != event.event_id:
                    # If we get a different event back then it means that its
                    # been de-duplicated, so we replace the given event with the
                    # one already persisted.
                    event = await self.store.get_event(event_id)
                else:
                    # If we newly persisted the event then we need to update its
                    # stream_ordering entry manually (as it was persisted on
                    # another worker).
                    event.internal_metadata.stream_ordering = stream_id
                return event

            event = await self.persist_and_notify_client_event(
                requester, event, context, ratelimit=ratelimit, extra_users=extra_users
            )

            return event
        except Exception:
            # Ensure that we actually remove the entries in the push actions
            # staging area, if we calculated them.
            await self.store.remove_push_actions_from_staging(event.event_id)
            raise

    async def cache_joined_hosts_for_event(
        self, event: EventBase, context: EventContext
    ) -> None:
        """Precalculate the joined hosts at the event, when using Redis, so that
        external federation senders don't have to recalculate it themselves.
        """

        if not self._external_cache.is_enabled():
            return

        # If external cache is enabled we should always have this.
        assert self._external_cache_joined_hosts_updates is not None

        # We actually store two mappings, event ID -> prev state group,
        # state group -> joined hosts, which is much more space efficient
        # than event ID -> joined hosts.
        #
        # Note: We have to cache event ID -> prev state group, as we don't
        # store that in the DB.
        #
        # Note: We set the state group -> joined hosts cache if it hasn't been
        # set for a while, so that the expiry time is reset.

        state_entry = await self.state.resolve_state_groups_for_events(
            event.room_id, event_ids=event.prev_event_ids()
        )

        if state_entry.state_group:
            await self._external_cache.set(
                "event_to_prev_state_group",
                event.event_id,
                state_entry.state_group,
                expiry_ms=60 * 60 * 1000,
            )

            if state_entry.state_group in self._external_cache_joined_hosts_updates:
                return

            joined_hosts = await self.store.get_joined_hosts(event.room_id, state_entry)

            # Note that the expiry times must be larger than the expiry time in
            # _external_cache_joined_hosts_updates.
            await self._external_cache.set(
                "get_joined_hosts",
                str(state_entry.state_group),
                list(joined_hosts),
                expiry_ms=60 * 60 * 1000,
            )

            self._external_cache_joined_hosts_updates[state_entry.state_group] = None

    async def _validate_canonical_alias(
        self, directory_handler, room_alias_str: str, expected_room_id: str
    ) -> None:
        """
        Ensure that the given room alias points to the expected room ID.

        Args:
            directory_handler: The directory handler object.
            room_alias_str: The room alias to check.
            expected_room_id: The room ID that the alias should point to.
        """
        room_alias = RoomAlias.from_string(room_alias_str)
        try:
            mapping = await directory_handler.get_association(room_alias)
        except SynapseError as e:
            # Turn M_NOT_FOUND errors into M_BAD_ALIAS errors.
            if e.errcode == Codes.NOT_FOUND:
                raise SynapseError(
                    400,
                    "Room alias %s does not point to the room" % (room_alias_str,),
                    Codes.BAD_ALIAS,
                )
            raise

        if mapping["room_id"] != expected_room_id:
            raise SynapseError(
                400,
                "Room alias %s does not point to the room" % (room_alias_str,),
                Codes.BAD_ALIAS,
            )

    async def persist_and_notify_client_event(
        self,
        requester: Requester,
        event: EventBase,
        context: EventContext,
        ratelimit: bool = True,
        extra_users: Optional[List[UserID]] = None,
    ) -> EventBase:
        """Called when we have fully built the event, have already
        calculated the push actions for the event, and checked auth.

        This should only be run on the instance in charge of persisting events.

        Returns:
            The persisted event. This may be different than the given event if
            it was de-duplicated (e.g. because we had already persisted an
            event with the same transaction ID.)
        """
        extra_users = extra_users or []

        assert self.storage.persistence is not None
        assert self._events_shard_config.should_handle(
            self._instance_name, event.room_id
        )

        if ratelimit:
            # We check if this is a room admin redacting an event so that we
            # can apply different ratelimiting. We do this by simply checking
            # it's not a self-redaction (to avoid having to look up whether the
            # user is actually admin or not).
            is_admin_redaction = False
            if event.type == EventTypes.Redaction:
                original_event = await self.store.get_event(
                    event.redacts,
                    redact_behaviour=EventRedactBehaviour.AS_IS,
                    get_prev_content=False,
                    allow_rejected=False,
                    allow_none=True,
                )

                is_admin_redaction = bool(
                    original_event and event.sender != original_event.sender
                )

            await self.base_handler.ratelimit(
                requester, is_admin_redaction=is_admin_redaction
            )

        await self.base_handler.maybe_kick_guest_users(event, context)

        if event.type == EventTypes.CanonicalAlias:
            # Validate a newly added alias or newly added alt_aliases.

            original_alias = None
            original_alt_aliases = []  # type: List[str]

            original_event_id = event.unsigned.get("replaces_state")
            if original_event_id:
                original_event = await self.store.get_event(original_event_id)

                if original_event:
                    original_alias = original_event.content.get("alias", None)
                    original_alt_aliases = original_event.content.get("alt_aliases", [])

            # Check the alias is currently valid (if it has changed).
            room_alias_str = event.content.get("alias", None)
            directory_handler = self.hs.get_directory_handler()
            if room_alias_str and room_alias_str != original_alias:
                await self._validate_canonical_alias(
                    directory_handler, room_alias_str, event.room_id
                )

            # Check that alt_aliases is the proper form.
            alt_aliases = event.content.get("alt_aliases", [])
            if not isinstance(alt_aliases, (list, tuple)):
                raise SynapseError(
                    400, "The alt_aliases property must be a list.", Codes.INVALID_PARAM
                )

            # If the old version of alt_aliases is of an unknown form,
            # completely replace it.
            if not isinstance(original_alt_aliases, (list, tuple)):
                original_alt_aliases = []

            # Check that each alias is currently valid.
            new_alt_aliases = set(alt_aliases) - set(original_alt_aliases)
            if new_alt_aliases:
                for alias_str in new_alt_aliases:
                    await self._validate_canonical_alias(
                        directory_handler, alias_str, event.room_id
                    )

        federation_handler = self.hs.get_federation_handler()

        if event.type == EventTypes.Member:
            if event.content["membership"] == Membership.INVITE:
                event.unsigned[
                    "invite_room_state"
                ] = await self.store.get_stripped_room_state_from_event_context(
                    context,
                    self.room_invite_state_types,
                    membership_user_id=event.sender,
                )

                invitee = UserID.from_string(event.state_key)
                if not self.hs.is_mine(invitee):
                    # TODO: Can we add signature from remote server in a nicer
                    # way? If we have been invited by a remote server, we need
                    # to get them to sign the event.

                    returned_invite = await federation_handler.send_invite(
                        invitee.domain, event
                    )
                    event.unsigned.pop("room_state", None)

                    # TODO: Make sure the signatures actually are correct.
                    event.signatures.update(returned_invite.signatures)

        if event.type == EventTypes.Redaction:
            original_event = await self.store.get_event(
                event.redacts,
                redact_behaviour=EventRedactBehaviour.AS_IS,
                get_prev_content=False,
                allow_rejected=False,
                allow_none=True,
            )

            # we can make some additional checks now if we have the original event.
            if original_event:
                if original_event.type == EventTypes.Create:
                    raise AuthError(403, "Redacting create events is not permitted")

                if original_event.room_id != event.room_id:
                    raise SynapseError(400, "Cannot redact event from a different room")

                if original_event.type == EventTypes.ServerACL:
                    raise AuthError(403, "Redacting server ACL events is not permitted")

            prev_state_ids = await context.get_prev_state_ids()
            auth_events_ids = self.auth.compute_auth_events(
                event, prev_state_ids, for_verification=True
            )
            auth_events_map = await self.store.get_events(auth_events_ids)
            auth_events = {(e.type, e.state_key): e for e in auth_events_map.values()}

            room_version = await self.store.get_room_version_id(event.room_id)
            room_version_obj = KNOWN_ROOM_VERSIONS[room_version]

            if event_auth.check_redaction(
                room_version_obj, event, auth_events=auth_events
            ):
                # this user doesn't have 'redact' rights, so we need to do some more
                # checks on the original event. Let's start by checking the original
                # event exists.
                if not original_event:
                    raise NotFoundError("Could not find event %s" % (event.redacts,))

                if event.user_id != original_event.user_id:
                    raise AuthError(403, "You don't have permission to redact events")

                # all the checks are done.
                event.internal_metadata.recheck_redaction = False

        if event.type == EventTypes.Create:
            prev_state_ids = await context.get_prev_state_ids()
            if prev_state_ids:
                raise AuthError(403, "Changing the room create event is forbidden")

        # Note that this returns the event that was persisted, which may not be
        # the same as we passed in if it was deduplicated due transaction IDs.
        (
            event,
            event_pos,
            max_stream_token,
        ) = await self.storage.persistence.persist_event(event, context=context)

        if self._ephemeral_events_enabled:
            # If there's an expiry timestamp on the event, schedule its expiry.
            self._message_handler.maybe_schedule_expiry(event)

        def _notify():
            try:
                self.notifier.on_new_room_event(
                    event, event_pos, max_stream_token, extra_users=extra_users
                )
            except Exception:
                logger.exception("Error notifying about new room event")

        run_in_background(_notify)

        if event.type == EventTypes.Message:
            # We don't want to block sending messages on any presence code. This
            # matters as sometimes presence code can take a while.
            run_in_background(self._bump_active_time, requester.user)

        return event

    async def _bump_active_time(self, user: UserID) -> None:
        try:
            presence = self.hs.get_presence_handler()
            await presence.bump_presence_active_time(user)
        except Exception:
            logger.exception("Error bumping presence active time")

    async def _send_dummy_events_to_fill_extremities(self):
        """Background task to send dummy events into rooms that have a large
        number of extremities
        """
        self._expire_rooms_to_exclude_from_dummy_event_insertion()
        room_ids = await self.store.get_rooms_with_many_extremities(
            min_count=self._dummy_events_threshold,
            limit=5,
            room_id_filter=self._rooms_to_exclude_from_dummy_event_insertion.keys(),
        )

        for room_id in room_ids:
            dummy_event_sent = await self._send_dummy_event_for_room(room_id)

            if not dummy_event_sent:
                # Did not find a valid user in the room, so remove from future attempts
                # Exclusion is time limited, so the room will be rechecked in the future
                # dependent on _DUMMY_EVENT_ROOM_EXCLUSION_EXPIRY
                logger.info(
                    "Failed to send dummy event into room %s. Will exclude it from "
                    "future attempts until cache expires" % (room_id,)
                )
                now = self.clock.time_msec()
                self._rooms_to_exclude_from_dummy_event_insertion[room_id] = now

    async def _send_dummy_event_for_room(self, room_id: str) -> bool:
        """Attempt to send a dummy event for the given room.

        Args:
            room_id: room to try to send an event from

        Returns:
            True if a dummy event was successfully sent. False if no user was able
            to send an event.
        """

        # For each room we need to find a joined member we can use to send
        # the dummy event with.
        latest_event_ids = await self.store.get_prev_events_for_room(room_id)
        members = await self.state.get_current_users_in_room(
            room_id, latest_event_ids=latest_event_ids
        )
        for user_id in members:
            if not self.hs.is_mine_id(user_id):
                continue
            requester = create_requester(user_id, authenticated_entity=self.server_name)
            try:
                event, context = await self.create_event(
                    requester,
                    {
                        "type": EventTypes.Dummy,
                        "content": {},
                        "room_id": room_id,
                        "sender": user_id,
                    },
                    prev_event_ids=latest_event_ids,
                )

                event.internal_metadata.proactively_send = False

                # Since this is a dummy-event it is OK if it is sent by a
                # shadow-banned user.
                await self.handle_new_client_event(
                    requester,
                    event,
                    context,
                    ratelimit=False,
                    ignore_shadow_ban=True,
                )
                return True
            except AuthError:
                logger.info(
                    "Failed to send dummy event into room %s for user %s due to "
                    "lack of power. Will try another user" % (room_id, user_id)
                )
        return False

    def _expire_rooms_to_exclude_from_dummy_event_insertion(self):
        expire_before = self.clock.time_msec() - _DUMMY_EVENT_ROOM_EXCLUSION_EXPIRY
        to_expire = set()
        for room_id, time in self._rooms_to_exclude_from_dummy_event_insertion.items():
            if time < expire_before:
                to_expire.add(room_id)
        for room_id in to_expire:
            logger.debug(
                "Expiring room id %s from dummy event insertion exclusion cache",
                room_id,
            )
            del self._rooms_to_exclude_from_dummy_event_insertion[room_id]

    async def _rebuild_event_after_third_party_rules(
        self, third_party_result: dict, original_event: EventBase
    ) -> Tuple[EventBase, EventContext]:
        # the third_party_event_rules want to replace the event.
        # we do some basic checks, and then return the replacement event and context.

        # Construct a new EventBuilder and validate it, which helps with the
        # rest of these checks.
        try:
            builder = self.event_builder_factory.for_room_version(
                original_event.room_version, third_party_result
            )
            self.validator.validate_builder(builder)
        except SynapseError as e:
            raise Exception(
                "Third party rules module created an invalid event: " + e.msg,
            )

        immutable_fields = [
            # changing the room is going to break things: we've already checked that the
            # room exists, and are holding a concurrency limiter token for that room.
            # Also, we might need to use a different room version.
            "room_id",
            # changing the type or state key might work, but we'd need to check that the
            # calling functions aren't making assumptions about them.
            "type",
            "state_key",
        ]

        for k in immutable_fields:
            if getattr(builder, k, None) != original_event.get(k):
                raise Exception(
                    "Third party rules module created an invalid event: "
                    "cannot change field " + k
                )

        # check that the new sender belongs to this HS
        if not self.hs.is_mine_id(builder.sender):
            raise Exception(
                "Third party rules module created an invalid event: "
                "invalid sender " + builder.sender
            )

        # copy over the original internal metadata
        for k, v in original_event.internal_metadata.get_dict().items():
            setattr(builder.internal_metadata, k, v)

        # the event type hasn't changed, so there's no point in re-calculating the
        # auth events.
        event = await builder.build(
            prev_event_ids=original_event.prev_event_ids(),
            auth_event_ids=original_event.auth_event_ids(),
        )

        # we rebuild the event context, to be on the safe side. If nothing else,
        # delta_ids might need an update.
        context = await self.state.compute_event_context(event)
        return event, context
