# -*- coding: utf-8 -*-
# Copyright 2014 - 2016 OpenMarket Ltd
# Copyright 2017 - 2018 New Vector Ltd
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

from six import iteritems, itervalues, string_types

from canonicaljson import encode_canonical_json, json

from twisted.internet import defer
from twisted.internet.defer import succeed

from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import (
    AuthError,
    Codes,
    ConsentNotGivenError,
    NotFoundError,
    SynapseError,
)
from synapse.api.room_versions import RoomVersions
from synapse.api.urls import ConsentURIBuilder
from synapse.events.utils import serialize_event
from synapse.events.validator import EventValidator
from synapse.replication.http.send_event import ReplicationSendEventRestServlet
from synapse.storage.state import StateFilter
from synapse.types import RoomAlias, UserID
from synapse.util.async_helpers import Linearizer
from synapse.util.frozenutils import frozendict_json_encoder
from synapse.util.logcontext import run_in_background
from synapse.util.metrics import measure_func
from synapse.visibility import filter_events_for_client

from ._base import BaseHandler

logger = logging.getLogger(__name__)


class MessageHandler(object):
    """Contains some read only APIs to get state about a room
    """

    def __init__(self, hs):
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.state = hs.get_state_handler()
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def get_room_data(self, user_id=None, room_id=None,
                      event_type=None, state_key="", is_guest=False):
        """ Get data from a room.

        Args:
            event : The room path event
        Returns:
            The path data content.
        Raises:
            SynapseError if something went wrong.
        """
        membership, membership_event_id = yield self.auth.check_in_room_or_world_readable(
            room_id, user_id
        )

        if membership == Membership.JOIN:
            data = yield self.state.get_current_state(
                room_id, event_type, state_key
            )
        elif membership == Membership.LEAVE:
            key = (event_type, state_key)
            room_state = yield self.store.get_state_for_events(
                [membership_event_id], StateFilter.from_types([key])
            )
            data = room_state[membership_event_id].get(key)

        defer.returnValue(data)

    @defer.inlineCallbacks
    def get_state_events(
        self, user_id, room_id, state_filter=StateFilter.all(),
        at_token=None, is_guest=False,
    ):
        """Retrieve all state events for a given room. If the user is
        joined to the room then return the current state. If the user has
        left the room return the state events from when they left. If an explicit
        'at' parameter is passed, return the state events as of that event, if
        visible.

        Args:
            user_id(str): The user requesting state events.
            room_id(str): The room ID to get all state events from.
            state_filter (StateFilter): The state filter used to fetch state
                from the database.
            at_token(StreamToken|None): the stream token of the at which we are requesting
                the stats. If the user is not allowed to view the state as of that
                stream token, we raise a 403 SynapseError. If None, returns the current
                state based on the current_state_events table.
            is_guest(bool): whether this user is a guest
        Returns:
            A list of dicts representing state events. [{}, {}, {}]
        Raises:
            NotFoundError (404) if the at token does not yield an event

            AuthError (403) if the user doesn't have permission to view
            members of this room.
        """
        if at_token:
            # FIXME this claims to get the state at a stream position, but
            # get_recent_events_for_room operates by topo ordering. This therefore
            # does not reliably give you the state at the given stream position.
            # (https://github.com/matrix-org/synapse/issues/3305)
            last_events, _ = yield self.store.get_recent_events_for_room(
                room_id, end_token=at_token.room_key, limit=1,
            )

            if not last_events:
                raise NotFoundError("Can't find event for token %s" % (at_token, ))

            visible_events = yield filter_events_for_client(
                self.store, user_id, last_events,
            )

            event = last_events[0]
            if visible_events:
                room_state = yield self.store.get_state_for_events(
                    [event.event_id], state_filter=state_filter,
                )
                room_state = room_state[event.event_id]
            else:
                raise AuthError(
                    403,
                    "User %s not allowed to view events in room %s at token %s" % (
                        user_id, room_id, at_token,
                    )
                )
        else:
            membership, membership_event_id = (
                yield self.auth.check_in_room_or_world_readable(
                    room_id, user_id,
                )
            )

            if membership == Membership.JOIN:
                state_ids = yield self.store.get_filtered_current_state_ids(
                    room_id, state_filter=state_filter,
                )
                room_state = yield self.store.get_events(state_ids.values())
            elif membership == Membership.LEAVE:
                room_state = yield self.store.get_state_for_events(
                    [membership_event_id], state_filter=state_filter,
                )
                room_state = room_state[membership_event_id]

        now = self.clock.time_msec()
        defer.returnValue(
            [serialize_event(c, now) for c in room_state.values()]
        )

    @defer.inlineCallbacks
    def get_joined_members(self, requester, room_id):
        """Get all the joined members in the room and their profile information.

        If the user has left the room return the state events from when they left.

        Args:
            requester(Requester): The user requesting state events.
            room_id(str): The room ID to get all state events from.
        Returns:
            A dict of user_id to profile info
        """
        user_id = requester.user.to_string()
        if not requester.app_service:
            # We check AS auth after fetching the room membership, as it
            # requires us to pull out all joined members anyway.
            membership, _ = yield self.auth.check_in_room_or_world_readable(
                room_id, user_id
            )
            if membership != Membership.JOIN:
                raise NotImplementedError(
                    "Getting joined members after leaving is not implemented"
                )

        users_with_profile = yield self.state.get_current_users_in_room(room_id)

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

        defer.returnValue({
            user_id: {
                "avatar_url": profile.avatar_url,
                "display_name": profile.display_name,
            }
            for user_id, profile in iteritems(users_with_profile)
        })


class EventCreationHandler(object):
    def __init__(self, hs):
        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()
        self.state = hs.get_state_handler()
        self.clock = hs.get_clock()
        self.validator = EventValidator()
        self.profile_handler = hs.get_profile_handler()
        self.event_builder_factory = hs.get_event_builder_factory()
        self.server_name = hs.hostname
        self.ratelimiter = hs.get_ratelimiter()
        self.notifier = hs.get_notifier()
        self.config = hs.config
        self.require_membership_for_aliases = hs.config.require_membership_for_aliases

        self.send_event_to_master = ReplicationSendEventRestServlet.make_client(hs)

        # This is only used to get at ratelimit function, and maybe_kick_guest_users
        self.base_handler = BaseHandler(hs)

        self.pusher_pool = hs.get_pusherpool()

        # We arbitrarily limit concurrent event creation for a room to 5.
        # This is to stop us from diverging history *too* much.
        self.limiter = Linearizer(max_count=5, name="room_event_creation_limit")

        self.action_generator = hs.get_action_generator()

        self.spam_checker = hs.get_spam_checker()

        self._block_events_without_consent_error = (
            self.config.block_events_without_consent_error
        )

        # we need to construct a ConsentURIBuilder here, as it checks that the necessary
        # config options, but *only* if we have a configuration for which we are
        # going to need it.
        if self._block_events_without_consent_error:
            self._consent_uri_builder = ConsentURIBuilder(self.config)

    @defer.inlineCallbacks
    def create_event(self, requester, event_dict, token_id=None, txn_id=None,
                     prev_events_and_hashes=None, require_consent=True):
        """
        Given a dict from a client, create a new event.

        Creates an FrozenEvent object, filling out auth_events, prev_events,
        etc.

        Adds display names to Join membership events.

        Args:
            requester
            event_dict (dict): An entire event
            token_id (str)
            txn_id (str)

            prev_events_and_hashes (list[(str, dict[str, str], int)]|None):
                the forward extremities to use as the prev_events for the
                new event. For each event, a tuple of (event_id, hashes, depth)
                where *hashes* is a map from algorithm to hash.

                If None, they will be requested from the database.

            require_consent (bool): Whether to check if the requester has
                consented to privacy policy.
        Raises:
            ResourceLimitError if server is blocked to some resource being
            exceeded
        Returns:
            Tuple of created event (FrozenEvent), Context
        """
        yield self.auth.check_auth_blocking(requester.user.to_string())

        if event_dict["type"] == EventTypes.Create and event_dict["state_key"] == "":
            room_version = event_dict["content"]["room_version"]
        else:
            try:
                room_version = yield self.store.get_room_version(event_dict["room_id"])
            except NotFoundError:
                raise AuthError(403, "Unknown room")

        builder = self.event_builder_factory.new(room_version, event_dict)

        self.validator.validate_builder(builder)

        if builder.type == EventTypes.Member:
            membership = builder.content.get("membership", None)
            target = UserID.from_string(builder.state_key)

            if membership in {Membership.JOIN, Membership.INVITE}:
                # If event doesn't include a display name, add one.
                profile = self.profile_handler
                content = builder.content

                try:
                    if "displayname" not in content:
                        content["displayname"] = yield profile.get_displayname(target)
                    if "avatar_url" not in content:
                        content["avatar_url"] = yield profile.get_avatar_url(target)
                except Exception as e:
                    logger.info(
                        "Failed to get profile information for %r: %s",
                        target, e
                    )

        is_exempt = yield self._is_exempt_from_privacy_policy(builder, requester)
        if require_consent and not is_exempt:
            yield self.assert_accepted_privacy_policy(requester)

        if token_id is not None:
            builder.internal_metadata.token_id = token_id

        if txn_id is not None:
            builder.internal_metadata.txn_id = txn_id

        event, context = yield self.create_new_client_event(
            builder=builder,
            requester=requester,
            prev_events_and_hashes=prev_events_and_hashes,
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
            prev_state_ids = yield context.get_prev_state_ids(self.store)
            prev_event_id = prev_state_ids.get((EventTypes.Member, event.sender))
            prev_event = yield self.store.get_event(prev_event_id, allow_none=True)
            if not prev_event or prev_event.membership != Membership.JOIN:
                logger.warning(
                    ("Attempt to send `m.room.aliases` in room %s by user %s but"
                     " membership is %s"),
                    event.room_id,
                    event.sender,
                    prev_event.membership if prev_event else None,
                )

                raise AuthError(
                    403,
                    "You must be in the room to create an alias for it",
                )

        self.validator.validate_new(event)

        defer.returnValue((event, context))

    def _is_exempt_from_privacy_policy(self, builder, requester):
        """"Determine if an event to be sent is exempt from having to consent
        to the privacy policy

        Args:
            builder (synapse.events.builder.EventBuilder): event being created
            requester (Requster): user requesting this event

        Returns:
            Deferred[bool]: true if the event can be sent without the user
                consenting
        """
        # the only thing the user can do is join the server notices room.
        if builder.type == EventTypes.Member:
            membership = builder.content.get("membership", None)
            if membership == Membership.JOIN:
                return self._is_server_notices_room(builder.room_id)
            elif membership == Membership.LEAVE:
                # the user is always allowed to leave (but not kick people)
                return builder.state_key == requester.user.to_string()
        return succeed(False)

    @defer.inlineCallbacks
    def _is_server_notices_room(self, room_id):
        if self.config.server_notices_mxid is None:
            defer.returnValue(False)
        user_ids = yield self.store.get_users_in_room(room_id)
        defer.returnValue(self.config.server_notices_mxid in user_ids)

    @defer.inlineCallbacks
    def assert_accepted_privacy_policy(self, requester):
        """Check if a user has accepted the privacy policy

        Called when the given user is about to do something that requires
        privacy consent. We see if the user is exempt and otherwise check that
        they have given consent. If they have not, a ConsentNotGiven error is
        raised.

        Args:
            requester (synapse.types.Requester):
                The user making the request

        Returns:
            Deferred[None]: returns normally if the user has consented or is
                exempt

        Raises:
            ConsentNotGivenError: if the user has not given consent yet
        """
        if self._block_events_without_consent_error is None:
            return

        # exempt AS users from needing consent
        if requester.app_service is not None:
            return

        user_id = requester.user.to_string()

        # exempt the system notices user
        if (
            self.config.server_notices_mxid is not None and
            user_id == self.config.server_notices_mxid
        ):
            return

        u = yield self.store.get_user_by_id(user_id)
        assert u is not None
        if u["appservice_id"] is not None:
            # users registered by an appservice are exempt
            return
        if u["consent_version"] == self.config.user_consent_version:
            return

        consent_uri = self._consent_uri_builder.build_user_consent_uri(
            requester.user.localpart,
        )
        msg = self._block_events_without_consent_error % {
            'consent_uri': consent_uri,
        }
        raise ConsentNotGivenError(
            msg=msg,
            consent_uri=consent_uri,
        )

    @defer.inlineCallbacks
    def send_nonmember_event(self, requester, event, context, ratelimit=True):
        """
        Persists and notifies local clients and federation of an event.

        Args:
            event (FrozenEvent) the event to send.
            context (Context) the context of the event.
            ratelimit (bool): Whether to rate limit this send.
            is_guest (bool): Whether the sender is a guest.
        """
        if event.type == EventTypes.Member:
            raise SynapseError(
                500,
                "Tried to send member event through non-member codepath"
            )

        user = UserID.from_string(event.sender)

        assert self.hs.is_mine(user), "User must be our own: %s" % (user,)

        if event.is_state():
            prev_state = yield self.deduplicate_state_event(event, context)
            if prev_state is not None:
                logger.info(
                    "Not bothering to persist state event %s duplicated by %s",
                    event.event_id, prev_state.event_id,
                )
                defer.returnValue(prev_state)

        yield self.handle_new_client_event(
            requester=requester,
            event=event,
            context=context,
            ratelimit=ratelimit,
        )

    @defer.inlineCallbacks
    def deduplicate_state_event(self, event, context):
        """
        Checks whether event is in the latest resolved state in context.

        If so, returns the version of the event in context.
        Otherwise, returns None.
        """
        prev_state_ids = yield context.get_prev_state_ids(self.store)
        prev_event_id = prev_state_ids.get((event.type, event.state_key))
        prev_event = yield self.store.get_event(prev_event_id, allow_none=True)
        if not prev_event:
            return

        if prev_event and event.user_id == prev_event.user_id:
            prev_content = encode_canonical_json(prev_event.content)
            next_content = encode_canonical_json(event.content)
            if prev_content == next_content:
                defer.returnValue(prev_event)
        return

    @defer.inlineCallbacks
    def create_and_send_nonmember_event(
        self,
        requester,
        event_dict,
        ratelimit=True,
        txn_id=None
    ):
        """
        Creates an event, then sends it.

        See self.create_event and self.send_nonmember_event.
        """

        # We limit the number of concurrent event sends in a room so that we
        # don't fork the DAG too much. If we don't limit then we can end up in
        # a situation where event persistence can't keep up, causing
        # extremities to pile up, which in turn leads to state resolution
        # taking longer.
        with (yield self.limiter.queue(event_dict["room_id"])):
            event, context = yield self.create_event(
                requester,
                event_dict,
                token_id=requester.access_token_id,
                txn_id=txn_id
            )

            spam_error = self.spam_checker.check_event_for_spam(event)
            if spam_error:
                if not isinstance(spam_error, string_types):
                    spam_error = "Spam is not permitted here"
                raise SynapseError(
                    403, spam_error, Codes.FORBIDDEN
                )

            yield self.send_nonmember_event(
                requester,
                event,
                context,
                ratelimit=ratelimit,
            )
        defer.returnValue(event)

    @measure_func("create_new_client_event")
    @defer.inlineCallbacks
    def create_new_client_event(self, builder, requester=None,
                                prev_events_and_hashes=None):
        """Create a new event for a local client

        Args:
            builder (EventBuilder):

            requester (synapse.types.Requester|None):

            prev_events_and_hashes (list[(str, dict[str, str], int)]|None):
                the forward extremities to use as the prev_events for the
                new event. For each event, a tuple of (event_id, hashes, depth)
                where *hashes* is a map from algorithm to hash.

                If None, they will be requested from the database.

        Returns:
            Deferred[(synapse.events.EventBase, synapse.events.snapshot.EventContext)]
        """

        if prev_events_and_hashes is not None:
            assert len(prev_events_and_hashes) <= 10, \
                "Attempting to create an event with %i prev_events" % (
                    len(prev_events_and_hashes),
            )
        else:
            prev_events_and_hashes = \
                yield self.store.get_prev_events_for_room(builder.room_id)

        prev_events = [
            (event_id, prev_hashes)
            for event_id, prev_hashes, _ in prev_events_and_hashes
        ]

        event = yield builder.build(
            prev_event_ids=[p for p, _ in prev_events],
        )
        context = yield self.state.compute_event_context(event)
        if requester:
            context.app_service = requester.app_service

        self.validator.validate_new(event)

        logger.debug(
            "Created event %s",
            event.event_id,
        )

        defer.returnValue(
            (event, context,)
        )

    @measure_func("handle_new_client_event")
    @defer.inlineCallbacks
    def handle_new_client_event(
        self,
        requester,
        event,
        context,
        ratelimit=True,
        extra_users=[],
    ):
        """Processes a new event. This includes checking auth, persisting it,
        notifying users, sending to remote servers, etc.

        If called from a worker will hit out to the master process for final
        processing.

        Args:
            requester (Requester)
            event (FrozenEvent)
            context (EventContext)
            ratelimit (bool)
            extra_users (list(UserID)): Any extra users to notify about event
        """

        if event.is_state() and (event.type, event.state_key) == (EventTypes.Create, ""):
            room_version = event.content.get(
                "room_version", RoomVersions.V1.identifier
            )
        else:
            room_version = yield self.store.get_room_version(event.room_id)

        try:
            yield self.auth.check_from_context(room_version, event, context)
        except AuthError as err:
            logger.warn("Denying new event %r because %s", event, err)
            raise err

        # Ensure that we can round trip before trying to persist in db
        try:
            dump = frozendict_json_encoder.encode(event.content)
            json.loads(dump)
        except Exception:
            logger.exception("Failed to encode content: %r", event.content)
            raise

        yield self.action_generator.handle_push_actions_for_event(
            event, context
        )

        # reraise does not allow inlineCallbacks to preserve the stacktrace, so we
        # hack around with a try/finally instead.
        success = False
        try:
            # If we're a worker we need to hit out to the master.
            if self.config.worker_app:
                yield self.send_event_to_master(
                    event_id=event.event_id,
                    store=self.store,
                    requester=requester,
                    event=event,
                    context=context,
                    ratelimit=ratelimit,
                    extra_users=extra_users,
                )
                success = True
                return

            yield self.persist_and_notify_client_event(
                requester,
                event,
                context,
                ratelimit=ratelimit,
                extra_users=extra_users,
            )

            success = True
        finally:
            if not success:
                # Ensure that we actually remove the entries in the push actions
                # staging area, if we calculated them.
                run_in_background(
                    self.store.remove_push_actions_from_staging,
                    event.event_id,
                )

    @defer.inlineCallbacks
    def persist_and_notify_client_event(
        self,
        requester,
        event,
        context,
        ratelimit=True,
        extra_users=[],
    ):
        """Called when we have fully built the event, have already
        calculated the push actions for the event, and checked auth.

        This should only be run on master.
        """
        assert not self.config.worker_app

        if ratelimit:
            yield self.base_handler.ratelimit(requester)

        yield self.base_handler.maybe_kick_guest_users(event, context)

        if event.type == EventTypes.CanonicalAlias:
            # Check the alias is acually valid (at this time at least)
            room_alias_str = event.content.get("alias", None)
            if room_alias_str:
                room_alias = RoomAlias.from_string(room_alias_str)
                directory_handler = self.hs.get_handlers().directory_handler
                mapping = yield directory_handler.get_association(room_alias)

                if mapping["room_id"] != event.room_id:
                    raise SynapseError(
                        400,
                        "Room alias %s does not point to the room" % (
                            room_alias_str,
                        )
                    )

        federation_handler = self.hs.get_handlers().federation_handler

        if event.type == EventTypes.Member:
            if event.content["membership"] == Membership.INVITE:
                def is_inviter_member_event(e):
                    return (
                        e.type == EventTypes.Member and
                        e.sender == event.sender
                    )

                current_state_ids = yield context.get_current_state_ids(self.store)

                state_to_include_ids = [
                    e_id
                    for k, e_id in iteritems(current_state_ids)
                    if k[0] in self.hs.config.room_invite_state_types
                    or k == (EventTypes.Member, event.sender)
                ]

                state_to_include = yield self.store.get_events(state_to_include_ids)

                event.unsigned["invite_room_state"] = [
                    {
                        "type": e.type,
                        "state_key": e.state_key,
                        "content": e.content,
                        "sender": e.sender,
                    }
                    for e in itervalues(state_to_include)
                ]

                invitee = UserID.from_string(event.state_key)
                if not self.hs.is_mine(invitee):
                    # TODO: Can we add signature from remote server in a nicer
                    # way? If we have been invited by a remote server, we need
                    # to get them to sign the event.

                    returned_invite = yield federation_handler.send_invite(
                        invitee.domain,
                        event,
                    )

                    event.unsigned.pop("room_state", None)

                    # TODO: Make sure the signatures actually are correct.
                    event.signatures.update(
                        returned_invite.signatures
                    )

        if event.type == EventTypes.Redaction:
            prev_state_ids = yield context.get_prev_state_ids(self.store)
            auth_events_ids = yield self.auth.compute_auth_events(
                event, prev_state_ids, for_verification=True,
            )
            auth_events = yield self.store.get_events(auth_events_ids)
            auth_events = {
                (e.type, e.state_key): e for e in auth_events.values()
            }
            room_version = yield self.store.get_room_version(event.room_id)
            if self.auth.check_redaction(room_version, event, auth_events=auth_events):
                original_event = yield self.store.get_event(
                    event.redacts,
                    check_redacted=False,
                    get_prev_content=False,
                    allow_rejected=False,
                    allow_none=False
                )
                if event.user_id != original_event.user_id:
                    raise AuthError(
                        403,
                        "You don't have permission to redact events"
                    )

                # We've already checked.
                event.internal_metadata.recheck_redaction = False

        if event.type == EventTypes.Create:
            prev_state_ids = yield context.get_prev_state_ids(self.store)
            if prev_state_ids:
                raise AuthError(
                    403,
                    "Changing the room create event is forbidden",
                )

        (event_stream_id, max_stream_id) = yield self.store.persist_event(
            event, context=context
        )

        yield self.pusher_pool.on_new_notifications(
            event_stream_id, max_stream_id,
        )

        def _notify():
            try:
                self.notifier.on_new_room_event(
                    event, event_stream_id, max_stream_id,
                    extra_users=extra_users
                )
            except Exception:
                logger.exception("Error notifying about new room event")

        run_in_background(_notify)

        if event.type == EventTypes.Message:
            # We don't want to block sending messages on any presence code. This
            # matters as sometimes presence code can take a while.
            run_in_background(self._bump_active_time, requester.user)

    @defer.inlineCallbacks
    def _bump_active_time(self, user):
        try:
            presence = self.hs.get_presence_handler()
            yield presence.bump_presence_active_time(user)
        except Exception:
            logger.exception("Error bumping presence active time")
