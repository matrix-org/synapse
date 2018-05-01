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
from twisted.internet import defer, reactor
from twisted.python.failure import Failure

from synapse.api.constants import EventTypes, Membership, MAX_DEPTH
from synapse.api.errors import AuthError, Codes, SynapseError
from synapse.crypto.event_signing import add_hashes_and_signatures
from synapse.events.utils import serialize_event
from synapse.events.validator import EventValidator
from synapse.types import (
    UserID, RoomAlias, RoomStreamToken,
)
from synapse.util.async import run_on_reactor, ReadWriteLock, Limiter
from synapse.util.logcontext import preserve_fn, run_in_background
from synapse.util.metrics import measure_func
from synapse.util.frozenutils import frozendict_json_encoder
from synapse.util.stringutils import random_string
from synapse.visibility import filter_events_for_client
from synapse.replication.http.send_event import send_event_to_master

from ._base import BaseHandler

from canonicaljson import encode_canonical_json

import logging
import simplejson

logger = logging.getLogger(__name__)


class PurgeStatus(object):
    """Object tracking the status of a purge request

    This class contains information on the progress of a purge request, for
    return by get_purge_status.

    Attributes:
        status (int): Tracks whether this request has completed. One of
            STATUS_{ACTIVE,COMPLETE,FAILED}
    """

    STATUS_ACTIVE = 0
    STATUS_COMPLETE = 1
    STATUS_FAILED = 2

    STATUS_TEXT = {
        STATUS_ACTIVE: "active",
        STATUS_COMPLETE: "complete",
        STATUS_FAILED: "failed",
    }

    def __init__(self):
        self.status = PurgeStatus.STATUS_ACTIVE

    def asdict(self):
        return {
            "status": PurgeStatus.STATUS_TEXT[self.status]
        }


class MessageHandler(BaseHandler):

    def __init__(self, hs):
        super(MessageHandler, self).__init__(hs)
        self.hs = hs
        self.state = hs.get_state_handler()
        self.clock = hs.get_clock()

        self.pagination_lock = ReadWriteLock()
        self._purges_in_progress_by_room = set()
        # map from purge id to PurgeStatus
        self._purges_by_id = {}

    def start_purge_history(self, room_id, topological_ordering,
                            delete_local_events=False):
        """Start off a history purge on a room.

        Args:
            room_id (str): The room to purge from

            topological_ordering (int): minimum topo ordering to preserve
            delete_local_events (bool): True to delete local events as well as
                remote ones

        Returns:
            str: unique ID for this purge transaction.
        """
        if room_id in self._purges_in_progress_by_room:
            raise SynapseError(
                400,
                "History purge already in progress for %s" % (room_id, ),
            )

        purge_id = random_string(16)

        # we log the purge_id here so that it can be tied back to the
        # request id in the log lines.
        logger.info("[purge] starting purge_id %s", purge_id)

        self._purges_by_id[purge_id] = PurgeStatus()
        run_in_background(
            self._purge_history,
            purge_id, room_id, topological_ordering, delete_local_events,
        )
        return purge_id

    @defer.inlineCallbacks
    def _purge_history(self, purge_id, room_id, topological_ordering,
                       delete_local_events):
        """Carry out a history purge on a room.

        Args:
            purge_id (str): The id for this purge
            room_id (str): The room to purge from
            topological_ordering (int): minimum topo ordering to preserve
            delete_local_events (bool): True to delete local events as well as
                remote ones

        Returns:
            Deferred
        """
        self._purges_in_progress_by_room.add(room_id)
        try:
            with (yield self.pagination_lock.write(room_id)):
                yield self.store.purge_history(
                    room_id, topological_ordering, delete_local_events,
                )
            logger.info("[purge] complete")
            self._purges_by_id[purge_id].status = PurgeStatus.STATUS_COMPLETE
        except Exception:
            logger.error("[purge] failed: %s", Failure().getTraceback().rstrip())
            self._purges_by_id[purge_id].status = PurgeStatus.STATUS_FAILED
        finally:
            self._purges_in_progress_by_room.discard(room_id)

            # remove the purge from the list 24 hours after it completes
            def clear_purge():
                del self._purges_by_id[purge_id]
            reactor.callLater(24 * 3600, clear_purge)

    def get_purge_status(self, purge_id):
        """Get the current status of an active purge

        Args:
            purge_id (str): purge_id returned by start_purge_history

        Returns:
            PurgeStatus|None
        """
        return self._purges_by_id.get(purge_id)

    @defer.inlineCallbacks
    def get_messages(self, requester, room_id=None, pagin_config=None,
                     as_client_event=True, event_filter=None):
        """Get messages in a room.

        Args:
            requester (Requester): The user requesting messages.
            room_id (str): The room they want messages from.
            pagin_config (synapse.api.streams.PaginationConfig): The pagination
                config rules to apply, if any.
            as_client_event (bool): True to get events in client-server format.
            event_filter (Filter): Filter to apply to results or None
        Returns:
            dict: Pagination API results
        """
        user_id = requester.user.to_string()

        if pagin_config.from_token:
            room_token = pagin_config.from_token.room_key
        else:
            pagin_config.from_token = (
                yield self.hs.get_event_sources().get_current_token_for_room(
                    room_id=room_id
                )
            )
            room_token = pagin_config.from_token.room_key

        room_token = RoomStreamToken.parse(room_token)

        pagin_config.from_token = pagin_config.from_token.copy_and_replace(
            "room_key", str(room_token)
        )

        source_config = pagin_config.get_source_config("room")

        with (yield self.pagination_lock.read(room_id)):
            membership, member_event_id = yield self._check_in_room_or_world_readable(
                room_id, user_id
            )

            if source_config.direction == 'b':
                # if we're going backwards, we might need to backfill. This
                # requires that we have a topo token.
                if room_token.topological:
                    max_topo = room_token.topological
                else:
                    max_topo = yield self.store.get_max_topological_token(
                        room_id, room_token.stream
                    )

                if membership == Membership.LEAVE:
                    # If they have left the room then clamp the token to be before
                    # they left the room, to save the effort of loading from the
                    # database.
                    leave_token = yield self.store.get_topological_token_for_event(
                        member_event_id
                    )
                    leave_token = RoomStreamToken.parse(leave_token)
                    if leave_token.topological < max_topo:
                        source_config.from_key = str(leave_token)

                yield self.hs.get_handlers().federation_handler.maybe_backfill(
                    room_id, max_topo
                )

            events, next_key = yield self.store.paginate_room_events(
                room_id=room_id,
                from_key=source_config.from_key,
                to_key=source_config.to_key,
                direction=source_config.direction,
                limit=source_config.limit,
                event_filter=event_filter,
            )

            next_token = pagin_config.from_token.copy_and_replace(
                "room_key", next_key
            )

        if not events:
            defer.returnValue({
                "chunk": [],
                "start": pagin_config.from_token.to_string(),
                "end": next_token.to_string(),
            })

        if event_filter:
            events = event_filter.filter(events)

        events = yield filter_events_for_client(
            self.store,
            user_id,
            events,
            is_peeking=(member_event_id is None),
        )

        time_now = self.clock.time_msec()

        chunk = {
            "chunk": [
                serialize_event(e, time_now, as_client_event)
                for e in events
            ],
            "start": pagin_config.from_token.to_string(),
            "end": next_token.to_string(),
        }

        defer.returnValue(chunk)

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
        membership, membership_event_id = yield self._check_in_room_or_world_readable(
            room_id, user_id
        )

        if membership == Membership.JOIN:
            data = yield self.state_handler.get_current_state(
                room_id, event_type, state_key
            )
        elif membership == Membership.LEAVE:
            key = (event_type, state_key)
            room_state = yield self.store.get_state_for_events(
                [membership_event_id], [key]
            )
            data = room_state[membership_event_id].get(key)

        defer.returnValue(data)

    @defer.inlineCallbacks
    def _check_in_room_or_world_readable(self, room_id, user_id):
        try:
            # check_user_was_in_room will return the most recent membership
            # event for the user if:
            #  * The user is a non-guest user, and was ever in the room
            #  * The user is a guest user, and has joined the room
            # else it will throw.
            member_event = yield self.auth.check_user_was_in_room(room_id, user_id)
            defer.returnValue((member_event.membership, member_event.event_id))
            return
        except AuthError:
            visibility = yield self.state_handler.get_current_state(
                room_id, EventTypes.RoomHistoryVisibility, ""
            )
            if (
                visibility and
                visibility.content["history_visibility"] == "world_readable"
            ):
                defer.returnValue((Membership.JOIN, None))
                return
            raise AuthError(
                403, "Guest access not allowed", errcode=Codes.GUEST_ACCESS_FORBIDDEN
            )

    @defer.inlineCallbacks
    def get_state_events(self, user_id, room_id, is_guest=False):
        """Retrieve all state events for a given room. If the user is
        joined to the room then return the current state. If the user has
        left the room return the state events from when they left.

        Args:
            user_id(str): The user requesting state events.
            room_id(str): The room ID to get all state events from.
        Returns:
            A list of dicts representing state events. [{}, {}, {}]
        """
        membership, membership_event_id = yield self._check_in_room_or_world_readable(
            room_id, user_id
        )

        if membership == Membership.JOIN:
            room_state = yield self.state_handler.get_current_state(room_id)
        elif membership == Membership.LEAVE:
            room_state = yield self.store.get_state_for_events(
                [membership_event_id], None
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
            membership, _ = yield self._check_in_room_or_world_readable(
                room_id, user_id
            )
            if membership != Membership.JOIN:
                raise NotImplementedError(
                    "Getting joined members after leaving is not implemented"
                )

        users_with_profile = yield self.state.get_current_user_in_room(room_id)

        # If this is an AS, double check that they are allowed to see the members.
        # This can either be because the AS user is in the room or becuase there
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
            for user_id, profile in users_with_profile.iteritems()
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

        self.http_client = hs.get_simple_http_client()

        # This is only used to get at ratelimit function, and maybe_kick_guest_users
        self.base_handler = BaseHandler(hs)

        self.pusher_pool = hs.get_pusherpool()

        # We arbitrarily limit concurrent event creation for a room to 5.
        # This is to stop us from diverging history *too* much.
        self.limiter = Limiter(max_count=5)

        self.action_generator = hs.get_action_generator()

        self.spam_checker = hs.get_spam_checker()

    @defer.inlineCallbacks
    def create_event(self, requester, event_dict, token_id=None, txn_id=None,
                     prev_events_and_hashes=None):
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

        Returns:
            Tuple of created event (FrozenEvent), Context
        """
        builder = self.event_builder_factory.new(event_dict)

        self.validator.validate_new(builder)

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

        if token_id is not None:
            builder.internal_metadata.token_id = token_id

        if txn_id is not None:
            builder.internal_metadata.txn_id = txn_id

        event, context = yield self.create_new_client_event(
            builder=builder,
            requester=requester,
            prev_events_and_hashes=prev_events_and_hashes,
        )

        defer.returnValue((event, context))

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
        prev_event_id = context.prev_state_ids.get((event.type, event.state_key))
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
                if not isinstance(spam_error, basestring):
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

        if prev_events_and_hashes:
            depth = max([d for _, _, d in prev_events_and_hashes]) + 1
            # we cap depth of generated events, to ensure that they are not
            # rejected by other servers (and so that they can be persisted in
            # the db)
            depth = min(depth, MAX_DEPTH)
        else:
            depth = 1

        prev_events = [
            (event_id, prev_hashes)
            for event_id, prev_hashes, _ in prev_events_and_hashes
        ]

        builder.prev_events = prev_events
        builder.depth = depth

        context = yield self.state.compute_event_context(builder)
        if requester:
            context.app_service = requester.app_service

        if builder.is_state():
            builder.prev_state = yield self.store.add_event_hashes(
                context.prev_state_events
            )

        yield self.auth.add_auth_events(builder, context)

        signing_key = self.hs.config.signing_key[0]
        add_hashes_and_signatures(
            builder, self.server_name, signing_key
        )

        event = builder.build()

        logger.debug(
            "Created event %s with state: %s",
            event.event_id, context.prev_state_ids,
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

        try:
            yield self.auth.check_from_context(event, context)
        except AuthError as err:
            logger.warn("Denying new event %r because %s", event, err)
            raise err

        # Ensure that we can round trip before trying to persist in db
        try:
            dump = frozendict_json_encoder.encode(event.content)
            simplejson.loads(dump)
        except Exception:
            logger.exception("Failed to encode content: %r", event.content)
            raise

        yield self.action_generator.handle_push_actions_for_event(
            event, context
        )

        try:
            # If we're a worker we need to hit out to the master.
            if self.config.worker_app:
                yield send_event_to_master(
                    self.http_client,
                    host=self.config.worker_replication_host,
                    port=self.config.worker_replication_http_port,
                    requester=requester,
                    event=event,
                    context=context,
                    ratelimit=ratelimit,
                    extra_users=extra_users,
                )
                return

            yield self.persist_and_notify_client_event(
                requester,
                event,
                context,
                ratelimit=ratelimit,
                extra_users=extra_users,
            )
        except:  # noqa: E722, as we reraise the exception this is fine.
            # Ensure that we actually remove the entries in the push actions
            # staging area, if we calculated them.
            preserve_fn(self.store.remove_push_actions_from_staging)(event.event_id)
            raise

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

                state_to_include_ids = [
                    e_id
                    for k, e_id in context.current_state_ids.iteritems()
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
                    for e in state_to_include.itervalues()
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
            auth_events_ids = yield self.auth.compute_auth_events(
                event, context.prev_state_ids, for_verification=True,
            )
            auth_events = yield self.store.get_events(auth_events_ids)
            auth_events = {
                (e.type, e.state_key): e for e in auth_events.values()
            }
            if self.auth.check_redaction(event, auth_events=auth_events):
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

        if event.type == EventTypes.Create and context.prev_state_ids:
            raise AuthError(
                403,
                "Changing the room create event is forbidden",
            )

        (event_stream_id, max_stream_id) = yield self.store.persist_event(
            event, context=context
        )

        # this intentionally does not yield: we don't care about the result
        # and don't need to wait for it.
        preserve_fn(self.pusher_pool.on_new_notifications)(
            event_stream_id, max_stream_id
        )

        @defer.inlineCallbacks
        def _notify():
            yield run_on_reactor()
            self.notifier.on_new_room_event(
                event, event_stream_id, max_stream_id,
                extra_users=extra_users
            )

        preserve_fn(_notify)()

        if event.type == EventTypes.Message:
            presence = self.hs.get_presence_handler()
            # We don't want to block sending messages on any presence code. This
            # matters as sometimes presence code can take a while.
            preserve_fn(presence.bump_presence_active_time)(requester.user)
