# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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

"""Contains functions for performing events on rooms."""
from twisted.internet import defer

from synapse.types import UserID, RoomAlias, RoomID
from synapse.api.constants import Membership
from synapse.api.errors import RoomError, StoreError, SynapseError
from synapse.api.events.room import (
    RoomTopicEvent, RoomMemberEvent, RoomConfigEvent
)
from synapse.streams.config import PaginationConfig
from synapse.util import stringutils
from ._base import BaseRoomHandler

import logging

logger = logging.getLogger(__name__)


class MessageHandler(BaseRoomHandler):

    def __init__(self, hs):
        super(MessageHandler, self).__init__(hs)
        self.hs = hs
        self.clock = hs.get_clock()
        self.event_factory = hs.get_event_factory()

    @defer.inlineCallbacks
    def get_message(self, msg_id=None, room_id=None, sender_id=None,
                    user_id=None):
        """ Retrieve a message.

        Args:
            msg_id (str): The message ID to obtain.
            room_id (str): The room where the message resides.
            sender_id (str): The user ID of the user who sent the message.
            user_id (str): The user ID of the user making this request.
        Returns:
            The message, or None if no message exists.
        Raises:
            SynapseError if something went wrong.
        """
        yield self.auth.check_joined_room(room_id, user_id)

        # Pull out the message from the db
#        msg = yield self.store.get_message(
#            room_id=room_id,
#            msg_id=msg_id,
#            user_id=sender_id
#        )

        # TODO (erikj): Once we work out the correct c-s api we need to think on how to do this.

        defer.returnValue(None)

    @defer.inlineCallbacks
    def send_message(self, event=None, suppress_auth=False, stamp_event=True):
        """ Send a message.

        Args:
            event : The message event to store.
            suppress_auth (bool) : True to suppress auth for this message. This
            is primarily so the home server can inject messages into rooms at
            will.
            stamp_event (bool) : True to stamp event content with server keys.
        Raises:
            SynapseError if something went wrong.
        """
        if stamp_event:
            event.content["hsob_ts"] = int(self.clock.time_msec())

        snapshot = yield self.store.snapshot_room(event.room_id, event.user_id)

        if not suppress_auth:
            yield self.auth.check(event, snapshot, raises=True)

        yield self._on_new_room_event(event, snapshot)

    @defer.inlineCallbacks
    def get_messages(self, user_id=None, room_id=None, pagin_config=None,
                     feedback=False):
        """Get messages in a room.

        Args:
            user_id (str): The user requesting messages.
            room_id (str): The room they want messages from.
            pagin_config (synapse.api.streams.PaginationConfig): The pagination
            config rules to apply, if any.
            feedback (bool): True to get compressed feedback with the messages
        Returns:
            dict: Pagination API results
        """
        yield self.auth.check_joined_room(room_id, user_id)

        data_source = self.hs.get_event_sources().sources["room"]

        if not pagin_config.from_token:
            pagin_config.from_token = yield self.hs.get_event_sources().get_current_token()

        user = self.hs.parse_userid(user_id)

        events, next_token = yield data_source.get_pagination_rows(
            user, pagin_config, room_id
        )

        chunk = {
            "chunk": [e.get_dict() for e in events],
            "start": pagin_config.from_token.to_string(),
            "end": next_token.to_string(),
        }

        defer.returnValue(chunk)

    @defer.inlineCallbacks
    def store_room_data(self, event=None, stamp_event=True):
        """ Stores data for a room.

        Args:
            event : The room path event
            stamp_event (bool) : True to stamp event content with server keys.
        Raises:
            SynapseError if something went wrong.
        """

        snapshot = yield self.store.snapshot_room(event.room_id, event.user_id)

        yield self.auth.check(event, snapshot, raises=True)

        if stamp_event:
            event.content["hsob_ts"] = int(self.clock.time_msec())

        yield self.state_handler.handle_new_event(event, snapshot)

        yield self._on_new_room_event(event, snapshot)

    @defer.inlineCallbacks
    def get_room_data(self, user_id=None, room_id=None,
                      event_type=None, state_key="",
                      public_room_rules=[],
                      private_room_rules=["join"]):
        """ Get data from a room.

        Args:
            event : The room path event
            public_room_rules : A list of membership states the user can be in,
            in order to read this data IN A PUBLIC ROOM. An empty list means
            'any state'.
            private_room_rules : A list of membership states the user can be
            in, in order to read this data IN A PRIVATE ROOM. An empty list
            means 'any state'.
        Returns:
            The path data content.
        Raises:
            SynapseError if something went wrong.
        """
        if event_type == RoomTopicEvent.TYPE:
            # anyone invited/joined can read the topic
            private_room_rules = ["invite", "join"]

        # does this room exist
        room = yield self.store.get_room(room_id)
        if not room:
            raise RoomError(403, "Room does not exist.")

        # does this user exist in this room
        member = yield self.store.get_room_member(
            room_id=room_id,
            user_id="" if not user_id else user_id)

        member_state = member.membership if member else None

        if room.is_public and public_room_rules:
            # make sure the user meets public room rules
            if member_state not in public_room_rules:
                raise RoomError(403, "Member does not meet public room rules.")
        elif not room.is_public and private_room_rules:
            # make sure the user meets private room rules
            if member_state not in private_room_rules:
                raise RoomError(
                    403, "Member does not meet private room rules.")

        data = yield self.store.get_current_state(
            room_id, event_type, state_key
        )
        defer.returnValue(data)

    @defer.inlineCallbacks
    def get_feedback(self, event_id):
        # yield self.auth.check_joined_room(room_id, user_id)

        # Pull out the feedback from the db
        fb = yield self.store.get_feedback(event_id)

        if fb:
            defer.returnValue(fb)
        defer.returnValue(None)

    @defer.inlineCallbacks
    def send_feedback(self, event, stamp_event=True):
        if stamp_event:
            event.content["hsob_ts"] = int(self.clock.time_msec())

        snapshot = yield self.store.snapshot_room(event.room_id, event.user_id)

        yield self.auth.check(event, snapshot, raises=True)

        # store message in db
        yield self._on_new_room_event(event, snapshot)

    @defer.inlineCallbacks
    def snapshot_all_rooms(self, user_id=None, pagin_config=None,
                           feedback=False):
        """Retrieve a snapshot of all rooms the user is invited or has joined.

        This snapshot may include messages for all rooms where the user is
        joined, depending on the pagination config.

        Args:
            user_id (str): The ID of the user making the request.
            pagin_config (synapse.api.streams.PaginationConfig): The pagination
            config used to determine how many messages *PER ROOM* to return.
            feedback (bool): True to get feedback along with these messages.
        Returns:
            A list of dicts with "room_id" and "membership" keys for all rooms
            the user is currently invited or joined in on. Rooms where the user
            is joined on, may return a "messages" key with messages, depending
            on the specified PaginationConfig.
        """
        room_list = yield self.store.get_rooms_for_user_where_membership_is(
            user_id=user_id,
            membership_list=[Membership.INVITE, Membership.JOIN]
        )

        user = self.hs.parse_userid(user_id)

        rooms_ret = []

        now_token = yield self.hs.get_event_sources().get_current_token()

        presence_stream = self.hs.get_event_sources().sources["presence"]
        pagination_config = PaginationConfig(from_token=now_token)
        presence, _ = yield presence_stream.get_pagination_rows(
            user, pagination_config, None
        )

        limit = pagin_config.limit
        if not limit:
            limit = 10

        for event in room_list:
            d = {
                "room_id": event.room_id,
                "membership": event.membership,
            }

            if event.membership == Membership.INVITE:
                d["inviter"] = event.user_id

            rooms_ret.append(d)

            if event.membership != Membership.JOIN:
                continue
            try:
                messages, token = yield self.store.get_recent_events_for_room(
                    event.room_id,
                    limit=limit,
                    end_token=now_token.events_key,
                )

                d["messages"] = {
                    "chunk": [m.get_dict() for m in messages],
                    "start": token[0],
                    "end": token[1],
                }

                current_state = yield self.store.get_current_state(
                    event.room_id
                )
                d["state"] = [c.get_dict() for c in current_state]
            except:
                logger.exception("Failed to get snapshot")

        ret = {
            "rooms": rooms_ret,
            "presence": presence,
            "end": now_token.to_string()
        }

        defer.returnValue(ret)


class RoomCreationHandler(BaseRoomHandler):

    @defer.inlineCallbacks
    def create_room(self, user_id, room_id, config):
        """ Creates a new room.

        Args:
            user_id (str): The ID of the user creating the new room.
            room_id (str): The proposed ID for the new room. Can be None, in
            which case one will be created for you.
            config (dict) : A dict of configuration options.
        Returns:
            The new room ID.
        Raises:
            SynapseError if the room ID was taken, couldn't be stored, or
            something went horribly wrong.
        """

        if "room_alias_name" in config:
            room_alias = RoomAlias.create_local(
                config["room_alias_name"],
                self.hs
            )
            mapping = yield self.store.get_association_from_room_alias(
                room_alias
            )

            if mapping:
                raise SynapseError(400, "Room alias already taken")
        else:
            room_alias = None

        if room_id:
            # Ensure room_id is the correct type
            room_id_obj = RoomID.from_string(room_id, self.hs)
            if not room_id_obj.is_mine:
                raise SynapseError(400, "Room id must be local")

            yield self.store.store_room(
                room_id=room_id,
                room_creator_user_id=user_id,
                is_public=config["visibility"] == "public"
            )
        else:
            # autogen room IDs and try to create it. We may clash, so just
            # try a few times till one goes through, giving up eventually.
            attempts = 0
            room_id = None
            while attempts < 5:
                try:
                    random_string = stringutils.random_string(18)
                    gen_room_id = RoomID.create_local(random_string, self.hs)
                    yield self.store.store_room(
                        room_id=gen_room_id.to_string(),
                        room_creator_user_id=user_id,
                        is_public=config["visibility"] == "public"
                    )
                    room_id = gen_room_id.to_string()
                    break
                except StoreError:
                    attempts += 1
            if not room_id:
                raise StoreError(500, "Couldn't generate a room ID.")

        config_event = self.event_factory.create_event(
            etype=RoomConfigEvent.TYPE,
            room_id=room_id,
            user_id=user_id,
            content=config,
        )

        snapshot = yield self.store.snapshot_room(
            room_id=room_id,
            user_id=user_id,
            state_type=RoomConfigEvent.TYPE,
            state_key="",
        )

        if room_alias:
            yield self.store.create_room_alias_association(
                room_id=room_id,
                room_alias=room_alias,
                servers=[self.hs.hostname],
            )

        yield self.state_handler.handle_new_event(config_event, snapshot)
        # store_id = persist...

        federation_handler = self.hs.get_handlers().federation_handler
        yield federation_handler.handle_new_event(config_event, snapshot)

        content = {"membership": Membership.JOIN}
        join_event = self.event_factory.create_event(
            etype=RoomMemberEvent.TYPE,
            state_key=user_id,
            room_id=room_id,
            user_id=user_id,
            membership=Membership.JOIN,
            content=content
        )

        yield self.hs.get_handlers().room_member_handler.change_membership(
            join_event,
            do_auth=False
        )

        result = {"room_id": room_id}
        if room_alias:
            result["room_alias"] = room_alias.to_string()

        defer.returnValue(result)


class RoomMemberHandler(BaseRoomHandler):
    # TODO(paul): This handler currently contains a messy conflation of
    #   low-level API that works on UserID objects and so on, and REST-level
    #   API that takes ID strings and returns pagination chunks. These concerns
    #   ought to be separated out a lot better.

    def __init__(self, hs):
        super(RoomMemberHandler, self).__init__(hs)

        self.clock = hs.get_clock()

        self.distributor = hs.get_distributor()
        self.distributor.declare("user_joined_room")

    @defer.inlineCallbacks
    def get_room_members(self, room_id, membership=Membership.JOIN):
        hs = self.hs

        memberships = yield self.store.get_room_members(
            room_id=room_id, membership=membership
        )

        defer.returnValue([hs.parse_userid(m.user_id) for m in memberships])

    @defer.inlineCallbacks
    def fetch_room_distributions_into(self, room_id, localusers=None,
                                      remotedomains=None, ignore_user=None):
        """Fetch the distribution of a room, adding elements to either
        'localusers' or 'remotedomains', which should be a set() if supplied.
        If ignore_user is set, ignore that user.

        This function returns nothing; its result is performed by the
        side-effect on the two passed sets. This allows easy accumulation of
        member lists of multiple rooms at once if required.
        """
        members = yield self.get_room_members(room_id)
        for member in members:
            if ignore_user is not None and member == ignore_user:
                continue

            if member.is_mine:
                if localusers is not None:
                    localusers.add(member)
            else:
                if remotedomains is not None:
                    remotedomains.add(member.domain)

    @defer.inlineCallbacks
    def get_room_members_as_pagination_chunk(self, room_id=None, user_id=None,
                                             limit=0, start_tok=None,
                                             end_tok=None):
        """Retrieve a list of room members in the room.

        Args:
            room_id (str): The room to get the member list for.
            user_id (str): The ID of the user making the request.
            limit (int): The max number of members to return.
            start_tok (str): Optional. The start token if known.
            end_tok (str): Optional. The end token if known.
        Returns:
            dict: A Pagination streamable dict.
        Raises:
            SynapseError if something goes wrong.
        """
        yield self.auth.check_joined_room(room_id, user_id)

        member_list = yield self.store.get_room_members(room_id=room_id)
        event_list = [
            entry.get_dict()
            for entry in member_list
        ]
        chunk_data = {
            "start": "START",  # FIXME (erikj): START is no longer valid
            "end": "END",
            "chunk": event_list
        }
        # TODO honor Pagination stream params
        # TODO snapshot this list to return on subsequent requests when
        # paginating
        defer.returnValue(chunk_data)

    @defer.inlineCallbacks
    def get_room_member(self, room_id, member_user_id, auth_user_id):
        """Retrieve a room member from a room.

        Args:
            room_id : The room the member is in.
            member_user_id : The member's user ID
            auth_user_id : The user ID of the user making this request.
        Returns:
            The room member, or None if this member does not exist.
        Raises:
            SynapseError if something goes wrong.
        """
        yield self.auth.check_joined_room(room_id, auth_user_id)

        member = yield self.store.get_room_member(user_id=member_user_id,
                                                  room_id=room_id)
        defer.returnValue(member)

    @defer.inlineCallbacks
    def change_membership(self, event=None, do_auth=True):
        """ Change the membership status of a user in a room.

        Args:
            event (SynapseEvent): The membership event
        Raises:
            SynapseError if there was a problem changing the membership.
        """
        target_user_id = event.state_key

        snapshot = yield self.store.snapshot_room(
            event.room_id, event.user_id,
            RoomMemberEvent.TYPE, target_user_id
        )
        ## TODO(markjh): get prev state from snapshot.
        prev_state = yield self.store.get_room_member(
            target_user_id, event.room_id
        )

        if prev_state:
            event.content["prev"] = prev_state.membership

#        if prev_state and prev_state.membership == event.membership:
#            # treat this event as a NOOP.
#            if do_auth:  # This is mainly to fix a unit test.
#                yield self.auth.check(event, raises=True)
#            defer.returnValue({})
#            return

        room_id = event.room_id

        # If we're trying to join a room then we have to do this differently
        # if this HS is not currently in the room, i.e. we have to do the
        # invite/join dance.
        if event.membership == Membership.JOIN:
            yield self._do_join(event, snapshot, do_auth=do_auth)
        else:
            # This is not a JOIN, so we can handle it normally.
            if do_auth:
                yield self.auth.check(event, snapshot, raises=True)

            if prev_state and prev_state.membership == event.membership:
                # double same action, treat this event as a NOOP.
                defer.returnValue({})
                return

            yield self.state_handler.handle_new_event(event, snapshot)
            yield self._do_local_membership_update(
                event,
                membership=event.content["membership"],
                snapshot=snapshot,
            )

        defer.returnValue({"room_id": room_id})

    @defer.inlineCallbacks
    def join_room_alias(self, joinee, room_alias, do_auth=True, content={}):
        directory_handler = self.hs.get_handlers().directory_handler
        mapping = yield directory_handler.get_association(room_alias)

        if not mapping:
            raise SynapseError(404, "No such room alias")

        room_id = mapping["room_id"]
        hosts = mapping["servers"]
        if not hosts:
            raise SynapseError(404, "No known servers")

        host = hosts[0]

        content.update({"membership": Membership.JOIN})
        new_event = self.event_factory.create_event(
            etype=RoomMemberEvent.TYPE,
            state_key=joinee.to_string(),
            room_id=room_id,
            user_id=joinee.to_string(),
            membership=Membership.JOIN,
            content=content,
        )

        snapshot = yield self.store.snapshot_room(
            room_id, joinee, RoomMemberEvent.TYPE, joinee
        )

        yield self._do_join(new_event, snapshot, room_host=host, do_auth=True)

        defer.returnValue({"room_id": room_id})

    @defer.inlineCallbacks
    def _do_join(self, event, snapshot, room_host=None, do_auth=True):
        joinee = self.hs.parse_userid(event.state_key)
        # room_id = RoomID.from_string(event.room_id, self.hs)
        room_id = event.room_id

        # If event doesn't include a display name, add one.
        yield self.distributor.fire(
            "collect_presencelike_data", joinee, event.content
        )

        # XXX: We don't do an auth check if we are doing an invite
        # join dance for now, since we're kinda implicitly checking
        # that we are allowed to join when we decide whether or not we
        # need to do the invite/join dance.

        hosts = yield self.store.get_joined_hosts_for_room(room_id)

        if self.hs.hostname in hosts:
            should_do_dance = False
        elif room_host:
            should_do_dance = True
        else:
            # TODO(markjh): get prev_state from snapshot
            prev_state = yield self.store.get_room_member(
                joinee.to_string(), room_id
            )

            if prev_state and prev_state.membership == Membership.INVITE:
                room = yield self.store.get_room(room_id)
                inviter = UserID.from_string(
                    prev_state.user_id, self.hs
                )

                should_do_dance = not inviter.is_mine and not room
                room_host = inviter.domain
            else:
                should_do_dance = False

        have_joined = False
        if should_do_dance:
            handler = self.hs.get_handlers().federation_handler
            have_joined = yield handler.do_invite_join(
                room_host, room_id, event.user_id, event.content, snapshot
            )

        # We want to do the _do_update inside the room lock.
        if not have_joined:
            logger.debug("Doing normal join")

            if do_auth:
                yield self.auth.check(event, snapshot, raises=True)

            yield self.state_handler.handle_new_event(event, snapshot)
            yield self._do_local_membership_update(
                event,
                membership=event.content["membership"],
                snapshot=snapshot,
            )

        user = self.hs.parse_userid(event.user_id)
        self.distributor.fire(
            "user_joined_room", user=user, room_id=room_id
        )

    @defer.inlineCallbacks
    def _should_invite_join(self, room_id, prev_state, do_auth):
        logger.debug("_should_invite_join: room_id: %s", room_id)

        # XXX: We don't do an auth check if we are doing an invite
        # join dance for now, since we're kinda implicitly checking
        # that we are allowed to join when we decide whether or not we
        # need to do the invite/join dance.

        # Only do an invite join dance if a) we were invited,
        # b) the person inviting was from a differnt HS and c) we are
        # not currently in the room
        room_host = None
        if prev_state and prev_state.membership == Membership.INVITE:
            room = yield self.store.get_room(room_id)
            inviter = UserID.from_string(
                prev_state.sender, self.hs
            )

            is_remote_invite_join = not inviter.is_mine and not room
            room_host = inviter.domain
        else:
            is_remote_invite_join = False

        defer.returnValue((is_remote_invite_join, room_host))

    @defer.inlineCallbacks
    def get_rooms_for_user(self, user, membership_list=[Membership.JOIN]):
        """Returns a list of roomids that the user has any of the given
        membership states in."""
        rooms = yield self.store.get_rooms_for_user_where_membership_is(
            user_id=user.to_string(), membership_list=membership_list
        )

        defer.returnValue([r.room_id for r in rooms])

    def _do_local_membership_update(self, event, membership, snapshot):
        destinations = []

        # If we're inviting someone, then we should also send it to that
        # HS.
        target_user_id = event.state_key
        target_user = self.hs.parse_userid(target_user_id)
        if membership == Membership.INVITE:
            host = target_user.domain
            destinations.append(host)

        # If we are joining a remote HS, include that.
        if membership == Membership.JOIN:
            host = target_user.domain
            destinations.append(host)

        return self._on_new_room_event(
            event, snapshot, extra_destinations=destinations,
            extra_users=[target_user]
        )

class RoomListHandler(BaseRoomHandler):

    @defer.inlineCallbacks
    def get_public_room_list(self):
        chunk = yield self.store.get_rooms(is_public=True)
        # FIXME (erikj): START is no longer a valid value
        defer.returnValue({"start": "START", "end": "END", "chunk": chunk})
