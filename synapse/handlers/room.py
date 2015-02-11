# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

from ._base import BaseHandler

from synapse.types import UserID, RoomAlias, RoomID
from synapse.api.constants import EventTypes, Membership, JoinRules
from synapse.api.errors import StoreError, SynapseError
from synapse.util import stringutils
from synapse.util.async import run_on_reactor
from synapse.events.utils import serialize_event

import logging

logger = logging.getLogger(__name__)


class RoomCreationHandler(BaseHandler):

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
        self.ratelimit(user_id)

        if "room_alias_name" in config:
            room_alias = RoomAlias.create(
                config["room_alias_name"],
                self.hs.hostname,
            )
            mapping = yield self.store.get_association_from_room_alias(
                room_alias
            )

            if mapping:
                raise SynapseError(400, "Room alias already taken")
        else:
            room_alias = None

        invite_list = config.get("invite", [])
        for i in invite_list:
            try:
                UserID.from_string(i)
            except:
                raise SynapseError(400, "Invalid user_id: %s" % (i,))

        is_public = config.get("visibility", None) == "public"

        if room_id:
            # Ensure room_id is the correct type
            room_id_obj = RoomID.from_string(room_id)
            if not self.hs.is_mine(room_id_obj):
                raise SynapseError(400, "Room id must be local")

            yield self.store.store_room(
                room_id=room_id,
                room_creator_user_id=user_id,
                is_public=is_public
            )
        else:
            # autogen room IDs and try to create it. We may clash, so just
            # try a few times till one goes through, giving up eventually.
            attempts = 0
            room_id = None
            while attempts < 5:
                try:
                    random_string = stringutils.random_string(18)
                    gen_room_id = RoomID.create(
                        random_string,
                        self.hs.hostname,
                    )
                    yield self.store.store_room(
                        room_id=gen_room_id.to_string(),
                        room_creator_user_id=user_id,
                        is_public=is_public
                    )
                    room_id = gen_room_id.to_string()
                    break
                except StoreError:
                    attempts += 1
            if not room_id:
                raise StoreError(500, "Couldn't generate a room ID.")

        if room_alias:
            directory_handler = self.hs.get_handlers().directory_handler
            yield directory_handler.create_association(
                user_id=user_id,
                room_id=room_id,
                room_alias=room_alias,
                servers=[self.hs.hostname],
            )

        user = UserID.from_string(user_id)
        creation_events = self._create_events_for_new_room(
            user, room_id, is_public=is_public
        )

        msg_handler = self.hs.get_handlers().message_handler

        for event in creation_events:
            yield msg_handler.create_and_send_event(event)

        if "name" in config:
            name = config["name"]
            yield msg_handler.create_and_send_event({
                "type": EventTypes.Name,
                "room_id": room_id,
                "sender": user_id,
                "state_key": "",
                "content": {"name": name},
            })

        if "topic" in config:
            topic = config["topic"]
            yield msg_handler.create_and_send_event({
                "type": EventTypes.Topic,
                "room_id": room_id,
                "sender": user_id,
                "state_key": "",
                "content": {"topic": topic},
            })

        for invitee in invite_list:
            yield msg_handler.create_and_send_event({
                "type": EventTypes.Member,
                "state_key": invitee,
                "room_id": room_id,
                "sender": user_id,
                "content": {"membership": Membership.INVITE},
            })

        result = {"room_id": room_id}

        if room_alias:
            result["room_alias"] = room_alias.to_string()
            yield directory_handler.send_room_alias_update_event(
                user_id, room_id
            )

        defer.returnValue(result)

    def _create_events_for_new_room(self, creator, room_id, is_public=False):
        creator_id = creator.to_string()

        event_keys = {
            "room_id": room_id,
            "sender": creator_id,
            "state_key": "",
        }

        def create(etype, content, **kwargs):
            e = {
                "type": etype,
                "content": content,
            }

            e.update(event_keys)
            e.update(kwargs)

            return e

        creation_event = create(
            etype=EventTypes.Create,
            content={"creator": creator.to_string()},
        )

        join_event = create(
            etype=EventTypes.Member,
            state_key=creator_id,
            content={
                "membership": Membership.JOIN,
            },
        )

        power_levels_event = create(
            etype=EventTypes.PowerLevels,
            content={
                "users": {
                    creator.to_string(): 100,
                },
                "users_default": 0,
                "events": {
                    EventTypes.Name: 100,
                    EventTypes.PowerLevels: 100,
                },
                "events_default": 0,
                "state_default": 50,
                "ban": 50,
                "kick": 50,
                "redact": 50
            },
        )

        join_rule = JoinRules.PUBLIC if is_public else JoinRules.INVITE
        join_rules_event = create(
            etype=EventTypes.JoinRules,
            content={"join_rule": join_rule},
        )

        return [
            creation_event,
            join_event,
            power_levels_event,
            join_rules_event,
        ]


class RoomMemberHandler(BaseHandler):
    # TODO(paul): This handler currently contains a messy conflation of
    #   low-level API that works on UserID objects and so on, and REST-level
    #   API that takes ID strings and returns pagination chunks. These concerns
    #   ought to be separated out a lot better.

    def __init__(self, hs):
        super(RoomMemberHandler, self).__init__(hs)

        self.clock = hs.get_clock()

        self.distributor = hs.get_distributor()
        self.distributor.declare("user_joined_room")
        self.distributor.declare("user_left_room")

    @defer.inlineCallbacks
    def get_room_members(self, room_id):
        users = yield self.store.get_users_in_room(room_id)

        defer.returnValue([UserID.from_string(u) for u in users])

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

            if self.hs.is_mine(member):
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
        time_now = self.clock.time_msec()
        event_list = [
            serialize_event(entry, time_now)
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
    def change_membership(self, event, context, do_auth=True):
        """ Change the membership status of a user in a room.

        Args:
            event (SynapseEvent): The membership event
        Raises:
            SynapseError if there was a problem changing the membership.
        """
        target_user_id = event.state_key

        prev_state = context.current_state.get(
            (EventTypes.Member, target_user_id),
            None
        )

        room_id = event.room_id

        # If we're trying to join a room then we have to do this differently
        # if this HS is not currently in the room, i.e. we have to do the
        # invite/join dance.
        if event.membership == Membership.JOIN:
            yield self._do_join(event, context, do_auth=do_auth)
        else:
            # This is not a JOIN, so we can handle it normally.

            # FIXME: This isn't idempotency.
            if prev_state and prev_state.membership == event.membership:
                # double same action, treat this event as a NOOP.
                defer.returnValue({})
                return

            yield self._do_local_membership_update(
                event,
                membership=event.content["membership"],
                context=context,
                do_auth=do_auth,
            )

            if prev_state and prev_state.membership == Membership.JOIN:
                user = UserID.from_string(event.user_id)
                self.distributor.fire(
                    "user_left_room", user=user, room_id=event.room_id
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

        # If event doesn't include a display name, add one.
        yield self.distributor.fire(
            "collect_presencelike_data", joinee, content
        )

        content.update({"membership": Membership.JOIN})
        builder = self.event_builder_factory.new({
            "type": EventTypes.Member,
            "state_key": joinee.to_string(),
            "room_id": room_id,
            "sender": joinee.to_string(),
            "membership": Membership.JOIN,
            "content": content,
        })
        event, context = yield self._create_new_client_event(builder)

        yield self._do_join(event, context, room_hosts=hosts, do_auth=True)

        defer.returnValue({"room_id": room_id})

    @defer.inlineCallbacks
    def _do_join(self, event, context, room_hosts=None, do_auth=True):
        joinee = UserID.from_string(event.state_key)
        # room_id = RoomID.from_string(event.room_id, self.hs)
        room_id = event.room_id

        # XXX: We don't do an auth check if we are doing an invite
        # join dance for now, since we're kinda implicitly checking
        # that we are allowed to join when we decide whether or not we
        # need to do the invite/join dance.

        is_host_in_room = yield self.auth.check_host_in_room(
            event.room_id,
            self.hs.hostname
        )
        if not is_host_in_room:
            # is *anyone* in the room?
            room_member_keys = [
                v for (k, v) in context.current_state.keys() if (
                    k == "m.room.member"
                )
            ]
            if len(room_member_keys) == 0:
                # has the room been created so we can join it?
                create_event = context.current_state.get(("m.room.create", ""))
                if create_event:
                    is_host_in_room = True

        if is_host_in_room:
            should_do_dance = False
        elif room_hosts:  # TODO: Shouldn't this be remote_room_host?
            should_do_dance = True
        else:
            # TODO(markjh): get prev_state from snapshot
            prev_state = yield self.store.get_room_member(
                joinee.to_string(), room_id
            )

            if prev_state and prev_state.membership == Membership.INVITE:
                inviter = UserID.from_string(prev_state.user_id)

                should_do_dance = not self.hs.is_mine(inviter)
                room_hosts = [inviter.domain]
            else:
                # return the same error as join_room_alias does
                raise SynapseError(404, "No known servers")

        if should_do_dance:
            handler = self.hs.get_handlers().federation_handler
            yield handler.do_invite_join(
                room_hosts,
                room_id,
                event.user_id,
                event.content,  # FIXME To get a non-frozen dict
                context
            )
        else:
            logger.debug("Doing normal join")

            yield self._do_local_membership_update(
                event,
                membership=event.content["membership"],
                context=context,
                do_auth=do_auth,
            )

        user = UserID.from_string(event.user_id)
        yield self.distributor.fire(
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
                prev_state.sender
            )

            is_remote_invite_join = not self.hs.is_mine(inviter) and not room
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

        # For some reason the list of events contains duplicates
        # TODO(paul): work out why because I really don't think it should
        room_ids = set(r.room_id for r in rooms)

        defer.returnValue(room_ids)

    @defer.inlineCallbacks
    def _do_local_membership_update(self, event, membership, context,
                                    do_auth):
        yield run_on_reactor()

        target_user = UserID.from_string(event.state_key)

        yield self.handle_new_client_event(
            event,
            context,
            extra_users=[target_user],
            suppress_auth=(not do_auth),
        )


class RoomListHandler(BaseHandler):

    @defer.inlineCallbacks
    def get_public_room_list(self):
        chunk = yield self.store.get_rooms(is_public=True)
        for room in chunk:
            joined_users = yield self.store.get_users_in_room(
                room_id=room["room_id"],
            )
            room["num_joined_members"] = len(joined_users)
        # FIXME (erikj): START is no longer a valid value
        defer.returnValue({"start": "START", "end": "END", "chunk": chunk})


class RoomEventSource(object):
    def __init__(self, hs):
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def get_new_events_for_user(self, user, from_key, limit):
        # We just ignore the key for now.

        to_key = yield self.get_current_key()

        events, end_key = yield self.store.get_room_events_stream(
            user_id=user.to_string(),
            from_key=from_key,
            to_key=to_key,
            room_id=None,
            limit=limit,
        )

        defer.returnValue((events, end_key))

    def get_current_key(self):
        return self.store.get_room_events_max_id()

    @defer.inlineCallbacks
    def get_pagination_rows(self, user, config, key):
        events, next_key = yield self.store.paginate_room_events(
            room_id=key,
            from_key=config.from_key,
            to_key=config.to_key,
            direction=config.direction,
            limit=config.limit,
            with_feedback=True
        )

        defer.returnValue((events, next_key))
