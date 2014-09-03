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
from synapse.api.constants import Membership, JoinRules
from synapse.api.errors import StoreError, SynapseError
from synapse.api.events.room import (
    RoomMemberEvent, RoomCreateEvent, RoomPowerLevelsEvent,
    RoomJoinRulesEvent, RoomAddStateLevelEvent, RoomTopicEvent,
    RoomSendEventLevelEvent, RoomOpsPowerLevelsEvent, RoomNameEvent,
)
from synapse.util import stringutils
from ._base import BaseRoomHandler

import logging

logger = logging.getLogger(__name__)


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
        self.ratelimit(user_id)

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

        is_public = config.get("visibility", None) == "public"

        if room_id:
            # Ensure room_id is the correct type
            room_id_obj = RoomID.from_string(room_id, self.hs)
            if not room_id_obj.is_mine:
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
                    gen_room_id = RoomID.create_local(random_string, self.hs)
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

        user = self.hs.parse_userid(user_id)
        creation_events = self._create_events_for_new_room(
            user, room_id, is_public=is_public
        )

        if room_alias:
            yield self.store.create_room_alias_association(
                room_id=room_id,
                room_alias=room_alias,
                servers=[self.hs.hostname],
            )

        @defer.inlineCallbacks
        def handle_event(event):
            snapshot = yield self.store.snapshot_room(
                room_id=room_id,
                user_id=user_id,
            )

            logger.debug("Event: %s", event)

            yield self.state_handler.handle_new_event(event, snapshot)
            yield self._on_new_room_event(event, snapshot, extra_users=[user])

        for event in creation_events:
            yield handle_event(event)

        if "name" in config:
            name = config["name"]
            name_event = self.event_factory.create_event(
                etype=RoomNameEvent.TYPE,
                room_id=room_id,
                user_id=user_id,
                required_power_level=5,
                content={"name": name},
            )

            yield handle_event(name_event)

        if "topic" in config:
            topic = config["topic"]
            topic_event = self.event_factory.create_event(
                etype=RoomTopicEvent.TYPE,
                room_id=room_id,
                user_id=user_id,
                required_power_level=5,
                content={"topic": topic},
            )

            yield handle_event(topic_event)

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

    def _create_events_for_new_room(self, creator, room_id, is_public=False):
        event_keys = {
            "room_id": room_id,
            "user_id": creator.to_string(),
            "required_power_level": 10,
        }

        def create(etype, **content):
            return self.event_factory.create_event(
                etype=etype,
                content=content,
                **event_keys
            )

        creation_event = create(
            etype=RoomCreateEvent.TYPE,
            creator=creator.to_string(),
        )

        power_levels_event = self.event_factory.create_event(
            etype=RoomPowerLevelsEvent.TYPE,
            content={creator.to_string(): 10, "default": 0},
            **event_keys
        )

        join_rule = JoinRules.PUBLIC if is_public else JoinRules.INVITE
        join_rules_event = create(
            etype=RoomJoinRulesEvent.TYPE,
            join_rule=join_rule,
        )

        add_state_event = create(
            etype=RoomAddStateLevelEvent.TYPE,
            level=10,
        )

        send_event = create(
            etype=RoomSendEventLevelEvent.TYPE,
            level=0,
        )

        ops = create(
            etype=RoomOpsPowerLevelsEvent.TYPE,
            ban_level=5,
            kick_level=5,
        )

        return [
            creation_event,
            power_levels_event,
            join_rules_event,
            add_state_event,
            send_event,
            ops,
        ]


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

            # If we're banning someone, set a req power level
            if event.membership == Membership.BAN:
                if not hasattr(event, "required_power_level") or event.required_power_level is None:
                    # Add some default required_power_level
                    user_level = yield self.store.get_power_level(
                        event.room_id,
                        event.user_id,
                    )
                    event.required_power_level = user_level

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
            room_id, joinee.to_string(), RoomMemberEvent.TYPE,
            joinee.to_string()
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

        # Always include target domain
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
    def get_pagination_rows(self, user, pagination_config, key):
        from_token = pagination_config.from_token
        to_token = pagination_config.to_token
        limit = pagination_config.limit
        direction = pagination_config.direction

        to_key = to_token.room_key if to_token else None

        events, next_key = yield self.store.paginate_room_events(
            room_id=key,
            from_key=from_token.room_key,
            to_key=to_key,
            direction=direction,
            limit=limit,
            with_feedback=True
        )

        next_token = from_token.copy_and_replace("room_key", next_key)

        defer.returnValue((events, next_token))
