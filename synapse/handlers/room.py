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
from synapse.api.constants import (
    EventTypes, Membership, JoinRules, RoomCreationPreset,
)
from synapse.api.errors import AuthError, StoreError, SynapseError
from synapse.util import stringutils, unwrapFirstError
from synapse.util.async import run_on_reactor

from signedjson.sign import verify_signed_json
from signedjson.key import decode_verify_key_bytes

from collections import OrderedDict
from unpaddedbase64 import decode_base64

import logging
import math
import string

logger = logging.getLogger(__name__)

id_server_scheme = "https://"


def collect_presencelike_data(distributor, user, content):
    return distributor.fire("collect_presencelike_data", user, content)


def user_left_room(distributor, user, room_id):
    return distributor.fire("user_left_room", user=user, room_id=room_id)


def user_joined_room(distributor, user, room_id):
    return distributor.fire("user_joined_room", user=user, room_id=room_id)


class RoomCreationHandler(BaseHandler):

    PRESETS_DICT = {
        RoomCreationPreset.PRIVATE_CHAT: {
            "join_rules": JoinRules.INVITE,
            "history_visibility": "shared",
            "original_invitees_have_ops": False,
        },
        RoomCreationPreset.TRUSTED_PRIVATE_CHAT: {
            "join_rules": JoinRules.INVITE,
            "history_visibility": "shared",
            "original_invitees_have_ops": True,
        },
        RoomCreationPreset.PUBLIC_CHAT: {
            "join_rules": JoinRules.PUBLIC,
            "history_visibility": "shared",
            "original_invitees_have_ops": False,
        },
    }

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
            for wchar in string.whitespace:
                if wchar in config["room_alias_name"]:
                    raise SynapseError(400, "Invalid characters in room alias")

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

        preset_config = config.get(
            "preset",
            RoomCreationPreset.PUBLIC_CHAT
            if is_public
            else RoomCreationPreset.PRIVATE_CHAT
        )

        raw_initial_state = config.get("initial_state", [])

        initial_state = OrderedDict()
        for val in raw_initial_state:
            initial_state[(val["type"], val.get("state_key", ""))] = val["content"]

        creation_content = config.get("creation_content", {})

        user = UserID.from_string(user_id)
        creation_events = self._create_events_for_new_room(
            user, room_id,
            preset_config=preset_config,
            invite_list=invite_list,
            initial_state=initial_state,
            creation_content=creation_content,
            room_alias=room_alias,
        )

        msg_handler = self.hs.get_handlers().message_handler

        for event in creation_events:
            yield msg_handler.create_and_send_event(event, ratelimit=False)

        if "name" in config:
            name = config["name"]
            yield msg_handler.create_and_send_event({
                "type": EventTypes.Name,
                "room_id": room_id,
                "sender": user_id,
                "state_key": "",
                "content": {"name": name},
            }, ratelimit=False)

        if "topic" in config:
            topic = config["topic"]
            yield msg_handler.create_and_send_event({
                "type": EventTypes.Topic,
                "room_id": room_id,
                "sender": user_id,
                "state_key": "",
                "content": {"topic": topic},
            }, ratelimit=False)

        for invitee in invite_list:
            yield msg_handler.create_and_send_event({
                "type": EventTypes.Member,
                "state_key": invitee,
                "room_id": room_id,
                "sender": user_id,
                "content": {"membership": Membership.INVITE},
            }, ratelimit=False)

        result = {"room_id": room_id}

        if room_alias:
            result["room_alias"] = room_alias.to_string()
            yield directory_handler.send_room_alias_update_event(
                user_id, room_id
            )

        defer.returnValue(result)

    def _create_events_for_new_room(self, creator, room_id, preset_config,
                                    invite_list, initial_state, creation_content,
                                    room_alias):
        config = RoomCreationHandler.PRESETS_DICT[preset_config]

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

        creation_content.update({"creator": creator.to_string()})
        creation_event = create(
            etype=EventTypes.Create,
            content=creation_content,
        )

        join_event = create(
            etype=EventTypes.Member,
            state_key=creator_id,
            content={
                "membership": Membership.JOIN,
            },
        )

        returned_events = [creation_event, join_event]

        if (EventTypes.PowerLevels, '') not in initial_state:
            power_level_content = {
                "users": {
                    creator.to_string(): 100,
                },
                "users_default": 0,
                "events": {
                    EventTypes.Name: 50,
                    EventTypes.PowerLevels: 100,
                    EventTypes.RoomHistoryVisibility: 100,
                    EventTypes.CanonicalAlias: 50,
                    EventTypes.RoomAvatar: 50,
                },
                "events_default": 0,
                "state_default": 50,
                "ban": 50,
                "kick": 50,
                "redact": 50,
                "invite": 0,
            }

            if config["original_invitees_have_ops"]:
                for invitee in invite_list:
                    power_level_content["users"][invitee] = 100

            power_levels_event = create(
                etype=EventTypes.PowerLevels,
                content=power_level_content,
            )

            returned_events.append(power_levels_event)

        if room_alias and (EventTypes.CanonicalAlias, '') not in initial_state:
            room_alias_event = create(
                etype=EventTypes.CanonicalAlias,
                content={"alias": room_alias.to_string()},
            )

            returned_events.append(room_alias_event)

        if (EventTypes.JoinRules, '') not in initial_state:
            join_rules_event = create(
                etype=EventTypes.JoinRules,
                content={"join_rule": config["join_rules"]},
            )

            returned_events.append(join_rules_event)

        if (EventTypes.RoomHistoryVisibility, '') not in initial_state:
            history_event = create(
                etype=EventTypes.RoomHistoryVisibility,
                content={"history_visibility": config["history_visibility"]}
            )

            returned_events.append(history_event)

        for (etype, state_key), content in initial_state.items():
            returned_events.append(create(
                etype=etype,
                state_key=state_key,
                content=content,
            ))

        return returned_events


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
    def change_membership(self, event, context, do_auth=True, is_guest=False):
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
            if is_guest:
                guest_access = context.current_state.get(
                    (EventTypes.GuestAccess, ""),
                    None
                )
                is_guest_access_allowed = (
                    guest_access
                    and guest_access.content
                    and "guest_access" in guest_access.content
                    and guest_access.content["guest_access"] == "can_join"
                )
                if not is_guest_access_allowed:
                    raise AuthError(403, "Guest access not allowed")

            yield self._do_join(event, context, do_auth=do_auth)
        else:
            if event.membership == Membership.LEAVE:
                is_host_in_room = yield self.is_host_in_room(room_id, context)
                if not is_host_in_room:
                    # Rejecting an invite, rather than leaving a joined room
                    handler = self.hs.get_handlers().federation_handler
                    inviter = yield self.get_inviter(event)
                    if not inviter:
                        # return the same error as join_room_alias does
                        raise SynapseError(404, "No known servers")
                    yield handler.do_remotely_reject_invite(
                        [inviter.domain],
                        room_id,
                        event.user_id
                    )
                    defer.returnValue({"room_id": room_id})
                    return

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
                user_left_room(self.distributor, user, event.room_id)

        defer.returnValue({"room_id": room_id})

    @defer.inlineCallbacks
    def join_room_alias(self, joinee, room_alias, content={}):
        directory_handler = self.hs.get_handlers().directory_handler
        mapping = yield directory_handler.get_association(room_alias)

        if not mapping:
            raise SynapseError(404, "No such room alias")

        room_id = mapping["room_id"]
        hosts = mapping["servers"]
        if not hosts:
            raise SynapseError(404, "No known servers")

        # If event doesn't include a display name, add one.
        yield collect_presencelike_data(self.distributor, joinee, content)

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
        room_id = event.room_id

        # XXX: We don't do an auth check if we are doing an invite
        # join dance for now, since we're kinda implicitly checking
        # that we are allowed to join when we decide whether or not we
        # need to do the invite/join dance.

        is_host_in_room = yield self.is_host_in_room(room_id, context)
        if is_host_in_room:
            should_do_dance = False
        elif room_hosts:  # TODO: Shouldn't this be remote_room_host?
            should_do_dance = True
        else:
            inviter = yield self.get_inviter(event)
            if not inviter:
                # return the same error as join_room_alias does
                raise SynapseError(404, "No known servers")
            should_do_dance = not self.hs.is_mine(inviter)
            room_hosts = [inviter.domain]

        if should_do_dance:
            handler = self.hs.get_handlers().federation_handler
            yield handler.do_invite_join(
                room_hosts,
                room_id,
                event.user_id,
                event.content,
            )
        else:
            logger.debug("Doing normal join")

            yield self._do_local_membership_update(
                event,
                membership=event.content["membership"],
                context=context,
                do_auth=do_auth,
            )

        prev_state = context.current_state.get((event.type, event.state_key))
        if not prev_state or prev_state.membership != Membership.JOIN:
            # Only fire user_joined_room if the user has acutally joined the
            # room. Don't bother if the user is just changing their profile
            # info.
            user = UserID.from_string(event.user_id)
            yield user_joined_room(self.distributor, user, room_id)

    @defer.inlineCallbacks
    def get_inviter(self, event):
        # TODO(markjh): get prev_state from snapshot
        prev_state = yield self.store.get_room_member(
            event.user_id, event.room_id
        )

        if prev_state and prev_state.membership == Membership.INVITE:
            defer.returnValue(UserID.from_string(prev_state.user_id))
            return
        elif "third_party_invite" in event.content:
            if "sender" in event.content["third_party_invite"]:
                inviter = UserID.from_string(
                    event.content["third_party_invite"]["sender"]
                )
                defer.returnValue(inviter)
        defer.returnValue(None)

    @defer.inlineCallbacks
    def is_host_in_room(self, room_id, context):
        is_host_in_room = yield self.auth.check_host_in_room(
            room_id,
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
        defer.returnValue(is_host_in_room)

    @defer.inlineCallbacks
    def get_joined_rooms_for_user(self, user):
        """Returns a list of roomids that the user has any of the given
        membership states in."""

        rooms = yield self.store.get_rooms_for_user(
            user.to_string(),
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

    @defer.inlineCallbacks
    def do_3pid_invite(
            self,
            room_id,
            inviter,
            medium,
            address,
            id_server,
            token_id,
            txn_id
    ):
        invitee = yield self._lookup_3pid(
            id_server, medium, address
        )

        if invitee:
            # make sure it looks like a user ID; it'll throw if it's invalid.
            UserID.from_string(invitee)
            yield self.hs.get_handlers().message_handler.create_and_send_event(
                {
                    "type": EventTypes.Member,
                    "content": {
                        "membership": unicode("invite")
                    },
                    "room_id": room_id,
                    "sender": inviter.to_string(),
                    "state_key": invitee,
                },
                token_id=token_id,
                txn_id=txn_id,
            )
        else:
            yield self._make_and_store_3pid_invite(
                id_server,
                medium,
                address,
                room_id,
                inviter,
                token_id,
                txn_id=txn_id
            )

    @defer.inlineCallbacks
    def _lookup_3pid(self, id_server, medium, address):
        """Looks up a 3pid in the passed identity server.

        Args:
            id_server (str): The server name (including port, if required)
                of the identity server to use.
            medium (str): The type of the third party identifier (e.g. "email").
            address (str): The third party identifier (e.g. "foo@example.com").

        Returns:
            (str) the matrix ID of the 3pid, or None if it is not recognized.
        """
        try:
            data = yield self.hs.get_simple_http_client().get_json(
                "%s%s/_matrix/identity/api/v1/lookup" % (id_server_scheme, id_server,),
                {
                    "medium": medium,
                    "address": address,
                }
            )

            if "mxid" in data:
                if "signatures" not in data:
                    raise AuthError(401, "No signatures on 3pid binding")
                self.verify_any_signature(data, id_server)
                defer.returnValue(data["mxid"])

        except IOError as e:
            logger.warn("Error from identity server lookup: %s" % (e,))
            defer.returnValue(None)

    @defer.inlineCallbacks
    def verify_any_signature(self, data, server_hostname):
        if server_hostname not in data["signatures"]:
            raise AuthError(401, "No signature from server %s" % (server_hostname,))
        for key_name, signature in data["signatures"][server_hostname].items():
            key_data = yield self.hs.get_simple_http_client().get_json(
                "%s%s/_matrix/identity/api/v1/pubkey/%s" %
                (id_server_scheme, server_hostname, key_name,),
            )
            if "public_key" not in key_data:
                raise AuthError(401, "No public key named %s from %s" %
                                (key_name, server_hostname,))
            verify_signed_json(
                data,
                server_hostname,
                decode_verify_key_bytes(key_name, decode_base64(key_data["public_key"]))
            )
            return

    @defer.inlineCallbacks
    def _make_and_store_3pid_invite(
            self,
            id_server,
            medium,
            address,
            room_id,
            user,
            token_id,
            txn_id
    ):
        room_state = yield self.hs.get_state_handler().get_current_state(room_id)

        inviter_display_name = ""
        inviter_avatar_url = ""
        member_event = room_state.get((EventTypes.Member, user.to_string()))
        if member_event:
            inviter_display_name = member_event.content.get("displayname", "")
            inviter_avatar_url = member_event.content.get("avatar_url", "")

        canonical_room_alias = ""
        canonical_alias_event = room_state.get((EventTypes.CanonicalAlias, ""))
        if canonical_alias_event:
            canonical_room_alias = canonical_alias_event.content.get("alias", "")

        room_name = ""
        room_name_event = room_state.get((EventTypes.Name, ""))
        if room_name_event:
            room_name = room_name_event.content.get("name", "")

        room_join_rules = ""
        join_rules_event = room_state.get((EventTypes.JoinRules, ""))
        if join_rules_event:
            room_join_rules = join_rules_event.content.get("join_rule", "")

        room_avatar_url = ""
        room_avatar_event = room_state.get((EventTypes.RoomAvatar, ""))
        if room_avatar_event:
            room_avatar_url = room_avatar_event.content.get("url", "")

        token, public_key, key_validity_url, display_name = (
            yield self._ask_id_server_for_third_party_invite(
                id_server=id_server,
                medium=medium,
                address=address,
                room_id=room_id,
                inviter_user_id=user.to_string(),
                room_alias=canonical_room_alias,
                room_avatar_url=room_avatar_url,
                room_join_rules=room_join_rules,
                room_name=room_name,
                inviter_display_name=inviter_display_name,
                inviter_avatar_url=inviter_avatar_url
            )
        )
        msg_handler = self.hs.get_handlers().message_handler
        yield msg_handler.create_and_send_event(
            {
                "type": EventTypes.ThirdPartyInvite,
                "content": {
                    "display_name": display_name,
                    "key_validity_url": key_validity_url,
                    "public_key": public_key,
                },
                "room_id": room_id,
                "sender": user.to_string(),
                "state_key": token,
            },
            token_id=token_id,
            txn_id=txn_id,
        )

    @defer.inlineCallbacks
    def _ask_id_server_for_third_party_invite(
            self,
            id_server,
            medium,
            address,
            room_id,
            inviter_user_id,
            room_alias,
            room_avatar_url,
            room_join_rules,
            room_name,
            inviter_display_name,
            inviter_avatar_url
    ):
        is_url = "%s%s/_matrix/identity/api/v1/store-invite" % (
            id_server_scheme, id_server,
        )
        data = yield self.hs.get_simple_http_client().post_urlencoded_get_json(
            is_url,
            {
                "medium": medium,
                "address": address,
                "room_id": room_id,
                "room_alias": room_alias,
                "room_avatar_url": room_avatar_url,
                "room_join_rules": room_join_rules,
                "room_name": room_name,
                "sender": inviter_user_id,
                "sender_display_name": inviter_display_name,
                "sender_avatar_url": inviter_avatar_url,
            }
        )
        # TODO: Check for success
        token = data["token"]
        public_key = data["public_key"]
        display_name = data["display_name"]
        key_validity_url = "%s%s/_matrix/identity/api/v1/pubkey/isvalid" % (
            id_server_scheme, id_server,
        )
        defer.returnValue((token, public_key, key_validity_url, display_name))

    def forget(self, user, room_id):
        return self.store.forget(user.to_string(), room_id)


class RoomListHandler(BaseHandler):

    @defer.inlineCallbacks
    def get_public_room_list(self):
        chunk = yield self.store.get_rooms(is_public=True)

        room_members = yield defer.gatherResults(
            [
                self.store.get_users_in_room(room["room_id"])
                for room in chunk
            ],
            consumeErrors=True,
        ).addErrback(unwrapFirstError)

        avatar_urls = yield defer.gatherResults(
            [
                self.get_room_avatar_url(room["room_id"])
                for room in chunk
            ],
            consumeErrors=True,
        ).addErrback(unwrapFirstError)

        for i, room in enumerate(chunk):
            room["num_joined_members"] = len(room_members[i])
            if avatar_urls[i]:
                room["avatar_url"] = avatar_urls[i]

        # FIXME (erikj): START is no longer a valid value
        defer.returnValue({"start": "START", "end": "END", "chunk": chunk})

    @defer.inlineCallbacks
    def get_room_avatar_url(self, room_id):
        event = yield self.hs.get_state_handler().get_current_state(
            room_id, "m.room.avatar"
        )
        if event and "url" in event.content:
            defer.returnValue(event.content["url"])


class RoomContextHandler(BaseHandler):
    @defer.inlineCallbacks
    def get_event_context(self, user, room_id, event_id, limit, is_guest):
        """Retrieves events, pagination tokens and state around a given event
        in a room.

        Args:
            user (UserID)
            room_id (str)
            event_id (str)
            limit (int): The maximum number of events to return in total
                (excluding state).

        Returns:
            dict
        """
        before_limit = math.floor(limit/2.)
        after_limit = limit - before_limit

        now_token = yield self.hs.get_event_sources().get_current_token()

        results = yield self.store.get_events_around(
            room_id, event_id, before_limit, after_limit
        )

        results["events_before"] = yield self._filter_events_for_client(
            user.to_string(),
            results["events_before"],
            is_guest=is_guest,
            require_all_visible_for_guests=False
        )

        results["events_after"] = yield self._filter_events_for_client(
            user.to_string(),
            results["events_after"],
            is_guest=is_guest,
            require_all_visible_for_guests=False
        )

        if results["events_after"]:
            last_event_id = results["events_after"][-1].event_id
        else:
            last_event_id = event_id

        state = yield self.store.get_state_for_events(
            [last_event_id], None
        )
        results["state"] = state[last_event_id].values()

        results["start"] = now_token.copy_and_replace(
            "room_key", results["start"]
        ).to_string()

        results["end"] = now_token.copy_and_replace(
            "room_key", results["end"]
        ).to_string()

        defer.returnValue(results)


class RoomEventSource(object):
    def __init__(self, hs):
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def get_new_events(
            self,
            user,
            from_key,
            limit,
            room_ids,
            is_guest,
    ):
        # We just ignore the key for now.

        to_key = yield self.get_current_key()

        app_service = yield self.store.get_app_service_by_user_id(
            user.to_string()
        )
        if app_service:
            events, end_key = yield self.store.get_appservice_room_stream(
                service=app_service,
                from_key=from_key,
                to_key=to_key,
                limit=limit,
            )
        else:
            events, end_key = yield self.store.get_room_events_stream(
                user_id=user.to_string(),
                from_key=from_key,
                to_key=to_key,
                limit=limit,
                room_ids=room_ids,
                is_guest=is_guest,
            )

        defer.returnValue((events, end_key))

    def get_current_key(self, direction='f'):
        return self.store.get_room_events_max_id(direction)

    @defer.inlineCallbacks
    def get_pagination_rows(self, user, config, key):
        events, next_key = yield self.store.paginate_room_events(
            room_id=key,
            from_key=config.from_key,
            to_key=config.to_key,
            direction=config.direction,
            limit=config.limit,
        )

        defer.returnValue((events, next_key))
