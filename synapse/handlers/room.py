# -*- coding: utf-8 -*-
# Copyright 2014 - 2016 OpenMarket Ltd
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

from synapse.types import UserID, RoomAlias, RoomID, RoomStreamToken, Requester
from synapse.api.constants import (
    EventTypes, Membership, JoinRules, RoomCreationPreset,
)
from synapse.api.errors import AuthError, StoreError, SynapseError, Codes
from synapse.util import stringutils, unwrapFirstError
from synapse.util.logcontext import preserve_context_over_fn

from signedjson.sign import verify_signed_json
from signedjson.key import decode_verify_key_bytes

from collections import OrderedDict
from unpaddedbase64 import decode_base64

import logging
import math
import string

logger = logging.getLogger(__name__)

id_server_scheme = "https://"


def user_left_room(distributor, user, room_id):
    return preserve_context_over_fn(
        distributor.fire,
        "user_left_room", user=user, room_id=room_id
    )


def user_joined_room(distributor, user, room_id):
    return preserve_context_over_fn(
        distributor.fire,
        "user_joined_room", user=user, room_id=room_id
    )


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
    def create_room(self, requester, config):
        """ Creates a new room.

        Args:
            requester (Requester): The user who requested the room creation.
            config (dict) : A dict of configuration options.
        Returns:
            The new room ID.
        Raises:
            SynapseError if the room ID couldn't be stored, or something went
            horribly wrong.
        """
        user_id = requester.user.to_string()

        self.ratelimit(requester)

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

        invite_3pid_list = config.get("invite_3pid", [])

        is_public = config.get("visibility", None) == "public"

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

        msg_handler = self.hs.get_handlers().message_handler
        room_member_handler = self.hs.get_handlers().room_member_handler

        yield self._send_events_for_new_room(
            requester,
            room_id,
            msg_handler,
            room_member_handler,
            preset_config=preset_config,
            invite_list=invite_list,
            initial_state=initial_state,
            creation_content=creation_content,
            room_alias=room_alias,
        )

        if "name" in config:
            name = config["name"]
            yield msg_handler.create_and_send_nonmember_event(
                requester,
                {
                    "type": EventTypes.Name,
                    "room_id": room_id,
                    "sender": user_id,
                    "state_key": "",
                    "content": {"name": name},
                },
                ratelimit=False)

        if "topic" in config:
            topic = config["topic"]
            yield msg_handler.create_and_send_nonmember_event(
                requester,
                {
                    "type": EventTypes.Topic,
                    "room_id": room_id,
                    "sender": user_id,
                    "state_key": "",
                    "content": {"topic": topic},
                },
                ratelimit=False)

        for invitee in invite_list:
            yield room_member_handler.update_membership(
                requester,
                UserID.from_string(invitee),
                room_id,
                "invite",
                ratelimit=False,
            )

        for invite_3pid in invite_3pid_list:
            id_server = invite_3pid["id_server"]
            address = invite_3pid["address"]
            medium = invite_3pid["medium"]
            yield self.hs.get_handlers().room_member_handler.do_3pid_invite(
                room_id,
                requester.user,
                medium,
                address,
                id_server,
                requester,
                txn_id=None,
            )

        result = {"room_id": room_id}

        if room_alias:
            result["room_alias"] = room_alias.to_string()
            yield directory_handler.send_room_alias_update_event(
                requester, user_id, room_id
            )

        defer.returnValue(result)

    @defer.inlineCallbacks
    def _send_events_for_new_room(
            self,
            creator,  # A Requester object.
            room_id,
            msg_handler,
            room_member_handler,
            preset_config,
            invite_list,
            initial_state,
            creation_content,
            room_alias
    ):
        def create(etype, content, **kwargs):
            e = {
                "type": etype,
                "content": content,
            }

            e.update(event_keys)
            e.update(kwargs)

            return e

        @defer.inlineCallbacks
        def send(etype, content, **kwargs):
            event = create(etype, content, **kwargs)
            yield msg_handler.create_and_send_nonmember_event(
                creator,
                event,
                ratelimit=False
            )

        config = RoomCreationHandler.PRESETS_DICT[preset_config]

        creator_id = creator.user.to_string()

        event_keys = {
            "room_id": room_id,
            "sender": creator_id,
            "state_key": "",
        }

        creation_content.update({"creator": creator_id})
        yield send(
            etype=EventTypes.Create,
            content=creation_content,
        )

        yield room_member_handler.update_membership(
            creator,
            creator.user,
            room_id,
            "join",
            ratelimit=False,
        )

        if (EventTypes.PowerLevels, '') not in initial_state:
            power_level_content = {
                "users": {
                    creator_id: 100,
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

            yield send(
                etype=EventTypes.PowerLevels,
                content=power_level_content,
            )

        if room_alias and (EventTypes.CanonicalAlias, '') not in initial_state:
            yield send(
                etype=EventTypes.CanonicalAlias,
                content={"alias": room_alias.to_string()},
            )

        if (EventTypes.JoinRules, '') not in initial_state:
            yield send(
                etype=EventTypes.JoinRules,
                content={"join_rule": config["join_rules"]},
            )

        if (EventTypes.RoomHistoryVisibility, '') not in initial_state:
            yield send(
                etype=EventTypes.RoomHistoryVisibility,
                content={"history_visibility": config["history_visibility"]}
            )

        for (etype, state_key), content in initial_state.items():
            yield send(
                etype=etype,
                state_key=state_key,
                content=content,
            )


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
    def update_membership(
            self,
            requester,
            target,
            room_id,
            action,
            txn_id=None,
            remote_room_hosts=None,
            third_party_signed=None,
            ratelimit=True,
    ):
        effective_membership_state = action
        if action in ["kick", "unban"]:
            effective_membership_state = "leave"
        elif action == "forget":
            effective_membership_state = "leave"

        if third_party_signed is not None:
            replication = self.hs.get_replication_layer()
            yield replication.exchange_third_party_invite(
                third_party_signed["sender"],
                target.to_string(),
                room_id,
                third_party_signed,
            )

        msg_handler = self.hs.get_handlers().message_handler

        content = {"membership": effective_membership_state}
        if requester.is_guest:
            content["kind"] = "guest"

        event, context = yield msg_handler.create_event(
            {
                "type": EventTypes.Member,
                "content": content,
                "room_id": room_id,
                "sender": requester.user.to_string(),
                "state_key": target.to_string(),

                # For backwards compatibility:
                "membership": effective_membership_state,
            },
            token_id=requester.access_token_id,
            txn_id=txn_id,
        )

        old_state = context.current_state.get((EventTypes.Member, event.state_key))
        old_membership = old_state.content.get("membership") if old_state else None
        if action == "unban" and old_membership != "ban":
            raise SynapseError(
                403,
                "Cannot unban user who was not banned (membership=%s)" % old_membership,
                errcode=Codes.BAD_STATE
            )
        if old_membership == "ban" and action != "unban":
            raise SynapseError(
                403,
                "Cannot %s user who was is banned" % (action,),
                errcode=Codes.BAD_STATE
            )

        member_handler = self.hs.get_handlers().room_member_handler
        yield member_handler.send_membership_event(
            requester,
            event,
            context,
            ratelimit=ratelimit,
            remote_room_hosts=remote_room_hosts,
        )

        if action == "forget":
            yield self.forget(requester.user, room_id)

    @defer.inlineCallbacks
    def send_membership_event(
            self,
            requester,
            event,
            context,
            remote_room_hosts=None,
            ratelimit=True,
    ):
        """
        Change the membership status of a user in a room.

        Args:
            requester (Requester): The local user who requested the membership
                event. If None, certain checks, like whether this homeserver can
                act as the sender, will be skipped.
            event (SynapseEvent): The membership event.
            context: The context of the event.
            is_guest (bool): Whether the sender is a guest.
            room_hosts ([str]): Homeservers which are likely to already be in
                the room, and could be danced with in order to join this
                homeserver for the first time.
            ratelimit (bool): Whether to rate limit this request.
        Raises:
            SynapseError if there was a problem changing the membership.
        """
        remote_room_hosts = remote_room_hosts or []

        target_user = UserID.from_string(event.state_key)
        room_id = event.room_id

        if requester is not None:
            sender = UserID.from_string(event.sender)
            assert sender == requester.user, (
                "Sender (%s) must be same as requester (%s)" %
                (sender, requester.user)
            )
            assert self.hs.is_mine(sender), "Sender must be our own: %s" % (sender,)
        else:
            requester = Requester(target_user, None, False)

        message_handler = self.hs.get_handlers().message_handler
        prev_event = message_handler.deduplicate_state_event(event, context)
        if prev_event is not None:
            return

        action = "send"

        if event.membership == Membership.JOIN:
            if requester.is_guest and not self._can_guest_join(context.current_state):
                # This should be an auth check, but guests are a local concept,
                # so don't really fit into the general auth process.
                raise AuthError(403, "Guest access not allowed")
            do_remote_join_dance, remote_room_hosts = self._should_do_dance(
                context,
                (self.get_inviter(event.state_key, context.current_state)),
                remote_room_hosts,
            )
            if do_remote_join_dance:
                action = "remote_join"
        elif event.membership == Membership.LEAVE:
            is_host_in_room = self.is_host_in_room(context.current_state)

            if not is_host_in_room:
                # perhaps we've been invited
                inviter = self.get_inviter(target_user.to_string(), context.current_state)
                if not inviter:
                    raise SynapseError(404, "Not a known room")

                if self.hs.is_mine(inviter):
                    # the inviter was on our server, but has now left. Carry on
                    # with the normal rejection codepath.
                    #
                    # This is a bit of a hack, because the room might still be
                    # active on other servers.
                    pass
                else:
                    # send the rejection to the inviter's HS.
                    remote_room_hosts = remote_room_hosts + [inviter.domain]
                    action = "remote_reject"

        federation_handler = self.hs.get_handlers().federation_handler

        if action == "remote_join":
            if len(remote_room_hosts) == 0:
                raise SynapseError(404, "No known servers")

            # We don't do an auth check if we are doing an invite
            # join dance for now, since we're kinda implicitly checking
            # that we are allowed to join when we decide whether or not we
            # need to do the invite/join dance.
            yield federation_handler.do_invite_join(
                remote_room_hosts,
                event.room_id,
                event.user_id,
                event.content,
            )
        elif action == "remote_reject":
            yield federation_handler.do_remotely_reject_invite(
                remote_room_hosts,
                room_id,
                event.user_id
            )
        else:
            yield self.handle_new_client_event(
                requester,
                event,
                context,
                extra_users=[target_user],
                ratelimit=ratelimit,
            )

        prev_member_event = context.current_state.get(
            (EventTypes.Member, target_user.to_string()),
            None
        )

        if event.membership == Membership.JOIN:
            if not prev_member_event or prev_member_event.membership != Membership.JOIN:
                # Only fire user_joined_room if the user has acutally joined the
                # room. Don't bother if the user is just changing their profile
                # info.
                yield user_joined_room(self.distributor, target_user, room_id)
        elif event.membership == Membership.LEAVE:
            if prev_member_event and prev_member_event.membership == Membership.JOIN:
                user_left_room(self.distributor, target_user, room_id)

    def _can_guest_join(self, current_state):
        """
        Returns whether a guest can join a room based on its current state.
        """
        guest_access = current_state.get((EventTypes.GuestAccess, ""), None)
        return (
            guest_access
            and guest_access.content
            and "guest_access" in guest_access.content
            and guest_access.content["guest_access"] == "can_join"
        )

    def _should_do_dance(self, context, inviter, room_hosts=None):
        # TODO: Shouldn't this be remote_room_host?
        room_hosts = room_hosts or []

        is_host_in_room = self.is_host_in_room(context.current_state)
        if is_host_in_room:
            return False, room_hosts

        if inviter and not self.hs.is_mine(inviter):
            room_hosts.append(inviter.domain)

        return True, room_hosts

    @defer.inlineCallbacks
    def lookup_room_alias(self, room_alias):
        """
        Get the room ID associated with a room alias.

        Args:
            room_alias (RoomAlias): The alias to look up.
        Returns:
            A tuple of:
                The room ID as a RoomID object.
                Hosts likely to be participating in the room ([str]).
        Raises:
            SynapseError if room alias could not be found.
        """
        directory_handler = self.hs.get_handlers().directory_handler
        mapping = yield directory_handler.get_association(room_alias)

        if not mapping:
            raise SynapseError(404, "No such room alias")

        room_id = mapping["room_id"]
        servers = mapping["servers"]

        defer.returnValue((RoomID.from_string(room_id), servers))

    def get_inviter(self, user_id, current_state):
        prev_state = current_state.get((EventTypes.Member, user_id))
        if prev_state and prev_state.membership == Membership.INVITE:
            return UserID.from_string(prev_state.user_id)
        return None

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
    def do_3pid_invite(
            self,
            room_id,
            inviter,
            medium,
            address,
            id_server,
            requester,
            txn_id
    ):
        invitee = yield self._lookup_3pid(
            id_server, medium, address
        )

        if invitee:
            handler = self.hs.get_handlers().room_member_handler
            yield handler.update_membership(
                requester,
                UserID.from_string(invitee),
                room_id,
                "invite",
                txn_id=txn_id,
            )
        else:
            yield self._make_and_store_3pid_invite(
                requester,
                id_server,
                medium,
                address,
                room_id,
                inviter,
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
            requester,
            id_server,
            medium,
            address,
            room_id,
            user,
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

        token, public_keys, fallback_public_key, display_name = (
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
        yield msg_handler.create_and_send_nonmember_event(
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
        """
        Asks an identity server for a third party invite.

        :param id_server (str): hostname + optional port for the identity server.
        :param medium (str): The literal string "email".
        :param address (str): The third party address being invited.
        :param room_id (str): The ID of the room to which the user is invited.
        :param inviter_user_id (str): The user ID of the inviter.
        :param room_alias (str): An alias for the room, for cosmetic
            notifications.
        :param room_avatar_url (str): The URL of the room's avatar, for cosmetic
            notifications.
        :param room_join_rules (str): The join rules of the email
            (e.g. "public").
        :param room_name (str): The m.room.name of the room.
        :param inviter_display_name (str): The current display name of the
            inviter.
        :param inviter_avatar_url (str): The URL of the inviter's avatar.

        :return: A deferred tuple containing:
            token (str): The token which must be signed to prove authenticity.
            public_keys ([{"public_key": str, "key_validity_url": str}]):
                public_key is a base64-encoded ed25519 public key.
            fallback_public_key: One element from public_keys.
            display_name (str): A user-friendly name to represent the invited
                user.
        """

        registration_handler = self.hs.get_handlers().registration_handler
        guest_access_token = yield registration_handler.guest_access_token_for(
            medium=medium,
            address=address,
            inviter_user_id=inviter_user_id,
        )

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
                "guest_access_token": guest_access_token,
            }
        )
        # TODO: Check for success
        token = data["token"]
        public_keys = data.get("public_keys", [])
        if "public_key" in data:
            fallback_public_key = {
                "public_key": data["public_key"],
                "key_validity_url": "%s%s/_matrix/identity/api/v1/pubkey/isvalid" % (
                    id_server_scheme, id_server,
                ),
            }
        else:
            fallback_public_key = public_keys[0]

        if not public_keys:
            public_keys.append(fallback_public_key)
        display_name = data["display_name"]
        defer.returnValue((token, public_keys, fallback_public_key, display_name))

    def forget(self, user, room_id):
        return self.store.forget(user.to_string(), room_id)


class RoomListHandler(BaseHandler):

    @defer.inlineCallbacks
    def get_public_room_list(self):
        room_ids = yield self.store.get_public_room_ids()

        @defer.inlineCallbacks
        def handle_room(room_id):
            aliases = yield self.store.get_aliases_for_room(room_id)
            if not aliases:
                defer.returnValue(None)

            state = yield self.state_handler.get_current_state(room_id)

            result = {"aliases": aliases, "room_id": room_id}

            name_event = state.get((EventTypes.Name, ""), None)
            if name_event:
                name = name_event.content.get("name", None)
                if name:
                    result["name"] = name

            topic_event = state.get((EventTypes.Topic, ""), None)
            if topic_event:
                topic = topic_event.content.get("topic", None)
                if topic:
                    result["topic"] = topic

            canonical_event = state.get((EventTypes.CanonicalAlias, ""), None)
            if canonical_event:
                canonical_alias = canonical_event.content.get("alias", None)
                if canonical_alias:
                    result["canonical_alias"] = canonical_alias

            visibility_event = state.get((EventTypes.RoomHistoryVisibility, ""), None)
            visibility = None
            if visibility_event:
                visibility = visibility_event.content.get("history_visibility", None)
            result["world_readable"] = visibility == "world_readable"

            guest_event = state.get((EventTypes.GuestAccess, ""), None)
            guest = None
            if guest_event:
                guest = guest_event.content.get("guest_access", None)
            result["guest_can_join"] = guest == "can_join"

            avatar_event = state.get(("m.room.avatar", ""), None)
            if avatar_event:
                avatar_url = avatar_event.content.get("url", None)
                if avatar_url:
                    result["avatar_url"] = avatar_url

            result["num_joined_members"] = sum(
                1 for (event_type, _), ev in state.items()
                if event_type == EventTypes.Member and ev.membership == Membership.JOIN
            )

            defer.returnValue(result)

        result = []
        for chunk in (room_ids[i:i + 10] for i in xrange(0, len(room_ids), 10)):
            chunk_result = yield defer.gatherResults([
                handle_room(room_id)
                for room_id in chunk
            ], consumeErrors=True).addErrback(unwrapFirstError)
            result.extend(v for v in chunk_result if v)

        # FIXME (erikj): START is no longer a valid value
        defer.returnValue({"start": "START", "end": "END", "chunk": result})


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
            dict, or None if the event isn't found
        """
        before_limit = math.floor(limit / 2.)
        after_limit = limit - before_limit

        now_token = yield self.hs.get_event_sources().get_current_token()

        def filter_evts(events):
            return self._filter_events_for_client(
                user.to_string(),
                events,
                is_peeking=is_guest)

        event = yield self.store.get_event(event_id, get_prev_content=True,
                                           allow_none=True)
        if not event:
            defer.returnValue(None)
            return

        filtered = yield(filter_evts([event]))
        if not filtered:
            raise AuthError(
                403,
                "You don't have permission to access that event."
            )

        results = yield self.store.get_events_around(
            room_id, event_id, before_limit, after_limit
        )

        results["events_before"] = yield filter_evts(results["events_before"])
        results["events_after"] = yield filter_evts(results["events_after"])
        results["event"] = event

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

        from_token = RoomStreamToken.parse(from_key)
        if from_token.topological:
            logger.warn("Stream has topological part!!!! %r", from_key)
            from_key = "s%s" % (from_token.stream,)

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
            room_events = yield self.store.get_membership_changes_for_user(
                user.to_string(), from_key, to_key
            )

            room_to_events = yield self.store.get_room_events_stream_for_rooms(
                room_ids=room_ids,
                from_key=from_key,
                to_key=to_key,
                limit=limit or 10,
                order='ASC',
            )

            events = list(room_events)
            events.extend(e for evs, _ in room_to_events.values() for e in evs)

            events.sort(key=lambda e: e.internal_metadata.order)

            if limit:
                events[:] = events[:limit]

            if events:
                end_key = events[-1].internal_metadata.after
            else:
                end_key = to_key

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
