# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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

import abc
import logging
from typing import Dict, Iterable, List, Optional, Tuple

from six.moves import http_client

from synapse import types
from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import AuthError, Codes, SynapseError
from synapse.events import EventBase
from synapse.events.snapshot import EventContext
from synapse.replication.http.membership import (
    ReplicationLocallyRejectInviteRestServlet,
)
from synapse.types import Collection, Requester, RoomAlias, RoomID, UserID
from synapse.util.async_helpers import Linearizer
from synapse.util.distributor import user_joined_room, user_left_room

from ._base import BaseHandler

logger = logging.getLogger(__name__)


class RoomMemberHandler(object):
    # TODO(paul): This handler currently contains a messy conflation of
    #   low-level API that works on UserID objects and so on, and REST-level
    #   API that takes ID strings and returns pagination chunks. These concerns
    #   ought to be separated out a lot better.

    __metaclass__ = abc.ABCMeta

    def __init__(self, hs):
        self.hs = hs
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()
        self.state_handler = hs.get_state_handler()
        self.config = hs.config

        self.federation_handler = hs.get_handlers().federation_handler
        self.directory_handler = hs.get_handlers().directory_handler
        self.identity_handler = hs.get_handlers().identity_handler
        self.registration_handler = hs.get_registration_handler()
        self.profile_handler = hs.get_profile_handler()
        self.event_creation_handler = hs.get_event_creation_handler()

        self.member_linearizer = Linearizer(name="member")

        self.clock = hs.get_clock()
        self.spam_checker = hs.get_spam_checker()
        self.third_party_event_rules = hs.get_third_party_event_rules()
        self._server_notices_mxid = self.config.server_notices_mxid
        self._enable_lookup = hs.config.enable_3pid_lookup
        self.allow_per_room_profiles = self.config.allow_per_room_profiles

        self._event_stream_writer_instance = hs.config.worker.writers.events
        self._is_on_event_persistence_instance = (
            self._event_stream_writer_instance == hs.get_instance_name()
        )
        if self._is_on_event_persistence_instance:
            self.persist_event_storage = hs.get_storage().persistence
        else:
            self._locally_reject_client = ReplicationLocallyRejectInviteRestServlet.make_client(
                hs
            )

        # This is only used to get at ratelimit function, and
        # maybe_kick_guest_users. It's fine there are multiple of these as
        # it doesn't store state.
        self.base_handler = BaseHandler(hs)

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
            requester
            remote_room_hosts: List of servers that can be used to join via.
            room_id: Room that we are trying to join
            user: User who is trying to join
            content: A dict that should be used as the content of the join event.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    async def _remote_reject_invite(
        self,
        requester: Requester,
        remote_room_hosts: List[str],
        room_id: str,
        target: UserID,
        content: dict,
    ) -> Tuple[Optional[str], int]:
        """Attempt to reject an invite for a room this server is not in. If we
        fail to do so we locally mark the invite as rejected.

        Args:
            requester
            remote_room_hosts: List of servers to use to try and reject invite
            room_id
            target: The user rejecting the invite
            content: The content for the rejection event

        Returns:
            A dictionary to be returned to the client, may
            include event_id etc, or nothing if we locally rejected
        """
        raise NotImplementedError()

    async def locally_reject_invite(self, user_id: str, room_id: str) -> int:
        """Mark the invite has having been rejected even though we failed to
        create a leave event for it.
        """
        if self._is_on_event_persistence_instance:
            return await self.persist_event_storage.locally_reject_invite(
                user_id, room_id
            )
        else:
            result = await self._locally_reject_client(
                instance_name=self._event_stream_writer_instance,
                user_id=user_id,
                room_id=room_id,
            )
            return result["stream_id"]

    @abc.abstractmethod
    async def _user_joined_room(self, target: UserID, room_id: str) -> None:
        """Notifies distributor on master process that the user has joined the
        room.

        Args:
            target
            room_id
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

    async def _local_membership_update(
        self,
        requester: Requester,
        target: UserID,
        room_id: str,
        membership: str,
        prev_event_ids: Collection[str],
        txn_id: Optional[str] = None,
        ratelimit: bool = True,
        content: Optional[dict] = None,
        require_consent: bool = True,
    ) -> Tuple[str, int]:
        user_id = target.to_string()

        if content is None:
            content = {}

        content["membership"] = membership
        if requester.is_guest:
            content["kind"] = "guest"

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
            },
            token_id=requester.access_token_id,
            txn_id=txn_id,
            prev_event_ids=prev_event_ids,
            require_consent=require_consent,
        )

        # Check if this event matches the previous membership event for the user.
        duplicate = await self.event_creation_handler.deduplicate_state_event(
            event, context
        )
        if duplicate is not None:
            # Discard the new event since this membership change is a no-op.
            _, stream_id = await self.store.get_event_ordering(duplicate.event_id)
            return duplicate.event_id, stream_id

        stream_id = await self.event_creation_handler.handle_new_client_event(
            requester, event, context, extra_users=[target], ratelimit=ratelimit
        )

        prev_state_ids = await context.get_prev_state_ids()

        prev_member_event_id = prev_state_ids.get((EventTypes.Member, user_id), None)

        if event.membership == Membership.JOIN:
            # Only fire user_joined_room if the user has actually joined the
            # room. Don't bother if the user is just changing their profile
            # info.
            newly_joined = True
            if prev_member_event_id:
                prev_member_event = await self.store.get_event(prev_member_event_id)
                newly_joined = prev_member_event.membership != Membership.JOIN
            if newly_joined:
                await self._user_joined_room(target, room_id)
        elif event.membership == Membership.LEAVE:
            if prev_member_event_id:
                prev_member_event = await self.store.get_event(prev_member_event_id)
                if prev_member_event.membership == Membership.JOIN:
                    await self._user_left_room(target, room_id)

        return event.event_id, stream_id

    async def copy_room_tags_and_direct_to_room(
        self, old_room_id, new_room_id, user_id
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
        direct_rooms = user_account_data.get("m.direct", {})

        # Check which key this room is under
        if isinstance(direct_rooms, dict):
            for key, room_id_list in direct_rooms.items():
                if old_room_id in room_id_list and new_room_id not in room_id_list:
                    # Add new room_id to this key
                    direct_rooms[key].append(new_room_id)

                    # Save back to user's m.direct account data
                    await self.store.add_account_data_for_user(
                        user_id, "m.direct", direct_rooms
                    )
                    break

        # Copy room tags if applicable
        room_tags = await self.store.get_tags_for_room(user_id, old_room_id)

        # Copy each room tag to the new room
        for tag, tag_content in room_tags.items():
            await self.store.add_tag_to_room(user_id, new_room_id, tag, tag_content)

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
        require_consent: bool = True,
    ) -> Tuple[Optional[str], int]:
        key = (room_id,)

        with (await self.member_linearizer.queue(key)):
            result = await self._update_membership(
                requester,
                target,
                room_id,
                action,
                txn_id=txn_id,
                remote_room_hosts=remote_room_hosts,
                third_party_signed=third_party_signed,
                ratelimit=ratelimit,
                content=content,
                require_consent=require_consent,
            )

        return result

    async def _update_membership(
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
        require_consent: bool = True,
    ) -> Tuple[Optional[str], int]:
        content_specified = bool(content)
        if content is None:
            content = {}
        else:
            # We do a copy here as we potentially change some keys
            # later on.
            content = dict(content)

        if not self.allow_per_room_profiles:
            # Strip profile data, knowing that new profile data will be added to the
            # event's content in event_creation_handler.create_event() using the target's
            # global profile.
            content.pop("displayname", None)
            content.pop("avatar_url", None)

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
            # block any attempts to invite the server notices mxid
            if target.to_string() == self._server_notices_mxid:
                raise SynapseError(http_client.FORBIDDEN, "Cannot invite this user")

            block_invite = False

            if (
                self._server_notices_mxid is not None
                and requester.user.to_string() == self._server_notices_mxid
            ):
                # allow the server notices mxid to send invites
                is_requester_admin = True

            else:
                is_requester_admin = await self.auth.is_server_admin(requester.user)

            if not is_requester_admin:
                if self.config.block_non_admin_invites:
                    logger.info(
                        "Blocking invite: user is not admin and non-admin "
                        "invites disabled"
                    )
                    block_invite = True

                if not self.spam_checker.user_may_invite(
                    requester.user.to_string(), target.to_string(), room_id
                ):
                    logger.info("Blocking invite due to spam checker")
                    block_invite = True

            if block_invite:
                raise SynapseError(403, "Invites have been disabled on this server")

        latest_event_ids = await self.store.get_prev_events_for_room(room_id)

        current_state_ids = await self.state_handler.get_current_state_ids(
            room_id, latest_event_ids=latest_event_ids
        )

        # TODO: Refactor into dictionary of explicitly allowed transitions
        # between old and new state, with specific error messages for some
        # transitions and generic otherwise
        old_state_id = current_state_ids.get((EventTypes.Member, target.to_string()))
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
            if old_membership == "ban" and action != "unban":
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
                    _, stream_id = await self.store.get_event_ordering(
                        old_state.event_id
                    )
                    return (
                        old_state.event_id,
                        stream_id,
                    )

            if old_membership in ["ban", "leave"] and action == "kick":
                raise AuthError(403, "The target user is not in the room")

            # we don't allow people to reject invites to the server notice
            # room, but they can leave it once they are joined.
            if (
                old_membership == Membership.INVITE
                and effective_membership_state == Membership.LEAVE
            ):
                is_blocked = await self._is_server_notice_room(room_id)
                if is_blocked:
                    raise SynapseError(
                        http_client.FORBIDDEN,
                        "You cannot reject this invite",
                        errcode=Codes.CANNOT_LEAVE_SERVER_NOTICE_ROOM,
                    )
        else:
            if action == "kick":
                raise AuthError(403, "The target user is not in the room")

        is_host_in_room = await self._is_host_in_room(current_state_ids)

        if effective_membership_state == Membership.JOIN:
            if requester.is_guest:
                guest_can_join = await self._can_guest_join(current_state_ids)
                if not guest_can_join:
                    # This should be an auth check, but guests are a local concept,
                    # so don't really fit into the general auth process.
                    raise AuthError(403, "Guest access not allowed")

            if not is_host_in_room:
                inviter = await self._get_inviter(target.to_string(), room_id)
                if inviter and not self.hs.is_mine(inviter):
                    remote_room_hosts.append(inviter.domain)

                content["membership"] = Membership.JOIN

                profile = self.profile_handler
                if not content_specified:
                    content["displayname"] = await profile.get_displayname(target)
                    content["avatar_url"] = await profile.get_avatar_url(target)

                if requester.is_guest:
                    content["kind"] = "guest"

                remote_join_response = await self._remote_join(
                    requester, remote_room_hosts, room_id, target, content
                )

                return remote_join_response

        elif effective_membership_state == Membership.LEAVE:
            if not is_host_in_room:
                # perhaps we've been invited
                inviter = await self._get_inviter(target.to_string(), room_id)
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
                    return await self._remote_reject_invite(
                        requester, remote_room_hosts, room_id, target, content,
                    )

        return await self._local_membership_update(
            requester=requester,
            target=target,
            room_id=room_id,
            membership=effective_membership_state,
            txn_id=txn_id,
            ratelimit=ratelimit,
            prev_event_ids=latest_event_ids,
            content=content,
            require_consent=require_consent,
        )

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
        users = await self.store.get_users_in_room(old_room_id)
        await self.copy_user_state_on_room_upgrade(old_room_id, room_id, users)

        # Add new room to the room directory if the old room was there
        # Remove old room from the room directory
        old_room = await self.store.get_room(old_room_id)
        if old_room and old_room["is_public"]:
            await self.store.set_room_is_public(old_room_id, False)
            await self.store.set_room_is_public(room_id, True)

        # Transfer alias mappings in the room directory
        await self.store.update_aliases_for_room(old_room_id, room_id)

        # Check if any groups we own contain the predecessor room
        local_group_ids = await self.store.get_local_groups_for_room(old_room_id)
        for group_id in local_group_ids:
            # Add new the new room to those groups
            await self.store.add_room_to_group(group_id, room_id, old_room["is_public"])

            # Remove the old room from those groups
            await self.store.remove_room_from_group(group_id, old_room_id)

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
        requester: Requester,
        event: EventBase,
        context: EventContext,
        ratelimit: bool = True,
    ):
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

        prev_event = await self.event_creation_handler.deduplicate_state_event(
            event, context
        )
        if prev_event is not None:
            return

        prev_state_ids = await context.get_prev_state_ids()
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

        await self.event_creation_handler.handle_new_client_event(
            requester, event, context, extra_users=[target_user], ratelimit=ratelimit
        )

        prev_member_event_id = prev_state_ids.get(
            (EventTypes.Member, event.state_key), None
        )

        if event.membership == Membership.JOIN:
            # Only fire user_joined_room if the user has actually joined the
            # room. Don't bother if the user is just changing their profile
            # info.
            newly_joined = True
            if prev_member_event_id:
                prev_member_event = await self.store.get_event(prev_member_event_id)
                newly_joined = prev_member_event.membership != Membership.JOIN
            if newly_joined:
                await self._user_joined_room(target_user, room_id)
        elif event.membership == Membership.LEAVE:
            if prev_member_event_id:
                prev_member_event = await self.store.get_event(prev_member_event_id)
                if prev_member_event.membership == Membership.JOIN:
                    await self._user_left_room(target_user, room_id)

    async def _can_guest_join(
        self, current_state_ids: Dict[Tuple[str, str], str]
    ) -> bool:
        """
        Returns whether a guest can join a room based on its current state.
        """
        guest_access_id = current_state_ids.get((EventTypes.GuestAccess, ""), None)
        if not guest_access_id:
            return False

        guest_access = await self.store.get_event(guest_access_id)

        return (
            guest_access
            and guest_access.content
            and "guest_access" in guest_access.content
            and guest_access.content["guest_access"] == "can_join"
        )

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
        id_access_token: Optional[str] = None,
    ) -> int:
        if self.config.block_non_admin_invites:
            is_requester_admin = await self.auth.is_server_admin(requester.user)
            if not is_requester_admin:
                raise SynapseError(
                    403, "Invites have been disabled on this server", Codes.FORBIDDEN
                )

        # We need to rate limit *before* we send out any 3PID invites, so we
        # can't just rely on the standard ratelimiting of events.
        await self.base_handler.ratelimit(requester)

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
            _, stream_id = await self.update_membership(
                requester, UserID.from_string(invitee), room_id, "invite", txn_id=txn_id
            )
        else:
            stream_id = await self._make_and_store_3pid_invite(
                requester,
                id_server,
                medium,
                address,
                room_id,
                inviter,
                txn_id=txn_id,
                id_access_token=id_access_token,
            )

        return stream_id

    async def _make_and_store_3pid_invite(
        self,
        requester: Requester,
        id_server: str,
        medium: str,
        address: str,
        room_id: str,
        user: UserID,
        txn_id: Optional[str],
        id_access_token: Optional[str] = None,
    ) -> int:
        room_state = await self.state_handler.get_current_state(room_id)

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
        )
        return stream_id

    async def _is_host_in_room(
        self, current_state_ids: Dict[Tuple[str, str], str]
    ) -> bool:
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

    async def _is_server_notice_room(self, room_id: str) -> bool:
        if self._server_notices_mxid is None:
            return False
        user_ids = await self.store.get_users_in_room(room_id)
        return self._server_notices_mxid in user_ids


class RoomMemberMasterHandler(RoomMemberHandler):
    def __init__(self, hs):
        super(RoomMemberMasterHandler, self).__init__(hs)

        self.distributor = hs.get_distributor()
        self.distributor.declare("user_joined_room")
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
        max_complexity = self.hs.config.limit_remote_rooms.complexity
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
        max_complexity = self.hs.config.limit_remote_rooms.complexity
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
        """Implements RoomMemberHandler._remote_join
        """
        # filter ourselves out of remote_room_hosts: do_invite_join ignores it
        # and if it is the only entry we'd like to return a 404 rather than a
        # 500.
        remote_room_hosts = [
            host for host in remote_room_hosts if host != self.hs.hostname
        ]

        if len(remote_room_hosts) == 0:
            raise SynapseError(404, "No known servers")

        if self.hs.config.limit_remote_rooms.enabled:
            # Fetch the room complexity
            too_complex = await self._is_remote_room_too_complex(
                room_id, remote_room_hosts
            )
            if too_complex is True:
                raise SynapseError(
                    code=400,
                    msg=self.hs.config.limit_remote_rooms.complexity_error,
                    errcode=Codes.RESOURCE_LIMIT_EXCEEDED,
                )

        # We don't do an auth check if we are doing an invite
        # join dance for now, since we're kinda implicitly checking
        # that we are allowed to join when we decide whether or not we
        # need to do the invite/join dance.
        event_id, stream_id = await self.federation_handler.do_invite_join(
            remote_room_hosts, room_id, user.to_string(), content
        )
        await self._user_joined_room(user, room_id)

        # Check the room we just joined wasn't too large, if we didn't fetch the
        # complexity of it before.
        if self.hs.config.limit_remote_rooms.enabled:
            if too_complex is False:
                # We checked, and we're under the limit.
                return event_id, stream_id

            # Check again, but with the local state events
            too_complex = await self._is_local_room_too_complex(room_id)

            if too_complex is False:
                # We're under the limit.
                return event_id, stream_id

            # The room is too large. Leave.
            requester = types.create_requester(user, None, False, None)
            await self.update_membership(
                requester=requester, target=user, room_id=room_id, action="leave"
            )
            raise SynapseError(
                code=400,
                msg=self.hs.config.limit_remote_rooms.complexity_error,
                errcode=Codes.RESOURCE_LIMIT_EXCEEDED,
            )

        return event_id, stream_id

    async def _remote_reject_invite(
        self,
        requester: Requester,
        remote_room_hosts: List[str],
        room_id: str,
        target: UserID,
        content: dict,
    ) -> Tuple[Optional[str], int]:
        """Implements RoomMemberHandler._remote_reject_invite
        """
        fed_handler = self.federation_handler
        try:
            event, stream_id = await fed_handler.do_remotely_reject_invite(
                remote_room_hosts, room_id, target.to_string(), content=content,
            )
            return event.event_id, stream_id
        except Exception as e:
            # if we were unable to reject the exception, just mark
            # it as rejected on our end and plough ahead.
            #
            # The 'except' clause is very broad, but we need to
            # capture everything from DNS failures upwards
            #
            logger.warning("Failed to reject invite: %s", e)

            stream_id = await self.locally_reject_invite(target.to_string(), room_id)
            return None, stream_id

    async def _user_joined_room(self, target: UserID, room_id: str) -> None:
        """Implements RoomMemberHandler._user_joined_room
        """
        user_joined_room(self.distributor, target, room_id)

    async def _user_left_room(self, target: UserID, room_id: str) -> None:
        """Implements RoomMemberHandler._user_left_room
        """
        user_left_room(self.distributor, target, room_id)

    async def forget(self, user: UserID, room_id: str) -> None:
        user_id = user.to_string()

        member = await self.state_handler.get_current_state(
            room_id=room_id, event_type=EventTypes.Member, state_key=user_id
        )
        membership = member.membership if member else None

        if membership is not None and membership not in [
            Membership.LEAVE,
            Membership.BAN,
        ]:
            raise SynapseError(400, "User %s in room %s" % (user_id, room_id))

        if membership:
            await self.store.forget(user_id, room_id)
