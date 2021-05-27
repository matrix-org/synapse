# Copyright 2017, 2018 New Vector Ltd
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
from typing import TYPE_CHECKING, Optional

from synapse.api.errors import SynapseError
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.types import Requester, UserID, create_requester

from ._base import BaseHandler

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class DeactivateAccountHandler(BaseHandler):
    """Handler which deals with deactivating user accounts."""

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.hs = hs
        self._auth_handler = hs.get_auth_handler()
        self._device_handler = hs.get_device_handler()
        self._room_member_handler = hs.get_room_member_handler()
        self._identity_handler = hs.get_identity_handler()
        self._profile_handler = hs.get_profile_handler()
        self.user_directory_handler = hs.get_user_directory_handler()
        self._server_name = hs.hostname

        # Flag that indicates whether the process to part users from rooms is running
        self._user_parter_running = False

        # Start the user parter loop so it can resume parting users from rooms where
        # it left off (if it has work left to do).
        if hs.config.run_background_tasks:
            hs.get_reactor().callWhenRunning(self._start_user_parting)

        self._account_validity_enabled = (
            hs.config.account_validity.account_validity_enabled
        )

    async def deactivate_account(
        self,
        user_id: str,
        erase_data: bool,
        requester: Requester,
        id_server: Optional[str] = None,
        by_admin: bool = False,
    ) -> bool:
        """Deactivate a user's account

        Args:
            user_id: ID of user to be deactivated
            erase_data: whether to GDPR-erase the user's data
            requester: The user attempting to make this change.
            id_server: Use the given identity server when unbinding
                any threepids. If None then will attempt to unbind using the
                identity server specified when binding (if known).
            by_admin: Whether this change was made by an administrator.

        Returns:
            True if identity server supports removing threepids, otherwise False.
        """
        # FIXME: Theoretically there is a race here wherein user resets
        # password using threepid.

        # delete threepids first. We remove these from the IS so if this fails,
        # leave the user still active so they can try again.
        # Ideally we would prevent password resets and then do this in the
        # background thread.

        # This will be set to false if the identity server doesn't support
        # unbinding
        identity_server_supports_unbinding = True

        # Retrieve the 3PIDs this user has bound to an identity server
        threepids = await self.store.user_get_bound_threepids(user_id)

        for threepid in threepids:
            try:
                result = await self._identity_handler.try_unbind_threepid(
                    user_id,
                    {
                        "medium": threepid["medium"],
                        "address": threepid["address"],
                        "id_server": id_server,
                    },
                )
                identity_server_supports_unbinding &= result
            except Exception:
                # Do we want this to be a fatal error or should we carry on?
                logger.exception("Failed to remove threepid from ID server")
                raise SynapseError(400, "Failed to remove threepid from ID server")
            await self.store.user_delete_threepid(
                user_id, threepid["medium"], threepid["address"]
            )

        # Remove all 3PIDs this user has bound to the homeserver
        await self.store.user_delete_threepids(user_id)

        # delete any devices belonging to the user, which will also
        # delete corresponding access tokens.
        await self._device_handler.delete_all_devices_for_user(user_id)
        # then delete any remaining access tokens which weren't associated with
        # a device.
        await self._auth_handler.delete_access_tokens_for_user(user_id)

        await self.store.user_set_password_hash(user_id, None)

        # Most of the pushers will have been deleted when we logged out the
        # associated devices above, but we still need to delete pushers not
        # associated with devices, e.g. email pushers.
        await self.store.delete_all_pushers_for_user(user_id)

        # Add the user to a table of users pending deactivation (ie.
        # removal from all the rooms they're a member of)
        await self.store.add_user_pending_deactivation(user_id)

        # delete from user directory
        await self.user_directory_handler.handle_user_deactivated(user_id)

        # Mark the user as erased, if they asked for that
        if erase_data:
            user = UserID.from_string(user_id)
            # Remove avatar URL from this user
            await self._profile_handler.set_avatar_url(user, requester, "", by_admin)
            # Remove displayname from this user
            await self._profile_handler.set_displayname(user, requester, "", by_admin)

            logger.info("Marking %s as erased", user_id)
            await self.store.mark_user_erased(user_id)

        # Now start the process that goes through that list and
        # parts users from rooms (if it isn't already running)
        self._start_user_parting()

        # Reject all pending invites for the user, so that the user doesn't show up in the
        # "invited" section of rooms' members list.
        await self._reject_pending_invites_for_user(user_id)

        # Remove all information on the user from the account_validity table.
        if self._account_validity_enabled:
            await self.store.delete_account_validity_for_user(user_id)

        # Mark the user as deactivated.
        await self.store.set_user_deactivated_status(user_id, True)

        return identity_server_supports_unbinding

    async def _reject_pending_invites_for_user(self, user_id: str) -> None:
        """Reject pending invites addressed to a given user ID.

        Args:
            user_id: The user ID to reject pending invites for.
        """
        user = UserID.from_string(user_id)
        pending_invites = await self.store.get_invited_rooms_for_local_user(user_id)

        for room in pending_invites:
            try:
                await self._room_member_handler.update_membership(
                    create_requester(user, authenticated_entity=self._server_name),
                    user,
                    room.room_id,
                    "leave",
                    ratelimit=False,
                    require_consent=False,
                )
                logger.info(
                    "Rejected invite for deactivated user %r in room %r",
                    user_id,
                    room.room_id,
                )
            except Exception:
                logger.exception(
                    "Failed to reject invite for user %r in room %r:"
                    " ignoring and continuing",
                    user_id,
                    room.room_id,
                )

    def _start_user_parting(self) -> None:
        """
        Start the process that goes through the table of users
        pending deactivation, if it isn't already running.
        """
        if not self._user_parter_running:
            run_as_background_process("user_parter_loop", self._user_parter_loop)

    async def _user_parter_loop(self) -> None:
        """Loop that parts deactivated users from rooms"""
        self._user_parter_running = True
        logger.info("Starting user parter")
        try:
            while True:
                user_id = await self.store.get_user_pending_deactivation()
                if user_id is None:
                    break
                logger.info("User parter parting %r", user_id)
                await self._part_user(user_id)
                await self.store.del_user_pending_deactivation(user_id)
                logger.info("User parter finished parting %r", user_id)
            logger.info("User parter finished: stopping")
        finally:
            self._user_parter_running = False

    async def _part_user(self, user_id: str) -> None:
        """Causes the given user_id to leave all the rooms they're joined to"""
        user = UserID.from_string(user_id)

        rooms_for_user = await self.store.get_rooms_for_user(user_id)
        for room_id in rooms_for_user:
            logger.info("User parter parting %r from %r", user_id, room_id)
            try:
                await self._room_member_handler.update_membership(
                    create_requester(user, authenticated_entity=self._server_name),
                    user,
                    room_id,
                    "leave",
                    ratelimit=False,
                    require_consent=False,
                )
            except Exception:
                logger.exception(
                    "Failed to part user %r from room %r: ignoring and continuing",
                    user_id,
                    room_id,
                )

    async def activate_account(self, user_id: str) -> None:
        """
        Activate an account that was previously deactivated.

        This marks the user as active and not erased in the database, but does
        not attempt to rejoin rooms, re-add threepids, etc.

        If enabled, the user will be re-added to the user directory.

        The user will also need a password hash set to actually login.

        Args:
            user_id: ID of user to be re-activated
        """
        # Add the user to the directory, if necessary.
        user = UserID.from_string(user_id)
        if self.hs.config.user_directory_search_all_users:
            profile = await self.store.get_profileinfo(user.localpart)
            await self.user_directory_handler.handle_local_profile_change(
                user_id, profile
            )

        # Ensure the user is not marked as erased.
        await self.store.mark_user_not_erased(user_id)

        # Mark the user as active.
        await self.store.set_user_deactivated_status(user_id, False)
