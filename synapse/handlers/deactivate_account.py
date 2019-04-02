# -*- coding: utf-8 -*-
# Copyright 2017, 2018 New Vector Ltd
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

from twisted.internet import defer

from synapse.api.errors import SynapseError
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.types import UserID, create_requester

from ._base import BaseHandler

logger = logging.getLogger(__name__)


class DeactivateAccountHandler(BaseHandler):
    """Handler which deals with deactivating user accounts."""
    def __init__(self, hs):
        super(DeactivateAccountHandler, self).__init__(hs)
        self._auth_handler = hs.get_auth_handler()
        self._device_handler = hs.get_device_handler()
        self._room_member_handler = hs.get_room_member_handler()
        self._identity_handler = hs.get_handlers().identity_handler
        self.user_directory_handler = hs.get_user_directory_handler()

        # Flag that indicates whether the process to part users from rooms is running
        self._user_parter_running = False

        # Start the user parter loop so it can resume parting users from rooms where
        # it left off (if it has work left to do).
        hs.get_reactor().callWhenRunning(self._start_user_parting)

    @defer.inlineCallbacks
    def deactivate_account(self, user_id, erase_data, id_server=None):
        """Deactivate a user's account

        Args:
            user_id (str): ID of user to be deactivated
            erase_data (bool): whether to GDPR-erase the user's data
            id_server (str|None): Use the given identity server when unbinding
                any threepids. If None then will attempt to unbind using the
                identity server specified when binding (if known).

        Returns:
            Deferred[bool]: True if identity server supports removing
            threepids, otherwise False.
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

        threepids = yield self.store.user_get_threepids(user_id)
        for threepid in threepids:
            try:
                result = yield self._identity_handler.try_unbind_threepid(
                    user_id,
                    {
                        'medium': threepid['medium'],
                        'address': threepid['address'],
                        'id_server': id_server,
                    },
                )
                identity_server_supports_unbinding &= result
            except Exception:
                # Do we want this to be a fatal error or should we carry on?
                logger.exception("Failed to remove threepid from ID server")
                raise SynapseError(400, "Failed to remove threepid from ID server")
            yield self.store.user_delete_threepid(
                user_id, threepid['medium'], threepid['address'],
            )

        # delete any devices belonging to the user, which will also
        # delete corresponding access tokens.
        yield self._device_handler.delete_all_devices_for_user(user_id)
        # then delete any remaining access tokens which weren't associated with
        # a device.
        yield self._auth_handler.delete_access_tokens_for_user(user_id)

        yield self.store.user_set_password_hash(user_id, None)

        # Add the user to a table of users pending deactivation (ie.
        # removal from all the rooms they're a member of)
        yield self.store.add_user_pending_deactivation(user_id)

        # delete from user directory
        yield self.user_directory_handler.handle_user_deactivated(user_id)

        # Mark the user as erased, if they asked for that
        if erase_data:
            logger.info("Marking %s as erased", user_id)
            yield self.store.mark_user_erased(user_id)

        # Now start the process that goes through that list and
        # parts users from rooms (if it isn't already running)
        self._start_user_parting()

        defer.returnValue(identity_server_supports_unbinding)

    def _start_user_parting(self):
        """
        Start the process that goes through the table of users
        pending deactivation, if it isn't already running.

        Returns:
            None
        """
        if not self._user_parter_running:
            run_as_background_process("user_parter_loop", self._user_parter_loop)

    @defer.inlineCallbacks
    def _user_parter_loop(self):
        """Loop that parts deactivated users from rooms

        Returns:
            None
        """
        self._user_parter_running = True
        logger.info("Starting user parter")
        try:
            while True:
                user_id = yield self.store.get_user_pending_deactivation()
                if user_id is None:
                    break
                logger.info("User parter parting %r", user_id)
                yield self._part_user(user_id)
                yield self.store.del_user_pending_deactivation(user_id)
                logger.info("User parter finished parting %r", user_id)
            logger.info("User parter finished: stopping")
        finally:
            self._user_parter_running = False

    @defer.inlineCallbacks
    def _part_user(self, user_id):
        """Causes the given user_id to leave all the rooms they're joined to

        Returns:
            None
        """
        user = UserID.from_string(user_id)

        rooms_for_user = yield self.store.get_rooms_for_user(user_id)
        for room_id in rooms_for_user:
            logger.info("User parter parting %r from %r", user_id, room_id)
            try:
                yield self._room_member_handler.update_membership(
                    create_requester(user),
                    user,
                    room_id,
                    "leave",
                    ratelimit=False,
                    require_consent=False,
                )
            except Exception:
                logger.exception(
                    "Failed to part user %r from room %r: ignoring and continuing",
                    user_id, room_id,
                )
