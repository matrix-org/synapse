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
from twisted.internet import defer

from ._base import BaseHandler
from synapse.types import UserID, create_requester

import logging

logger = logging.getLogger(__name__)


class DeactivateAccountHandler(BaseHandler):
    """Handler which deals with deactivating user accounts."""
    def __init__(self, hs):
        super(DeactivateAccountHandler, self).__init__(hs)
        self._auth_handler = hs.get_auth_handler()
        self._device_handler = hs.get_device_handler()
        self._room_member_handler = hs.get_room_member_handler()

    @defer.inlineCallbacks
    def deactivate_account(self, user_id):
        """Deactivate a user's account

        Args:
            user_id (str): ID of user to be deactivated

        Returns:
            Deferred
        """
        # FIXME: Theoretically there is a race here wherein user resets
        # password using threepid.

        # first delete any devices belonging to the user, which will also
        # delete corresponding access tokens.
        yield self._device_handler.delete_all_devices_for_user(user_id)
        # then delete any remaining access tokens which weren't associated with
        # a device.
        yield self._auth_handler.delete_access_tokens_for_user(user_id)

        yield self.store.user_delete_threepids(user_id)
        yield self.store.user_set_password_hash(user_id, None)

        user = UserID.from_string(user_id)

        rooms_for_user = yield self.store.get_rooms_for_user(user_id)
        for room_id in rooms_for_user:
            yield self._room_member_handler.update_membership(
                create_requester(user),
                user,
                room_id,
                "leave",
                ratelimit=False,
            )
