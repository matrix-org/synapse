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

from twisted.internet import defer

from ._base import BaseHandler
from synapse.api.errors import LoginError, Codes

import bcrypt
import logging

logger = logging.getLogger(__name__)


class LoginHandler(BaseHandler):

    def __init__(self, hs):
        super(LoginHandler, self).__init__(hs)
        self.hs = hs

    @defer.inlineCallbacks
    def login(self, user, password):
        """Login as the specified user with the specified password.

        Args:
            user (str): The user ID.
            password (str): The password.
        Returns:
            The newly allocated access token.
        Raises:
            StoreError if there was a problem storing the token.
            LoginError if there was an authentication problem.
        """
        # TODO do this better, it can't go in __init__ else it cyclic loops
        if not hasattr(self, "reg_handler"):
            self.reg_handler = self.hs.get_handlers().registration_handler

        # pull out the hash for this user if they exist
        user_info = yield self.store.get_user_by_id(user_id=user)
        if not user_info:
            logger.warn("Attempted to login as %s but they do not exist", user)
            raise LoginError(403, "", errcode=Codes.FORBIDDEN)

        stored_hash = user_info[0]["password_hash"]
        if bcrypt.checkpw(password, stored_hash):
            # generate an access token and store it.
            token = self.reg_handler._generate_token(user)
            logger.info("Adding token %s for user %s", token, user)
            yield self.store.add_access_token_to_user(user, token)
            defer.returnValue(token)
        else:
            logger.warn("Failed password login for user %s", user)
            raise LoginError(403, "", errcode=Codes.FORBIDDEN)

    @defer.inlineCallbacks
    def set_password(self, user_id, newpassword, token_id=None):
        password_hash = bcrypt.hashpw(newpassword, bcrypt.gensalt())

        yield self.store.user_set_password_hash(user_id, password_hash)
        yield self.store.user_delete_access_tokens_apart_from(user_id, token_id)
        yield self.hs.get_pusherpool().remove_pushers_by_user_access_token(
            user_id, token_id
        )
        yield self.store.flush_user(user_id)

    @defer.inlineCallbacks
    def add_threepid(self, user_id, medium, address, validated_at):
        yield self.store.user_add_threepid(
            user_id, medium, address, validated_at,
            self.hs.get_clock().time_msec()
        )