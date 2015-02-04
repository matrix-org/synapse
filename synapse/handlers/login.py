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
from synapse.api.errors import LoginError, Codes, CodeMessageException
from synapse.http.client import SimpleHttpClient
from synapse.util.emailutils import EmailException
import synapse.util.emailutils as emailutils

import bcrypt
import json
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
    def reset_password(self, user_id, email):
        is_valid = yield self._check_valid_association(user_id, email)
        logger.info("reset_password user=%s email=%s valid=%s", user_id, email,
                    is_valid)
        if is_valid:
            try:
                # send an email out
                emailutils.send_email(
                    smtp_server=self.hs.config.email_smtp_server,
                    from_addr=self.hs.config.email_from_address,
                    to_addr=email,
                    subject="Password Reset",
                    body="TODO."
                )
            except EmailException as e:
                logger.exception(e)

    @defer.inlineCallbacks
    def _check_valid_association(self, user_id, email):
        identity = yield self._query_email(email)
        if identity and "mxid" in identity:
            if identity["mxid"] == user_id:
                defer.returnValue(True)
                return
        defer.returnValue(False)

    @defer.inlineCallbacks
    def _query_email(self, email):
        http_client = SimpleHttpClient(self.hs)
        try:
            data = yield http_client.get_json(
                # TODO FIXME This should be configurable.
                # XXX: ID servers need to use HTTPS
                "http://%s%s" % (
                    "matrix.org:8090", "/_matrix/identity/api/v1/lookup"
                ),
                {
                    'medium': 'email',
                    'address': email
                }
            )
            defer.returnValue(data)
        except CodeMessageException as e:
            data = json.loads(e.msg)
            defer.returnValue(data)
