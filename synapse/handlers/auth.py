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
from synapse.api.constants import LoginType
from synapse.types import UserID
from synapse.api.errors import LoginError, Codes

import logging
import bcrypt


logger = logging.getLogger(__name__)


class AuthHandler(BaseHandler):

    def __init__(self, hs):
        super(AuthHandler, self).__init__(hs)

    @defer.inlineCallbacks
    def check_auth(self, flows, clientdict):
        """
        Takes a dictionary sent by the client in the login / registration
        protocol and handles the login flow.

        Args:
            flows: list of list of stages
            authdict: The dictionary from the client root level, not the
                      'auth' key: this method prompts for auth if none is sent.
        Returns:
            A tuple of authed, dict where authed is true if the client
            has successfully completed an auth flow. If it is true, the dict
            contains the authenticated credentials of each stage.
            If authed is false, the dictionary is the server response to the
            login request and should be passed back to the client.
        """
        types = {
            LoginType.PASSWORD: self.check_password_auth
        }

        if 'auth' not in clientdict:
            defer.returnValue((False, auth_dict_for_flows(flows)))

        authdict = clientdict['auth']

        # In future: support sessions & retrieve previously succeeded
        # login types
        creds = {}

        # check auth type currently being presented
        if 'type' not in authdict:
            raise LoginError(400, "", Codes.MISSING_PARAM)
        if authdict['type'] not in types:
            raise LoginError(400, "", Codes.UNRECOGNIZED)
        result = yield types[authdict['type']](authdict)
        if result:
            creds[authdict['type']] = result

        for f in flows:
            if len(set(f) - set(creds.keys())) == 0:
                logger.info("Auth completed with creds: %r", creds)
                defer.returnValue((True, creds))

        ret = auth_dict_for_flows(flows)
        ret['completed'] = creds.keys()
        defer.returnValue((False, ret))

    @defer.inlineCallbacks
    def check_password_auth(self, authdict):
        if "user" not in authdict or "password" not in authdict:
            raise LoginError(400, "", Codes.MISSING_PARAM)

        user = authdict["user"]
        password = authdict["password"]
        if not user.startswith('@'):
            user = UserID.create(user, self.hs.hostname).to_string()

        user_info = yield self.store.get_user_by_id(user_id=user)
        if not user_info:
            logger.warn("Attempted to login as %s but they do not exist", user)
            raise LoginError(403, "", errcode=Codes.FORBIDDEN)

        stored_hash = user_info[0]["password_hash"]
        if bcrypt.checkpw(password, stored_hash):
            defer.returnValue(user)
        else:
            logger.warn("Failed password login for user %s", user)
            raise LoginError(403, "", errcode=Codes.FORBIDDEN)


def auth_dict_for_flows(flows):
    return {
        "flows": {"stages": f for f in flows}
    }
