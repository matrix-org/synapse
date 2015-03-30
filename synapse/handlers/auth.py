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
from synapse.http.client import SimpleHttpClient
from twisted.web.client import PartialDownloadError

import logging
import bcrypt
import simplejson


logger = logging.getLogger(__name__)


class AuthHandler(BaseHandler):

    def __init__(self, hs):
        super(AuthHandler, self).__init__(hs)

    @defer.inlineCallbacks
    def check_auth(self, flows, clientdict, clientip=None):
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
            LoginType.PASSWORD: self.check_password_auth,
            LoginType.RECAPTCHA: self.check_recaptcha,
        }

        if not clientdict or 'auth' not in clientdict:
            defer.returnValue((False, self.auth_dict_for_flows(flows)))

        authdict = clientdict['auth']

        # In future: support sessions & retrieve previously succeeded
        # login types
        creds = {}

        # check auth type currently being presented
        if 'type' not in authdict:
            raise LoginError(400, "", Codes.MISSING_PARAM)
        if authdict['type'] not in types:
            raise LoginError(400, "", Codes.UNRECOGNIZED)
        result = yield types[authdict['type']](authdict, clientip)
        if result:
            creds[authdict['type']] = result

        for f in flows:
            if len(set(f) - set(creds.keys())) == 0:
                logger.info("Auth completed with creds: %r", creds)
                defer.returnValue((True, creds))

        ret = self.auth_dict_for_flows(flows)
        ret['completed'] = creds.keys()
        defer.returnValue((False, ret))

    @defer.inlineCallbacks
    def check_password_auth(self, authdict, _):
        if "user" not in authdict or "password" not in authdict:
            raise LoginError(400, "", Codes.MISSING_PARAM)

        user = authdict["user"]
        password = authdict["password"]
        if not user.startswith('@'):
            user = UserID.create(user, self.hs.hostname).to_string()

        user_info = yield self.store.get_user_by_id(user_id=user)
        if not user_info:
            logger.warn("Attempted to login as %s but they do not exist", user)
            raise LoginError(401, "", errcode=Codes.UNAUTHORIZED)

        stored_hash = user_info[0]["password_hash"]
        if bcrypt.checkpw(password, stored_hash):
            defer.returnValue(user)
        else:
            logger.warn("Failed password login for user %s", user)
            raise LoginError(401, "", errcode=Codes.UNAUTHORIZED)

    @defer.inlineCallbacks
    def check_recaptcha(self, authdict, clientip):
        try:
            user_response = authdict["response"]
        except KeyError:
            # Client tried to provide captcha but didn't give the parameter:
            # bad request.
            raise LoginError(
                400, "Captcha response is required",
                errcode=Codes.CAPTCHA_NEEDED
            )

        logger.info(
            "Submitting recaptcha response %s with remoteip %s",
            user_response, clientip
        )

        # TODO: get this from the homeserver rather than creating a new one for
        # each request
        try:
            client = SimpleHttpClient(self.hs)
            data = yield client.post_urlencoded_get_json(
                "https://www.google.com/recaptcha/api/siteverify",
                args={
                    'secret': self.hs.config.recaptcha_private_key,
                    'response': user_response,
                    'remoteip': clientip,
                }
            )
        except PartialDownloadError as pde:
            # Twisted is silly
            data = pde.response
        resp_body = simplejson.loads(data)
        if 'success' in resp_body and resp_body['success']:
            defer.returnValue(True)
        raise LoginError(401, "", errcode=Codes.UNAUTHORIZED)

    def get_params_recaptcha(self):
        return {"public_key": self.hs.config.recaptcha_public_key}

    def auth_dict_for_flows(self, flows):
        public_flows = []
        for f in flows:
            hidden = False
            for stagetype in f:
                if stagetype in LoginType.HIDDEN_TYPES:
                    hidden = True
            if not hidden:
                public_flows.append(f)

        get_params = {
            LoginType.RECAPTCHA: self.get_params_recaptcha,
        }

        params = {}

        for f in public_flows:
            for stage in f:
                if stage in get_params and stage not in params:
                    params[stage] = get_params[stage]()

        return {
            "flows": [{"stages": f} for f in public_flows],
            "params": params
        }