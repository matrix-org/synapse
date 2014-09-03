# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

"""Contains functions for registering clients."""
from twisted.internet import defer

from synapse.types import UserID
from synapse.api.errors import SynapseError, RegistrationError
from ._base import BaseHandler
import synapse.util.stringutils as stringutils
from synapse.http.client import PlainHttpClient

import base64
import bcrypt
import logging

logger = logging.getLogger(__name__)


class RegistrationHandler(BaseHandler):

    def __init__(self, hs):
        super(RegistrationHandler, self).__init__(hs)

        self.distributor = hs.get_distributor()
        self.distributor.declare("registered_user")

    @defer.inlineCallbacks
    def register(self, localpart=None, password=None, threepidCreds=None):
        """Registers a new client on the server.

        Args:
            localpart : The local part of the user ID to register. If None,
              one will be randomly generated.
            password (str) : The password to assign to this user so they can
            login again.
        Returns:
            A tuple of (user_id, access_token).
        Raises:
            RegistrationError if there was a problem registering.
        """

        if threepidCreds:
            for c in threepidCreds:
                logger.info("validating theeepidcred sid %s on id server %s", c['sid'], c['idServer'])
                try:
                    threepid = yield self._threepid_from_creds(c)
                except:
                    logger.err()
                    raise RegistrationError(400, "Couldn't validate 3pid")
                    
                if not threepid:
                    raise RegistrationError(400, "Couldn't validate 3pid")
                logger.info("got threepid medium %s address %s", threepid['medium'], threepid['address'])

        password_hash = None
        if password:
            password_hash = bcrypt.hashpw(password, bcrypt.gensalt())

        if localpart:
            user = UserID(localpart, self.hs.hostname, True)
            user_id = user.to_string()

            token = self._generate_token(user_id)
            yield self.store.register(user_id=user_id,
                token=token,
                password_hash=password_hash)

            self.distributor.fire("registered_user", user)
        else:
            # autogen a random user ID
            attempts = 0
            user_id = None
            token = None
            while not user_id and not token:
                try:
                    localpart = self._generate_user_id()
                    user = UserID(localpart, self.hs.hostname, True)
                    user_id = user.to_string()

                    token = self._generate_token(user_id)
                    yield self.store.register(
                        user_id=user_id,
                        token=token,
                        password_hash=password_hash)

                    self.distributor.fire("registered_user", user)
                except SynapseError:
                    # if user id is taken, just generate another
                    user_id = None
                    token = None
                    attempts += 1
                    if attempts > 5:
                        raise RegistrationError(
                            500, "Cannot generate user ID.")

        # Now we have a matrix ID, bind it to the threepids we were given
        if threepidCreds:
            for c in threepidCreds:
                # XXX: This should be a deferred list, shouldn't it?
                yield self._bind_threepid(c, user_id)
                

        defer.returnValue((user_id, token))

    def _generate_token(self, user_id):
        # urlsafe variant uses _ and - so use . as the separator and replace
        # all =s with .s so http clients don't quote =s when it is used as
        # query params.
        return (base64.urlsafe_b64encode(user_id).replace('=', '.') + '.' +
                stringutils.random_string(18))

    def _generate_user_id(self):
        return "-" + stringutils.random_string(18)

    @defer.inlineCallbacks
    def _threepid_from_creds(self, creds):
        httpCli = PlainHttpClient(self.hs)
        # XXX: make this configurable!
        trustedIdServers = [ 'matrix.org:8090' ]
        if not creds['idServer'] in trustedIdServers:
            logger.warn('%s is not a trusted ID server: rejecting 3pid credentials', creds['idServer'])
            defer.returnValue(None)
        data = yield httpCli.get_json(
            creds['idServer'],
            "/_matrix/identity/api/v1/3pid/getValidated3pid",
            { 'sid': creds['sid'], 'clientSecret': creds['clientSecret'] }
        )
        
        if 'medium' in data:
            defer.returnValue(data)
        defer.returnValue(None)

    @defer.inlineCallbacks
    def _bind_threepid(self, creds, mxid):
        httpCli = PlainHttpClient(self.hs)
        data = yield httpCli.post_urlencoded_get_json(
            creds['idServer'],
            "/_matrix/identity/api/v1/3pid/bind",
            { 'sid': creds['sid'], 'clientSecret': creds['clientSecret'], 'mxid':mxid }
        )
        defer.returnValue(data)
        
        

