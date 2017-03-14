# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

"""Utilities for interacting with Identity Servers"""
from twisted.internet import defer

from synapse.api.errors import (
    CodeMessageException
)
from ._base import BaseHandler
from synapse.util.async import run_on_reactor
from synapse.api.errors import SynapseError, Codes

import json
import logging

logger = logging.getLogger(__name__)


class IdentityHandler(BaseHandler):

    def __init__(self, hs):
        super(IdentityHandler, self).__init__(hs)

        self.http_client = hs.get_simple_http_client()

        self.trusted_id_servers = set(hs.config.trusted_third_party_id_servers)
        self.trust_any_id_server_just_for_testing_do_not_use = (
            hs.config.use_insecure_ssl_client_just_for_testing_do_not_use
        )

    def _should_trust_id_server(self, id_server):
        if id_server not in self.trusted_id_servers:
            if self.trust_any_id_server_just_for_testing_do_not_use:
                logger.warn(
                    "Trusting untrustworthy ID server %r even though it isn't"
                    " in the trusted id list for testing because"
                    " 'use_insecure_ssl_client_just_for_testing_do_not_use'"
                    " is set in the config",
                    id_server,
                )
            else:
                return False
        return True

    @defer.inlineCallbacks
    def threepid_from_creds(self, creds):
        yield run_on_reactor()

        if 'id_server' in creds:
            id_server = creds['id_server']
        elif 'idServer' in creds:
            id_server = creds['idServer']
        else:
            raise SynapseError(400, "No id_server in creds")

        if 'client_secret' in creds:
            client_secret = creds['client_secret']
        elif 'clientSecret' in creds:
            client_secret = creds['clientSecret']
        else:
            raise SynapseError(400, "No client_secret in creds")

        if not self._should_trust_id_server(id_server):
            logger.warn(
                '%s is not a trusted ID server: rejecting 3pid ' +
                'credentials', id_server
            )
            defer.returnValue(None)

        data = {}
        try:
            data = yield self.http_client.get_json(
                "https://%s%s" % (
                    id_server,
                    "/_matrix/identity/api/v1/3pid/getValidated3pid"
                ),
                {'sid': creds['sid'], 'client_secret': client_secret}
            )
        except CodeMessageException as e:
            data = json.loads(e.msg)

        if 'medium' in data:
            defer.returnValue(data)
        defer.returnValue(None)

    @defer.inlineCallbacks
    def bind_threepid(self, creds, mxid):
        yield run_on_reactor()
        logger.debug("binding threepid %r to %s", creds, mxid)
        data = None

        if 'id_server' in creds:
            id_server = creds['id_server']
        elif 'idServer' in creds:
            id_server = creds['idServer']
        else:
            raise SynapseError(400, "No id_server in creds")

        if 'client_secret' in creds:
            client_secret = creds['client_secret']
        elif 'clientSecret' in creds:
            client_secret = creds['clientSecret']
        else:
            raise SynapseError(400, "No client_secret in creds")

        try:
            data = yield self.http_client.post_urlencoded_get_json(
                "https://%s%s" % (
                    id_server, "/_matrix/identity/api/v1/3pid/bind"
                ),
                {
                    'sid': creds['sid'],
                    'client_secret': client_secret,
                    'mxid': mxid,
                }
            )
            logger.debug("bound threepid %r to %s", creds, mxid)
        except CodeMessageException as e:
            data = json.loads(e.msg)
        defer.returnValue(data)

    @defer.inlineCallbacks
    def requestEmailToken(self, id_server, email, client_secret, send_attempt, **kwargs):
        yield run_on_reactor()

        if not self._should_trust_id_server(id_server):
            raise SynapseError(
                400, "Untrusted ID server '%s'" % id_server,
                Codes.SERVER_NOT_TRUSTED
            )

        params = {
            'email': email,
            'client_secret': client_secret,
            'send_attempt': send_attempt,
        }
        params.update(kwargs)

        try:
            data = yield self.http_client.post_urlencoded_get_json(
                "https://%s%s" % (
                    id_server,
                    "/_matrix/identity/api/v1/validate/email/requestToken"
                ),
                params
            )
            defer.returnValue(data)
        except CodeMessageException as e:
            logger.info("Proxied requestToken failed: %r", e)
            raise e
