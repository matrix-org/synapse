# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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
from synapse.http.client import SimpleHttpClient
from synapse.util.async import run_on_reactor

import json
import logging

logger = logging.getLogger(__name__)


class IdentityHandler(BaseHandler):

    def __init__(self, hs):
        super(IdentityHandler, self).__init__(hs)

    @defer.inlineCallbacks
    def threepid_from_creds(self, creds):
        yield run_on_reactor()

        # TODO: get this from the homeserver rather than creating a new one for
        # each request
        http_client = SimpleHttpClient(self.hs)
        # XXX: make this configurable!
        # trustedIdServers = ['matrix.org', 'localhost:8090']
        trustedIdServers = ['matrix.org']
        if not creds['id_server'] in trustedIdServers:
            logger.warn('%s is not a trusted ID server: rejecting 3pid ' +
                        'credentials', creds['id_server'])
            defer.returnValue(None)

        data = {}
        try:
            data = yield http_client.get_json(
                "https://%s%s" % (
                    creds['id_server'],
                    "/_matrix/identity/api/v1/3pid/getValidated3pid"
                ),
                {'sid': creds['sid'], 'client_secret': creds['client_secret']}
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
        http_client = SimpleHttpClient(self.hs)
        data = None
        try:
            data = yield http_client.post_urlencoded_get_json(
                "https://%s%s" % (
                    creds['id_server'], "/_matrix/identity/api/v1/3pid/bind"
                ),
                {
                    'sid': creds['sid'],
                    'client_secret': creds['client_secret'],
                    'mxid': mxid,
                }
            )
            logger.debug("bound threepid %r to %s", creds, mxid)
        except CodeMessageException as e:
            data = json.loads(e.msg)
        defer.returnValue(data)
