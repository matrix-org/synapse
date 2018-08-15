# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
# Copyright 2018 New Vector Ltd
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

import logging

from canonicaljson import json

from twisted.internet import defer

from synapse.api.errors import (
    CodeMessageException,
    Codes,
    HttpResponseException,
    SynapseError,
)

from ._base import BaseHandler

logger = logging.getLogger(__name__)


class IdentityHandler(BaseHandler):

    def __init__(self, hs):
        super(IdentityHandler, self).__init__(hs)

        self.http_client = hs.get_simple_http_client()
        self.federation_http_client = hs.get_http_client()

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

        try:
            data = yield self.http_client.get_json(
                "https://%s%s" % (
                    id_server,
                    "/_matrix/identity/api/v1/3pid/getValidated3pid"
                ),
                {'sid': creds['sid'], 'client_secret': client_secret}
            )
        except HttpResponseException as e:
            logger.info("getValidated3pid failed with Matrix error: %r", e)
            raise e.to_synapse_error()

        if 'medium' in data:
            defer.returnValue(data)
        defer.returnValue(None)

    @defer.inlineCallbacks
    def bind_threepid(self, creds, mxid):
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
            data = json.loads(e.msg)  # XXX WAT?
        defer.returnValue(data)

    @defer.inlineCallbacks
    def try_unbind_threepid(self, mxid, threepid):
        """Removes a binding from an identity server

        Args:
            mxid (str): Matrix user ID of binding to be removed
            threepid (dict): Dict with medium & address of binding to be removed

        Raises:
            SynapseError: If we failed to contact the identity server

        Returns:
            Deferred[bool]: True on success, otherwise False if the identity
            server doesn't support unbinding
        """
        logger.debug("unbinding threepid %r from %s", threepid, mxid)
        if not self.trusted_id_servers:
            logger.warn("Can't unbind threepid: no trusted ID servers set in config")
            defer.returnValue(False)

        # We don't track what ID server we added 3pids on (perhaps we ought to)
        # but we assume that any of the servers in the trusted list are in the
        # same ID server federation, so we can pick any one of them to send the
        # deletion request to.
        id_server = next(iter(self.trusted_id_servers))

        url = "https://%s/_matrix/identity/api/v1/3pid/unbind" % (id_server,)
        content = {
            "mxid": mxid,
            "threepid": threepid,
        }
        headers = {}
        # we abuse the federation http client to sign the request, but we have to send it
        # using the normal http client since we don't want the SRV lookup and want normal
        # 'browser-like' HTTPS.
        self.federation_http_client.sign_request(
            destination=None,
            method='POST',
            url_bytes='/_matrix/identity/api/v1/3pid/unbind'.encode('ascii'),
            headers_dict=headers,
            content=content,
            destination_is=id_server,
        )
        try:
            yield self.http_client.post_json_get_json(
                url,
                content,
                headers,
            )
        except HttpResponseException as e:
            if e.code in (400, 404, 501,):
                # The remote server probably doesn't support unbinding (yet)
                logger.warn("Received %d response while unbinding threepid", e.code)
                defer.returnValue(False)
            else:
                logger.error("Failed to unbind threepid on identity server: %s", e)
                raise SynapseError(502, "Failed to contact identity server")

        defer.returnValue(True)

    @defer.inlineCallbacks
    def requestEmailToken(self, id_server, email, client_secret, send_attempt, **kwargs):
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
            data = yield self.http_client.post_json_get_json(
                "https://%s%s" % (
                    id_server,
                    "/_matrix/identity/api/v1/validate/email/requestToken"
                ),
                params
            )
            defer.returnValue(data)
        except HttpResponseException as e:
            logger.info("Proxied requestToken failed: %r", e)
            raise e.to_synapse_error()

    @defer.inlineCallbacks
    def requestMsisdnToken(
            self, id_server, country, phone_number,
            client_secret, send_attempt, **kwargs
    ):
        if not self._should_trust_id_server(id_server):
            raise SynapseError(
                400, "Untrusted ID server '%s'" % id_server,
                Codes.SERVER_NOT_TRUSTED
            )

        params = {
            'country': country,
            'phone_number': phone_number,
            'client_secret': client_secret,
            'send_attempt': send_attempt,
        }
        params.update(kwargs)

        try:
            data = yield self.http_client.post_json_get_json(
                "https://%s%s" % (
                    id_server,
                    "/_matrix/identity/api/v1/validate/msisdn/requestToken"
                ),
                params
            )
            defer.returnValue(data)
        except HttpResponseException as e:
            logger.info("Proxied requestToken failed: %r", e)
            raise e.to_synapse_error()
