# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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

from mock import Mock

from twisted.internet import defer

import synapse.rest.admin
from synapse.rest.client.v1 import login
from synapse.rest.client.v2_alpha import account

from tests import unittest


class ThreepidISRewrittenURLTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        account.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        self.address = "test@test"
        self.is_server_name = "testis"
        self.rewritten_is_url = "int.testis"

        config = self.default_config()
        config["trusted_third_party_id_servers"] = [
            self.is_server_name,
        ]
        config["rewrite_identity_server_urls"] = {
            self.is_server_name: self.rewritten_is_url,
        }

        mock_http_client = Mock(spec=[
            "post_urlencoded_get_json",
        ])
        mock_http_client.post_urlencoded_get_json.return_value = defer.succeed({
            "address": self.address,
            "medium": "email",
        })

        self.hs = self.setup_test_homeserver(
            config=config,
            simple_http_client=mock_http_client,
        )

        return self.hs

    def prepare(self, reactor, clock, hs):
        self.user_id = self.register_user("kermit", "monkey")

    def test_rewritten_id_server(self):
        """
        Tests that, when validating a 3PID association while rewriting the IS's server
        name:
        * the bind request is done against the rewritten hostname
        * the original, non-rewritten, server name is stored in the database
        """
        handler = self.hs.get_handlers().identity_handler
        post_urlenc_get_json = self.hs.get_simple_http_client().post_urlencoded_get_json
        store = self.hs.get_datastore()

        creds = {
            "sid": "123",
            "client_secret": "some_secret",
        }

        # Make sure processing the mocked response goes through.
        data = self.get_success(handler.bind_threepid(
            {
                "id_server": self.is_server_name,
                "client_secret": creds["client_secret"],
                "sid": creds["sid"],
            },
            self.user_id,
        ))
        self.assertEqual(data.get("address"), self.address)

        # Check that the request was done against the rewritten server name.
        post_urlenc_get_json.assert_called_once_with(
            "https://%s/_matrix/identity/api/v1/3pid/bind" % self.rewritten_is_url,
            {
                'sid': creds['sid'],
                'client_secret': creds["client_secret"],
                'mxid': self.user_id,
            }
        )

        # Check that the original server name is saved in the database instead of the
        # rewritten one.
        id_servers = self.get_success(store.get_id_servers_user_bound(
            self.user_id, "email", self.address
        ))
        self.assertEqual(id_servers, [self.is_server_name])
