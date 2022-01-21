# Copyright 2022 The Matrix.org Foundation C.I.C.
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
from http import HTTPStatus
from typing import Dict

from twisted.web.resource import Resource

from synapse.app.homeserver import SynapseHomeServer
from synapse.config.server import HttpListenerConfig, HttpResourceConfig, ListenerConfig
from synapse.http.site import SynapseSite

from tests.server import make_request
from tests.unittest import HomeserverTestCase, create_resource_tree, override_config


class WebClientTests(HomeserverTestCase):
    @override_config(
        {
            "web_client_location": "https://example.org",
        }
    )
    def test_webclient_resolves_with_client_resource(self):
        """
        Tests that both client and webclient resources can be accessed simultaneously.

        This is a regression test created in response to https://github.com/matrix-org/synapse/issues/11763.
        """
        for resource_name_order_list in [
            ["webclient", "client"],
            ["client", "webclient"],
        ]:
            # Create a dictionary from path regex -> resource
            resource_dict: Dict[str, Resource] = {}

            for resource_name in resource_name_order_list:
                resource_dict.update(
                    SynapseHomeServer._configure_named_resource(self.hs, resource_name)
                )

            # Create a root resource which ties the above resources together into one
            root_resource = Resource()
            create_resource_tree(resource_dict, root_resource)

            # Create a site configured with this resource to make HTTP requests against
            listener_config = ListenerConfig(
                port=8008,
                bind_addresses=["127.0.0.1"],
                type="http",
                http_options=HttpListenerConfig(
                    resources=[HttpResourceConfig(names=resource_name_order_list)]
                ),
            )
            test_site = SynapseSite(
                logger_name="synapse.access.http.fake",
                site_tag=self.hs.config.server.server_name,
                config=listener_config,
                resource=root_resource,
                server_version_string="1",
                max_request_body_size=1234,
                reactor=self.reactor,
            )

            # Attempt to make requests to endpoints on both the webclient and client resources
            # on test_site.
            self._request_client_and_webclient_resources(test_site)

    def _request_client_and_webclient_resources(self, test_site: SynapseSite) -> None:
        """Make a request to an endpoint on both the webclient and client-server resources
        of the given SynapseSite.

        Args:
            test_site: The SynapseSite object to make requests against.
        """

        # Ensure that the *webclient* resource is behaving as expected (we get redirected to
        # the configured web_client_location)
        channel = make_request(
            self.reactor,
            site=test_site,
            method="GET",
            path="/_matrix/client",
        )
        # Check that we are being redirected to the webclient location URI.
        self.assertEqual(channel.code, HTTPStatus.FOUND)
        self.assertEqual(
            channel.headers.getRawHeaders("Location"), ["https://example.org"]
        )

        # Ensure that a request to the *client* resource works.
        channel = make_request(
            self.reactor,
            site=test_site,
            method="GET",
            path="/_matrix/client/v3/login",
        )
        self.assertEqual(channel.code, HTTPStatus.OK)
        self.assertIn("flows", channel.json_body)
