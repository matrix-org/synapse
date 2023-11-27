# Copyright 2023 The Matrix.org Foundation C.I.C.
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

from typing import Dict

from twisted.web.resource import Resource

from synapse.rest.synapse.client import build_synapse_client_resource_tree

from tests.unittest import HomeserverTestCase, override_config, skip_unless
from tests.utils import HAS_AUTHLIB


@skip_unless(HAS_AUTHLIB, "requires authlib")
class JWKSTestCase(HomeserverTestCase):
    """Test /_synapse/jwks JWKS data."""

    def create_resource_dict(self) -> Dict[str, Resource]:
        d = super().create_resource_dict()
        d.update(build_synapse_client_resource_tree(self.hs))
        return d

    def test_empty_jwks(self) -> None:
        """Test that the JWKS endpoint is not present by default."""
        channel = self.make_request("GET", "/_synapse/jwks")
        self.assertEqual(404, channel.code, channel.result)

    @override_config(
        {
            "disable_registration": True,
            "experimental_features": {
                "msc3861": {
                    "enabled": True,
                    "issuer": "https://issuer/",
                    "client_id": "test-client-id",
                    "client_auth_method": "client_secret_post",
                    "client_secret": "secret",
                },
            },
        }
    )
    def test_empty_jwks_for_msc3861_client_secret_post(self) -> None:
        """Test that the JWKS endpoint is empty when plain auth is used."""
        channel = self.make_request("GET", "/_synapse/jwks")
        self.assertEqual(200, channel.code, channel.result)
        self.assertEqual({"keys": []}, channel.json_body)

    @override_config(
        {
            "disable_registration": True,
            "experimental_features": {
                "msc3861": {
                    "enabled": True,
                    "issuer": "https://issuer/",
                    "client_id": "test-client-id",
                    "client_auth_method": "private_key_jwt",
                    "jwk": {
                        "p": "-frVdP_tZ-J_nIR6HNMDq1N7aunwm51nAqNnhqIyuA8ikx7LlQED1tt2LD3YEvYyW8nxE2V95HlCRZXQPMiRJBFOsbmYkzl2t-MpavTaObB_fct_JqcRtdXddg4-_ihdjRDwUOreq_dpWh6MIKsC3UyekfkHmeEJg5YpOTL15j8",
                        "kty": "RSA",
                        "q": "oFw-Enr_YozQB1ab-kawn4jY3yHi8B1nSmYT0s8oTCflrmps5BFJfCkHL5ij3iY15z0o2m0N-jjB1oSJ98O4RayEEYNQlHnTNTl0kRIWzpoqblHUIxVcahIpP_xTovBJzwi8XXoLGqHOOMA-r40LSyVgP2Ut8D9qBwV6_UfT0LU",
                        "d": "WFkDPYo4b4LIS64D_QtQfGGuAObPvc3HFfp9VZXyq3SJR58XZRHE0jqtlEMNHhOTgbMYS3w8nxPQ_qVzY-5hs4fIanwvB64mAoOGl0qMHO65DTD_WsGFwzYClJPBVniavkLE2Hmpu8IGe6lGliN8vREC6_4t69liY-XcN_ECboVtC2behKkLOEASOIMuS7YcKAhTJFJwkl1dqDlliEn5A4u4xy7nuWQz3juB1OFdKlwGA5dfhDNglhoLIwNnkLsUPPFO-WB5ZNEW35xxHOToxj4bShvDuanVA6mJPtTKjz0XibjB36bj_nF_j7EtbE2PdGJ2KevAVgElR4lqS4ISgQ",
                        "e": "AQAB",
                        "kid": "test",
                        "qi": "cPfNk8l8W5exVNNea4d7QZZ8Qr8LgHghypYAxz8PQh1fNa8Ya1SNUDVzC2iHHhszxxA0vB9C7jGze8dBrvnzWYF1XvQcqNIVVgHhD57R1Nm3dj2NoHIKe0Cu4bCUtP8xnZQUN4KX7y4IIcgRcBWG1hT6DEYZ4BxqicnBXXNXAUI",
                        "dp": "dKlMHvslV1sMBQaKWpNb3gPq0B13TZhqr3-E2_8sPlvJ3fD8P4CmwwnOn50JDuhY3h9jY5L06sBwXjspYISVv8hX-ndMLkEeF3lrJeA5S70D8rgakfZcPIkffm3tlf1Ok3v5OzoxSv3-67Df4osMniyYwDUBCB5Oq1tTx77xpU8",
                        "dq": "S4ooU1xNYYcjl9FcuJEEMqKsRrAXzzSKq6laPTwIp5dDwt2vXeAm1a4eDHXC-6rUSZGt5PbqVqzV4s-cjnJMI8YYkIdjNg4NSE1Ac_YpeDl3M3Colb5CQlU7yUB7xY2bt0NOOFp9UJZYJrOo09mFMGjy5eorsbitoZEbVqS3SuE",
                        "n": "nJbYKqFwnURKimaviyDFrNLD3gaKR1JW343Qem25VeZxoMq1665RHVoO8n1oBm4ClZdjIiZiVdpyqzD5-Ow12YQgQEf1ZHP3CCcOQQhU57Rh5XvScTe5IxYVkEW32IW2mp_CJ6WfjYpfeL4azarVk8H3Vr59d1rSrKTVVinVdZer9YLQyC_rWAQNtHafPBMrf6RYiNGV9EiYn72wFIXlLlBYQ9Fx7bfe1PaL6qrQSsZP3_rSpuvVdLh1lqGeCLR0pyclA9uo5m2tMyCXuuGQLbA_QJm5xEc7zd-WFdux2eXF045oxnSZ_kgQt-pdN7AxGWOVvwoTf9am6mSkEdv6iw",
                    },
                },
            },
        }
    )
    def test_key_returned_for_msc3861_client_secret_post(self) -> None:
        """Test that the JWKS includes public part of JWK for private_key_jwt auth is used."""
        channel = self.make_request("GET", "/_synapse/jwks")
        self.assertEqual(200, channel.code, channel.result)
        self.assertEqual(
            {
                "keys": [
                    {
                        "kty": "RSA",
                        "e": "AQAB",
                        "kid": "test",
                        "n": "nJbYKqFwnURKimaviyDFrNLD3gaKR1JW343Qem25VeZxoMq1665RHVoO8n1oBm4ClZdjIiZiVdpyqzD5-Ow12YQgQEf1ZHP3CCcOQQhU57Rh5XvScTe5IxYVkEW32IW2mp_CJ6WfjYpfeL4azarVk8H3Vr59d1rSrKTVVinVdZer9YLQyC_rWAQNtHafPBMrf6RYiNGV9EiYn72wFIXlLlBYQ9Fx7bfe1PaL6qrQSsZP3_rSpuvVdLh1lqGeCLR0pyclA9uo5m2tMyCXuuGQLbA_QJm5xEc7zd-WFdux2eXF045oxnSZ_kgQt-pdN7AxGWOVvwoTf9am6mSkEdv6iw",
                    }
                ]
            },
            channel.json_body,
        )
