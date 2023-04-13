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
import logging
from typing import Dict, List, Tuple

from synapse.api.urls import LINEARIZED_PREFIX
from synapse.federation.transport.server import Authenticator
from synapse.federation.transport.server.federation import BaseFederationServerServlet
from synapse.http.server import JsonResource
from synapse.http.servlet import parse_string_from_args
from synapse.types import JsonDict, get_domain_from_id

logger = logging.getLogger(__name__)


class LinearizedResource(JsonResource):
    """Handles incoming federation HTTP requests"""

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.clock = hs.get_clock()

        super().__init__(hs, canonical_json=False)

        self.authenticator = Authenticator(hs)
        self.ratelimiter = hs.get_federation_ratelimiter()

        self.register_servlets()

    def register_servlets(self) -> None:
        for servletclass in (LinearizedSendServlet, LinearizedInviteServlet):
            servletclass(
                self.hs,
                authenticator=self.authenticator,
                ratelimiter=self.ratelimiter,
                server_name=self.hs.hostname,
            ).register(self)


class LinearizedSendServlet(BaseFederationServerServlet):
    PATH = "/send/(?P<transaction_id>[^/]*)/?"
    CATEGORY = "Inbound linearized transaction request"
    PREFIX = LINEARIZED_PREFIX

    # This doesn't seem right. :)
    REQUIRE_AUTH = False

    # We ratelimit manually in the handler as we queue up the requests and we
    # don't want to fill up the ratelimiter with blocked requests.
    RATELIMIT = False

    # This is when someone is trying to send us a bunch of data.
    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        transaction_id: str,
    ) -> Tuple[int, JsonDict]:
        """Called on PUT /send/<transaction_id>/

        Args:
            transaction_id: The transaction_id associated with this request. This
                is *not* None.

        Returns:
            Tuple of `(code, response)`, where
            `response` is a python dict to be converted into JSON that is
            used as the response body.
        """
        # Parse the request
        try:
            transaction_data = content

            logger.debug("Decoded %s: %s", transaction_id, str(transaction_data))

            logger.info(
                "Received txn %s from %s. (PDUs: %d, EDUs: %d)",
                transaction_id,
                origin,
                len(transaction_data.get("pdus", [])),
                len(transaction_data.get("edus", [])),
            )

        except Exception as e:
            logger.exception(e)
            return 400, {"error": "Invalid transaction"}

        code, response = await self.handler.on_incoming_transaction(
            origin, transaction_id, self.server_name, transaction_data
        )

        return code, response


class LinearizedInviteServlet(BaseFederationServerServlet):
    PATH = "/invite"
    CATEGORY = "Linearized requests"
    PREFIX = LINEARIZED_PREFIX

    # This doesn't seem right. :)
    REQUIRE_AUTH = False

    async def on_POST(
        self, origin: str, content: JsonDict, query: Dict[bytes, List[bytes]]
    ) -> Tuple[int, JsonDict]:
        room_version = parse_string_from_args(query, "room_version", required=True)
        event = content

        # XXX Currently no auth.
        origin = get_domain_from_id(event["sender"])

        result = await self.handler.on_invite_request(
            origin, event, room_version_id=room_version
        )

        return 200, result
