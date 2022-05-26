# Copyright 2021 The Matrix.org Foundation C.I.C.
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
from http import HTTPStatus
from typing import TYPE_CHECKING, Tuple

from synapse.api.errors import Codes, NotFoundError, SynapseError
from synapse.federation.transport.server import Authenticator
from synapse.http.servlet import RestServlet, parse_integer, parse_string
from synapse.http.site import SynapseRequest
from synapse.rest.admin._base import admin_patterns, assert_requester_is_admin
from synapse.storage.databases.main.transactions import DestinationSortOrder
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class ListDestinationsRestServlet(RestServlet):
    """Get request to list all destinations.
    This needs user to have administrator access in Synapse.

    GET /_synapse/admin/v1/federation/destinations?from=0&limit=10

    returns:
        200 OK with list of destinations if success otherwise an error.

    The parameters `from` and `limit` are required only for pagination.
    By default, a `limit` of 100 is used.
    The parameter `destination` can be used to filter by destination.
    The parameter `order_by` can be used to order the result.
    """

    PATTERNS = admin_patterns("/federation/destinations$")

    def __init__(self, hs: "HomeServer"):
        self._auth = hs.get_auth()
        self._store = hs.get_datastores().main

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self._auth, request)

        start = parse_integer(request, "from", default=0)
        limit = parse_integer(request, "limit", default=100)

        if start < 0:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Query parameter from must be a string representing a positive integer.",
                errcode=Codes.INVALID_PARAM,
            )

        if limit < 0:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Query parameter limit must be a string representing a positive integer.",
                errcode=Codes.INVALID_PARAM,
            )

        destination = parse_string(request, "destination")

        order_by = parse_string(
            request,
            "order_by",
            default=DestinationSortOrder.DESTINATION.value,
            allowed_values=[dest.value for dest in DestinationSortOrder],
        )

        direction = parse_string(request, "dir", default="f", allowed_values=("f", "b"))

        destinations, total = await self._store.get_destinations_paginate(
            start, limit, destination, order_by, direction
        )
        response = {"destinations": destinations, "total": total}
        if (start + limit) < total:
            response["next_token"] = str(start + len(destinations))

        return HTTPStatus.OK, response


class DestinationRestServlet(RestServlet):
    """Get details of a destination.
    This needs user to have administrator access in Synapse.

    GET /_synapse/admin/v1/federation/destinations/<destination>

    returns:
        200 OK with details of a destination if success otherwise an error.
    """

    PATTERNS = admin_patterns("/federation/destinations/(?P<destination>[^/]*)$")

    def __init__(self, hs: "HomeServer"):
        self._auth = hs.get_auth()
        self._store = hs.get_datastores().main

    async def on_GET(
        self, request: SynapseRequest, destination: str
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self._auth, request)

        if not await self._store.is_destination_known(destination):
            raise NotFoundError("Unknown destination")

        destination_retry_timings = await self._store.get_destination_retry_timings(
            destination
        )

        last_successful_stream_ordering = (
            await self._store.get_destination_last_successful_stream_ordering(
                destination
            )
        )

        response: JsonDict = {
            "destination": destination,
            "last_successful_stream_ordering": last_successful_stream_ordering,
        }

        if destination_retry_timings:
            response = {
                **response,
                "failure_ts": destination_retry_timings.failure_ts,
                "retry_last_ts": destination_retry_timings.retry_last_ts,
                "retry_interval": destination_retry_timings.retry_interval,
            }
        else:
            response = {
                **response,
                "failure_ts": None,
                "retry_last_ts": 0,
                "retry_interval": 0,
            }

        return HTTPStatus.OK, response


class DestinationMembershipRestServlet(RestServlet):
    """Get list of rooms of a destination.
    This needs user to have administrator access in Synapse.

    GET /_synapse/admin/v1/federation/destinations/<destination>/rooms?from=0&limit=10

    returns:
        200 OK with a list of rooms if success otherwise an error.

    The parameters `from` and `limit` are required only for pagination.
    By default, a `limit` of 100 is used.
    """

    PATTERNS = admin_patterns("/federation/destinations/(?P<destination>[^/]*)/rooms$")

    def __init__(self, hs: "HomeServer"):
        self._auth = hs.get_auth()
        self._store = hs.get_datastores().main

    async def on_GET(
        self, request: SynapseRequest, destination: str
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self._auth, request)

        if not await self._store.is_destination_known(destination):
            raise NotFoundError("Unknown destination")

        start = parse_integer(request, "from", default=0)
        limit = parse_integer(request, "limit", default=100)

        if start < 0:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Query parameter from must be a string representing a positive integer.",
                errcode=Codes.INVALID_PARAM,
            )

        if limit < 0:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Query parameter limit must be a string representing a positive integer.",
                errcode=Codes.INVALID_PARAM,
            )

        direction = parse_string(request, "dir", default="f", allowed_values=("f", "b"))

        rooms, total = await self._store.get_destination_rooms_paginate(
            destination, start, limit, direction
        )
        response = {"rooms": rooms, "total": total}
        if (start + limit) < total:
            response["next_token"] = str(start + len(rooms))

        return HTTPStatus.OK, response


class DestinationResetConnectionRestServlet(RestServlet):
    """Reset destinations' connection timeouts and wake it up.
    This needs user to have administrator access in Synapse.

    POST /_synapse/admin/v1/federation/destinations/<destination>/reset_connection
    {}

    returns:
        200 OK otherwise an error.
    """

    PATTERNS = admin_patterns(
        "/federation/destinations/(?P<destination>[^/]+)/reset_connection$"
    )

    def __init__(self, hs: "HomeServer"):
        self._auth = hs.get_auth()
        self._store = hs.get_datastores().main
        self._authenticator = Authenticator(hs)

    async def on_POST(
        self, request: SynapseRequest, destination: str
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self._auth, request)

        if not await self._store.is_destination_known(destination):
            raise NotFoundError("Unknown destination")

        retry_timings = await self._store.get_destination_retry_timings(destination)
        if not (retry_timings and retry_timings.retry_last_ts):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "The retry timing does not need to be reset for this destination.",
            )

        # reset timings and wake up
        await self._authenticator.reset_retry_timings(destination)

        return HTTPStatus.OK, {}
