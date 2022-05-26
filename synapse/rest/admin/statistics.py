# Copyright 2020 Dirk Klimpel
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

from synapse.api.errors import Codes, SynapseError
from synapse.http.servlet import RestServlet, parse_integer, parse_string
from synapse.http.site import SynapseRequest
from synapse.rest.admin._base import admin_patterns, assert_requester_is_admin
from synapse.storage.databases.main.stats import UserSortOrder
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class UserMediaStatisticsRestServlet(RestServlet):
    """
    Get statistics about uploaded media by users.
    """

    PATTERNS = admin_patterns("/statistics/users/media$")

    def __init__(self, hs: "HomeServer"):
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        order_by = parse_string(
            request,
            "order_by",
            default=UserSortOrder.USER_ID.value,
            allowed_values=(
                UserSortOrder.MEDIA_LENGTH.value,
                UserSortOrder.MEDIA_COUNT.value,
                UserSortOrder.USER_ID.value,
                UserSortOrder.DISPLAYNAME.value,
            ),
        )

        start = parse_integer(request, "from", default=0)
        if start < 0:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Query parameter from must be a string representing a positive integer.",
                errcode=Codes.INVALID_PARAM,
            )

        limit = parse_integer(request, "limit", default=100)
        if limit < 0:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Query parameter limit must be a string representing a positive integer.",
                errcode=Codes.INVALID_PARAM,
            )

        from_ts = parse_integer(request, "from_ts", default=0)
        if from_ts < 0:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Query parameter from_ts must be a string representing a positive integer.",
                errcode=Codes.INVALID_PARAM,
            )

        until_ts = parse_integer(request, "until_ts")
        if until_ts is not None:
            if until_ts < 0:
                raise SynapseError(
                    HTTPStatus.BAD_REQUEST,
                    "Query parameter until_ts must be a string representing a positive integer.",
                    errcode=Codes.INVALID_PARAM,
                )
            if until_ts <= from_ts:
                raise SynapseError(
                    HTTPStatus.BAD_REQUEST,
                    "Query parameter until_ts must be greater than from_ts.",
                    errcode=Codes.INVALID_PARAM,
                )

        search_term = parse_string(request, "search_term")
        if search_term == "":
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Query parameter search_term cannot be an empty string.",
                errcode=Codes.INVALID_PARAM,
            )

        direction = parse_string(request, "dir", default="f")
        if direction not in ("f", "b"):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Unknown direction: %s" % (direction,),
                errcode=Codes.INVALID_PARAM,
            )

        users_media, total = await self.store.get_users_media_usage_paginate(
            start, limit, from_ts, until_ts, order_by, direction, search_term
        )
        ret = {"users": users_media, "total": total}
        if (start + limit) < total:
            ret["next_token"] = start + len(users_media)

        return HTTPStatus.OK, ret
