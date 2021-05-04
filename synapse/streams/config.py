# Copyright 2014-2016 OpenMarket Ltd
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
from typing import Optional

import attr

from synapse.api.errors import SynapseError
from synapse.http.servlet import parse_integer, parse_string
from synapse.http.site import SynapseRequest
from synapse.storage.databases.main import DataStore
from synapse.types import StreamToken

logger = logging.getLogger(__name__)


MAX_LIMIT = 1000


@attr.s(slots=True)
class PaginationConfig:
    """A configuration object which stores pagination parameters."""

    from_token = attr.ib(type=Optional[StreamToken])
    to_token = attr.ib(type=Optional[StreamToken])
    direction = attr.ib(type=str)
    limit = attr.ib(type=Optional[int])

    @classmethod
    async def from_request(
        cls,
        store: "DataStore",
        request: SynapseRequest,
        raise_invalid_params: bool = True,
        default_limit: Optional[int] = None,
    ) -> "PaginationConfig":
        direction = parse_string(request, "dir", default="f", allowed_values=["f", "b"])

        from_tok = parse_string(request, "from")
        to_tok = parse_string(request, "to")

        try:
            if from_tok == "END":
                from_tok = None  # For backwards compat.
            elif from_tok:
                from_tok = await StreamToken.from_string(store, from_tok)
        except Exception:
            raise SynapseError(400, "'from' parameter is invalid")

        try:
            if to_tok:
                to_tok = await StreamToken.from_string(store, to_tok)
        except Exception:
            raise SynapseError(400, "'to' parameter is invalid")

        limit = parse_integer(request, "limit", default=default_limit)

        if limit:
            if limit < 0:
                raise SynapseError(400, "Limit must be 0 or above")

            limit = min(int(limit), MAX_LIMIT)

        try:
            return PaginationConfig(from_tok, to_tok, direction, limit)
        except Exception:
            logger.exception("Failed to create pagination config")
            raise SynapseError(400, "Invalid request.")

    def __repr__(self) -> str:
        return ("PaginationConfig(from_tok=%r, to_tok=%r, direction=%r, limit=%r)") % (
            self.from_token,
            self.to_token,
            self.direction,
            self.limit,
        )
