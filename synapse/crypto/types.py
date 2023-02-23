# Copyright 2023- The Matrix.org Foundation C.I.C.
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
from typing import List

import attr


@attr.s(slots=True, frozen=True, auto_attribs=True)
class _FetchKeyRequest:
    """A request for keys for a given server.

    We will continue to try and fetch until we have all the keys listed under
    `key_ids` (with an appropriate `valid_until_ts` property) or we run out of
    places to fetch keys from.

    Attributes:
        server_name: The name of the server that owns the keys.
        minimum_valid_until_ts: The timestamp which the keys must be valid until.
        key_ids: The IDs of the keys to attempt to fetch
    """

    server_name: str
    minimum_valid_until_ts: int
    key_ids: List[str]
