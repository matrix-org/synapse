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
from typing import Awaitable, Callable, List, Optional, Tuple

from synapse.types import PublicRoom, ThirdPartyInstanceID

logger = logging.getLogger(__name__)


# Types for callbacks to be registered via the module api
FETCH_PUBLIC_ROOMS_CALLBACK = Callable[
    [
        Optional[ThirdPartyInstanceID],  # network_tuple
        Optional[dict],  # search_filter
        Optional[int],  # limit
        Tuple[Optional[int], Optional[str]],  # bounds
        bool,  # forwards
    ],
    Awaitable[List[PublicRoom]],
]


class PublicRoomsModuleApiCallbacks:
    def __init__(self) -> None:
        self.fetch_public_rooms_callbacks: List[FETCH_PUBLIC_ROOMS_CALLBACK] = []

    def register_callbacks(
        self,
        fetch_public_rooms: Optional[FETCH_PUBLIC_ROOMS_CALLBACK] = None,
    ) -> None:
        if fetch_public_rooms is not None:
            self.fetch_public_rooms_callbacks.append(fetch_public_rooms)
