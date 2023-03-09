# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2021, 2023 The Matrix.org Foundation C.I.C.
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
from typing import Awaitable, Callable, List, Optional

from synapse.types import JsonDict

ON_ACCOUNT_DATA_UPDATED_CALLBACK = Callable[
    [str, Optional[str], str, JsonDict], Awaitable
]


class AccountDataModuleApiCallbacks:
    def __init__(self) -> None:
        self.on_account_data_updated_callbacks: List[
            ON_ACCOUNT_DATA_UPDATED_CALLBACK
        ] = []

    def register_callbacks(
        self, on_account_data_updated: Optional[ON_ACCOUNT_DATA_UPDATED_CALLBACK] = None
    ) -> None:
        """Register callbacks from modules."""
        if on_account_data_updated is not None:
            self.on_account_data_updated_callbacks.append(on_account_data_updated)
