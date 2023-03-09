# Copyright 2014-2016 OpenMarket Ltd
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
from typing import AsyncContextManager, Awaitable, Callable, Optional

logger = logging.getLogger(__name__)

ON_UPDATE_CALLBACK = Callable[[str, str, bool], AsyncContextManager[int]]
DEFAULT_BATCH_SIZE_CALLBACK = Callable[[str, str], Awaitable[int]]
MIN_BATCH_SIZE_CALLBACK = Callable[[str, str], Awaitable[int]]


class BackgroundUpdaterModuleApiCallbacks:
    def __init__(self) -> None:
        self.on_update_callback: Optional[ON_UPDATE_CALLBACK] = None
        self.default_batch_size_callback: Optional[DEFAULT_BATCH_SIZE_CALLBACK] = None
        self.min_batch_size_callback: Optional[MIN_BATCH_SIZE_CALLBACK] = None

    def register_callbacks(
        self,
        on_update: ON_UPDATE_CALLBACK,
        default_batch_size: Optional[DEFAULT_BATCH_SIZE_CALLBACK] = None,
        min_batch_size: Optional[DEFAULT_BATCH_SIZE_CALLBACK] = None,
    ) -> None:
        """Register callbacks from a module for each hook."""
        if self.on_update_callback is not None:
            logger.warning(
                "More than one module tried to register callbacks for controlling"
                " background updates. Only the callbacks registered by the first module"
                " (in order of appearance in Synapse's configuration file) that tried to"
                " do so will be called."
            )

            return

        self.on_update_callback = on_update

        if default_batch_size is not None:
            self.default_batch_size_callback = default_batch_size

        if min_batch_size is not None:
            self.min_batch_size_callback = min_batch_size
