# Copyright 2017 New Vector Ltd
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

from typing import TYPE_CHECKING, Any, Awaitable, Callable, Optional, Tuple

from twisted.web.server import Request

from synapse.http.server import DirectServeJsonResource

if TYPE_CHECKING:
    from synapse.server import HomeServer


class AdditionalResource(DirectServeJsonResource):
    """Resource wrapper for additional_resources

    If the user has configured additional_resources, we need to wrap the
    handler class with a Resource so that we can map it into the resource tree.

    This class is also where we wrap the request handler with logging, metrics,
    and exception handling.
    """

    def __init__(
        self,
        hs: "HomeServer",
        handler: Callable[[Request], Awaitable[Optional[Tuple[int, Any]]]],
    ):
        """Initialise AdditionalResource

        The ``handler`` should return a deferred which completes when it has
        done handling the request. It should write a response with
        ``request.write()``, and call ``request.finish()``.

        Args:
            hs: homeserver
            handler ((twisted.web.server.Request) -> twisted.internet.defer.Deferred):
                function to be called to handle the request.
        """
        super().__init__()
        self._handler = handler

    async def _async_render(self, request: Request) -> Optional[Tuple[int, Any]]:
        # Cheekily pass the result straight through, so we don't need to worry
        # if its an awaitable or not.
        return await self._handler(request)
