# -*- coding: utf-8 -*-
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

from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET

from synapse.http.server import wrap_json_request_handler


class AdditionalResource(Resource):
    """Resource wrapper for additional_resources

    If the user has configured additional_resources, we need to wrap the
    handler class with a Resource so that we can map it into the resource tree.

    This class is also where we wrap the request handler with logging, metrics,
    and exception handling.
    """

    def __init__(self, hs, handler):
        """Initialise AdditionalResource

        The ``handler`` should return a deferred which completes when it has
        done handling the request. It should write a response with
        ``request.write()``, and call ``request.finish()``.

        Args:
            hs (synapse.server.HomeServer): homeserver
            handler ((twisted.web.server.Request) -> twisted.internet.defer.Deferred):
                function to be called to handle the request.
        """
        Resource.__init__(self)
        self._handler = handler

        # required by the request_handler wrapper
        self.clock = hs.get_clock()

    def render(self, request):
        self._async_render(request)
        return NOT_DONE_YET

    @wrap_json_request_handler
    def _async_render(self, request):
        return self._handler(request)
