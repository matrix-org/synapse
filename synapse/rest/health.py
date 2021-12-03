# Copyright 2020 The Matrix.org Foundation C.I.C.
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
from twisted.web.server import Request


class HealthResource(Resource):
    """A resource that does nothing except return a 200 with a body of `OK`,
    which can be used as a health check.

    Note: `SynapseRequest._should_log_request` ensures that requests to
    `/health` do not get logged at INFO.
    """

    isLeaf = 1

    def render_GET(self, request: Request) -> bytes:
        request.setHeader(b"Content-Type", b"text/plain")
        return b"OK"
