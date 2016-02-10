# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

import synapse.metrics


METRICS_PREFIX = "/_synapse/metrics"


class MetricsResource(Resource):
    isLeaf = True

    def __init__(self, hs):
        Resource.__init__(self)  # Resource is old-style, so no super()

        self.hs = hs

    def render_GET(self, request):
        response = synapse.metrics.render_all()

        request.setHeader("Content-Type", "text/plain")
        request.setHeader("Content-Length", str(len(response)))

        # Encode as UTF-8 (default)
        return response.encode()
