# -*- coding: utf-8 -*-
# Copyright 2018 Will Hunt <will@half-shot.uk>
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
#
from twisted.web.server import NOT_DONE_YET
from twisted.web.resource import Resource
from synapse.http.server import respond_with_json, respond_with_json_bytes


class MediaLimitsResource(Resource):
    isLeaf = True

    def __init__(self, hs):
        Resource.__init__(self)
        self.limits_dict = {}
        config = hs.get_config()
        self.limits_dict["upload_size"] = config.max_upload_size

    def render_GET(self, request):
        respond_with_json(request, 200, self.limits_dict, send_cors=True)
        return NOT_DONE_YET

    def render_OPTIONS(self, request):
        respond_with_json_bytes(request, 200, {}, send_cors=True)
        return NOT_DONE_YET
