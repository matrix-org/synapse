# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

from twisted.internet import defer

from . import V2AlphaRestTestCase

from synapse.rest.client.v2_alpha import filter


class FilterTestCase(V2AlphaRestTestCase):
    USER_ID = "@apple:test"
    TO_REGISTER = [filter]

    @defer.inlineCallbacks
    def test_filter(self):
        (code, response) = yield self.mock_resource.trigger("POST",
            "/user/%s/filter" % (self.USER_ID),
            '{"type": ["m.*"]}'
        )
        self.assertEquals(200, code)
        self.assertEquals({"filter_id": "0"}, response)

        (code, response) = yield self.mock_resource.trigger("GET",
            "/user/%s/filter/0" % (self.USER_ID), None
        )
        self.assertEquals(200, code)
        self.assertEquals({"type": ["m.*"]}, response)
