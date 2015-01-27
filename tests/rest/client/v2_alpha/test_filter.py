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

from mock import Mock

from . import V2AlphaRestTestCase

from synapse.rest.client.v2_alpha import filter


class FilterTestCase(V2AlphaRestTestCase):
    USER_ID = "@apple:test"
    TO_REGISTER = [filter]

    def make_datastore_mock(self):
        datastore = super(FilterTestCase, self).make_datastore_mock()

        self._user_filters = {}

        def add_user_filter(user_localpart, definition):
            filters = self._user_filters.setdefault(user_localpart, [])
            filter_id = len(filters)
            filters.append(definition)
            return defer.succeed(filter_id)
        datastore.add_user_filter = add_user_filter

        def get_user_filter(user_localpart, filter_id):
            filters = self._user_filters[user_localpart]
            return defer.succeed(filters[filter_id])
        datastore.get_user_filter = get_user_filter

        return datastore

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
