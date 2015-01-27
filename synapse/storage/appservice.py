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

from synapse.api.errors import StoreError

from ._base import SQLBaseStore


class ApplicationServiceStore(SQLBaseStore):

    def __init__(self, hs):
        super(ApplicationServiceStore, self).__init__(hs)

        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    def get_app_service(self, as_token):
        """Get the application service with the given token.

        Args:
            token (str): The application service token.
        Raises:
            StoreError if there was a problem retrieving this.
        """
        row = self._simple_select_one(
            "application_services", {"token": as_token},
            ["url", "token"]
        )
        if not row:
            raise StoreError(400, "Bad application services token supplied.")
        defer.returnValue(row)
