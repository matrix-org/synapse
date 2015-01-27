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

from ._base import BaseHandler
from synapse.api.errors import StoreError, SynapseError

import logging


logger = logging.getLogger(__name__)


class ApplicationServicesHandler(BaseHandler):

    def __init__(self, hs):
        super(ApplicationServicesHandler, self).__init__(hs)

    @defer.inlineCallbacks
    def register(self, base_url, token, namespaces):
        # check the token is recognised
        try:
            app_service = yield self.store.get_app_service(token)
            if not app_service:
                raise StoreError
        except StoreError:
            raise SynapseError(
                403, "Unrecognised application services token. "
                "Consult the home server admin."
            )

        # update AS entry with base URL

        # store namespaces for this AS

        defer.returnValue("not_implemented_yet")
