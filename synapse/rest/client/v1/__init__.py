# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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
from synapse.http.servlet import RestServlet
from synapse.rest.client.v2_alpha._base import client_patterns


class ClientServlet(RestServlet):
    @classmethod
    def _decorated_pattern(cls, pattern, **kwargs):
        kwargs.setdefault("add_stopper", True)

        return client_patterns(pattern, **kwargs)
