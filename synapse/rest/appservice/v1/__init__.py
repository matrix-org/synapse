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
from . import register

from synapse.http.server import JsonResource


class AppServiceRestResource(JsonResource):
    """A resource for version 1 of the matrix application service API."""

    def __init__(self, hs):
        JsonResource.__init__(self, hs)
        self.register_servlets(self, hs)

    @staticmethod
    def register_servlets(appservice_resource, hs):
        register.register_servlets(hs, appservice_resource)
