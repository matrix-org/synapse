# -*- coding: utf-8 -*-
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

from typing import TYPE_CHECKING

from synapse.http.server import JsonResource
from synapse.rest.internal.client import password_reset

if TYPE_CHECKING:
    from synapse.server import HomeServer


class PasswordResetRestResource(JsonResource):
    """Synapse Internal Resource for password reset functionality

    This resource gets mounted under /_synapse/client
    """

    def __init__(self, hs: "HomeServer"):
        JsonResource.__init__(self, hs, canonical_json=False)
        self.register_servlets(self, hs)

    @staticmethod
    def register_servlets(synapse_client_resource: JsonResource, hs: "HomeServer"):
        password_reset.register_servlets(hs, synapse_client_resource)
