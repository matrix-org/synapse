# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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

from synapse.http.server import JsonResource
from synapse.replication.http import federation, login, membership, register, send_event

REPLICATION_PREFIX = "/_synapse/replication"


class ReplicationRestResource(JsonResource):
    def __init__(self, hs):
        JsonResource.__init__(self, hs, canonical_json=False)
        self.register_servlets(hs)

    def register_servlets(self, hs):
        send_event.register_servlets(hs, self)
        membership.register_servlets(hs, self)
        federation.register_servlets(hs, self)
        login.register_servlets(hs, self)
        register.register_servlets(hs, self)
