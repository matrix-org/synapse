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

from typing import TYPE_CHECKING

from synapse.http.server import JsonResource
from synapse.replication.http import (
    account_data,
    devices,
    federation,
    login,
    membership,
    presence,
    push,
    register,
    send_event,
    state,
    streams,
)

if TYPE_CHECKING:
    from synapse.server import HomeServer

REPLICATION_PREFIX = "/_synapse/replication"


class ReplicationRestResource(JsonResource):
    def __init__(self, hs: "HomeServer"):
        # We enable extracting jaeger contexts here as these are internal APIs.
        super().__init__(hs, canonical_json=False, extract_context=True)
        self.register_servlets(hs)

    def register_servlets(self, hs: "HomeServer") -> None:
        send_event.register_servlets(hs, self)
        federation.register_servlets(hs, self)
        presence.register_servlets(hs, self)
        membership.register_servlets(hs, self)
        streams.register_servlets(hs, self)
        account_data.register_servlets(hs, self)
        push.register_servlets(hs, self)
        state.register_servlets(hs, self)

        # The following can't currently be instantiated on workers.
        if hs.config.worker.worker_app is None:
            login.register_servlets(hs, self)
            register.register_servlets(hs, self)
            devices.register_servlets(hs, self)
