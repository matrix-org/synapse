# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

from . import (
    room, events, register, login, profile, presence, initial_sync, directory,
    voip, admin, pusher, push_rule
)

from synapse.http.server import JsonResource


class ClientV1RestResource(JsonResource):
    """A resource for version 1 of the matrix client API."""

    def __init__(self, hs):
        JsonResource.__init__(self, hs)
        self.register_servlets(self, hs)

    def get_extra_resources(self, hs):
        # some parts of client v1 need to produce HTML as the output (e.g.
        # fallback pages) but we can only produce JSON output. In an effort to
        # keep similar logic close together, we'll call through to any servlet
        # which requires HTML output.
        register_resources = register.get_prefixes_and_resources(hs)
        return register_resources

    @staticmethod
    def register_servlets(client_resource, hs):
        room.register_servlets(hs, client_resource)
        events.register_servlets(hs, client_resource)
        register.register_servlets(hs, client_resource)
        login.register_servlets(hs, client_resource)
        profile.register_servlets(hs, client_resource)
        presence.register_servlets(hs, client_resource)
        initial_sync.register_servlets(hs, client_resource)
        directory.register_servlets(hs, client_resource)
        voip.register_servlets(hs, client_resource)
        admin.register_servlets(hs, client_resource)
        pusher.register_servlets(hs, client_resource)
        push_rule.register_servlets(hs, client_resource)
