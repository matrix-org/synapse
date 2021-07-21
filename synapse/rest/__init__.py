# Copyright 2014-2016 OpenMarket Ltd
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
from synapse.rest import admin
from synapse.rest.client import versions
from synapse.rest.client.v1 import (
    directory,
    events,
    initial_sync,
    login as v1_login,
    logout,
    presence,
    profile,
    push_rule,
    pusher,
    room,
    voip,
)
from synapse.rest.client.v2_alpha import (
    account,
    account_data,
    account_validity,
    auth,
    capabilities,
    devices,
    filter,
    groups,
    keys,
    knock,
    notifications,
    openid,
    password_policy,
    read_marker,
    receipts,
    register,
    relations,
    report_event,
    room_keys,
    room_upgrade_rest_servlet,
    sendtodevice,
    shared_rooms,
    sync,
    tags,
    thirdparty,
    tokenrefresh,
    user_directory,
)


class ClientRestResource(JsonResource):
    """Matrix Client API REST resource.

    This gets mounted at various points under /_matrix/client, including:
       * /_matrix/client/r0
       * /_matrix/client/api/v1
       * /_matrix/client/unstable
       * etc
    """

    def __init__(self, hs):
        JsonResource.__init__(self, hs, canonical_json=False)
        self.register_servlets(self, hs)

    @staticmethod
    def register_servlets(client_resource, hs):
        versions.register_servlets(hs, client_resource)

        # Deprecated in r0
        initial_sync.register_servlets(hs, client_resource)
        room.register_deprecated_servlets(hs, client_resource)

        # Partially deprecated in r0
        events.register_servlets(hs, client_resource)

        # "v1" + "r0"
        room.register_servlets(hs, client_resource)
        v1_login.register_servlets(hs, client_resource)
        profile.register_servlets(hs, client_resource)
        presence.register_servlets(hs, client_resource)
        directory.register_servlets(hs, client_resource)
        voip.register_servlets(hs, client_resource)
        pusher.register_servlets(hs, client_resource)
        push_rule.register_servlets(hs, client_resource)
        logout.register_servlets(hs, client_resource)

        # "v2"
        sync.register_servlets(hs, client_resource)
        filter.register_servlets(hs, client_resource)
        account.register_servlets(hs, client_resource)
        register.register_servlets(hs, client_resource)
        auth.register_servlets(hs, client_resource)
        receipts.register_servlets(hs, client_resource)
        read_marker.register_servlets(hs, client_resource)
        room_keys.register_servlets(hs, client_resource)
        keys.register_servlets(hs, client_resource)
        tokenrefresh.register_servlets(hs, client_resource)
        tags.register_servlets(hs, client_resource)
        account_data.register_servlets(hs, client_resource)
        report_event.register_servlets(hs, client_resource)
        openid.register_servlets(hs, client_resource)
        notifications.register_servlets(hs, client_resource)
        devices.register_servlets(hs, client_resource)
        thirdparty.register_servlets(hs, client_resource)
        sendtodevice.register_servlets(hs, client_resource)
        user_directory.register_servlets(hs, client_resource)
        groups.register_servlets(hs, client_resource)
        room_upgrade_rest_servlet.register_servlets(hs, client_resource)
        capabilities.register_servlets(hs, client_resource)
        account_validity.register_servlets(hs, client_resource)
        relations.register_servlets(hs, client_resource)
        password_policy.register_servlets(hs, client_resource)
        knock.register_servlets(hs, client_resource)

        # moving to /_synapse/admin
        admin.register_servlets_for_client_rest_resource(hs, client_resource)

        # unstable
        shared_rooms.register_servlets(hs, client_resource)
