# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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

import logging

from synapse.http.servlet import parse_json_object_from_request
from synapse.replication.http._base import ReplicationEndpoint

logger = logging.getLogger(__name__)


class ReplicationRegisterServlet(ReplicationEndpoint):
    """Register a new user"""

    NAME = "register_user"
    PATH_ARGS = ("user_id",)

    def __init__(self, hs):
        super().__init__(hs)
        self.store = hs.get_datastore()
        self.registration_handler = hs.get_registration_handler()

    @staticmethod
    async def _serialize_payload(
        user_id,
        password_hash,
        was_guest,
        make_guest,
        appservice_id,
        create_profile_with_displayname,
        admin,
        user_type,
        address,
        shadow_banned,
    ):
        """
        Args:
            user_id (str): The desired user ID to register.
            password_hash (str|None): Optional. The password hash for this user.
            was_guest (bool): Optional. Whether this is a guest account being
                upgraded to a non-guest account.
            make_guest (boolean): True if the the new user should be guest,
                false to add a regular user account.
            appservice_id (str|None): The ID of the appservice registering the user.
            create_profile_with_displayname (unicode|None): Optionally create a
                profile for the user, setting their displayname to the given value
            admin (boolean): is an admin user?
            user_type (str|None): type of user. One of the values from
                api.constants.UserTypes, or None for a normal user.
            address (str|None): the IP address used to perform the regitration.
            shadow_banned (bool): Whether to shadow-ban the user
        """
        return {
            "password_hash": password_hash,
            "was_guest": was_guest,
            "make_guest": make_guest,
            "appservice_id": appservice_id,
            "create_profile_with_displayname": create_profile_with_displayname,
            "admin": admin,
            "user_type": user_type,
            "address": address,
            "shadow_banned": shadow_banned,
        }

    async def _handle_request(self, request, user_id):
        content = parse_json_object_from_request(request)

        self.registration_handler.check_registration_ratelimit(content["address"])

        await self.registration_handler.register_with_store(
            user_id=user_id,
            password_hash=content["password_hash"],
            was_guest=content["was_guest"],
            make_guest=content["make_guest"],
            appservice_id=content["appservice_id"],
            create_profile_with_displayname=content["create_profile_with_displayname"],
            admin=content["admin"],
            user_type=content["user_type"],
            address=content["address"],
            shadow_banned=content["shadow_banned"],
        )

        return 200, {}


class ReplicationPostRegisterActionsServlet(ReplicationEndpoint):
    """Run any post registration actions"""

    NAME = "post_register"
    PATH_ARGS = ("user_id",)

    def __init__(self, hs):
        super().__init__(hs)
        self.store = hs.get_datastore()
        self.registration_handler = hs.get_registration_handler()

    @staticmethod
    async def _serialize_payload(user_id, auth_result, access_token):
        """
        Args:
            user_id (str): The user ID that consented
            auth_result (dict): The authenticated credentials of the newly
                registered user.
            access_token (str|None): The access token of the newly logged in
                device, or None if `inhibit_login` enabled.
        """
        return {"auth_result": auth_result, "access_token": access_token}

    async def _handle_request(self, request, user_id):
        content = parse_json_object_from_request(request)

        auth_result = content["auth_result"]
        access_token = content["access_token"]

        await self.registration_handler.post_registration_actions(
            user_id=user_id, auth_result=auth_result, access_token=access_token
        )

        return 200, {}


def register_servlets(hs, http_server):
    ReplicationRegisterServlet(hs).register(http_server)
    ReplicationPostRegisterActionsServlet(hs).register(http_server)
