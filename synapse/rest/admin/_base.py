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

import re

import twisted.web.server

import synapse.api.auth
from synapse.api.errors import AuthError
from synapse.types import UserID


def admin_patterns(path_regex: str, version: str = "v1"):
    """Returns the list of patterns for an admin endpoint

    Args:
        path_regex: The regex string to match. This should NOT have a ^
            as this will be prefixed.

    Returns:
        A list of regex patterns.
    """
    admin_prefix = "^/_synapse/admin/" + version
    patterns = [re.compile(admin_prefix + path_regex)]
    return patterns


async def assert_requester_is_admin(
    auth: synapse.api.auth.Auth, request: twisted.web.server.Request
) -> None:
    """Verify that the requester is an admin user

    Args:
        auth: api.auth.Auth singleton
        request: incoming request

    Raises:
        AuthError if the requester is not a server admin
    """
    requester = await auth.get_user_by_req(request)
    await assert_user_is_admin(auth, requester.user)


async def assert_user_is_admin(auth: synapse.api.auth.Auth, user_id: UserID) -> None:
    """Verify that the given user is an admin user

    Args:
        auth: api.auth.Auth singleton
        user_id: user to check

    Raises:
        AuthError if the user is not a server admin
    """
    is_admin = await auth.is_server_admin(user_id)
    if not is_admin:
        raise AuthError(403, "You are not a server admin")
