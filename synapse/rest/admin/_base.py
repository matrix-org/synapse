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
from twisted.internet import defer

from synapse.api.errors import AuthError


@defer.inlineCallbacks
def assert_requester_is_admin(auth, request):
    """Verify that the requester is an admin user

    WARNING: MAKE SURE YOU YIELD ON THE RESULT!

    Args:
        auth (synapse.api.auth.Auth):
        request (twisted.web.server.Request): incoming request

    Returns:
        Deferred

    Raises:
        AuthError if the requester is not an admin
    """
    requester = yield auth.get_user_by_req(request)
    yield assert_user_is_admin(auth, requester.user)


@defer.inlineCallbacks
def assert_user_is_admin(auth, user_id):
    """Verify that the given user is an admin user

    WARNING: MAKE SURE YOU YIELD ON THE RESULT!

    Args:
        auth (synapse.api.auth.Auth):
        user_id (UserID):

    Returns:
        Deferred

    Raises:
        AuthError if the user is not an admin
    """

    is_admin = yield auth.is_server_admin(user_id)
    if not is_admin:
        raise AuthError(403, "You are not a server admin")
