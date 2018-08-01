# -*- coding: utf-8 -*-
# Copyright 2017 New Vector Ltd
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

from synapse.types import UserID


class ModuleApi(object):
    """A proxy object that gets passed to password auth providers so they
    can register new users etc if necessary.
    """
    def __init__(self, hs, auth_handler):
        self.hs = hs

        self._store = hs.get_datastore()
        self._auth = hs.get_auth()
        self._auth_handler = auth_handler

    def get_user_by_req(self, req, allow_guest=False):
        """Check the access_token provided for a request

        Args:
            req (twisted.web.server.Request): Incoming HTTP request
            allow_guest (bool): True if guest users should be allowed. If this
                is False, and the access token is for a guest user, an
                AuthError will be thrown
        Returns:
            twisted.internet.defer.Deferred[synapse.types.Requester]:
                the requester for this request
        Raises:
            synapse.api.errors.AuthError: if no user by that token exists,
                or the token is invalid.
        """
        return self._auth.get_user_by_req(req, allow_guest)

    def get_qualified_user_id(self, username):
        """Qualify a user id, if necessary

        Takes a user id provided by the user and adds the @ and :domain to
        qualify it, if necessary

        Args:
            username (str): provided user id

        Returns:
            str: qualified @user:id
        """
        if username.startswith('@'):
            return username
        return UserID(username, self.hs.hostname).to_string()

    def check_user_exists(self, user_id):
        """Check if user exists.

        Args:
            user_id (str): Complete @user:id

        Returns:
            Deferred[str|None]: Canonical (case-corrected) user_id, or None
               if the user is not registered.
        """
        return self._auth_handler.check_user_exists(user_id)

    def register(self, localpart):
        """Registers a new user with given localpart

        Returns:
            Deferred: a 2-tuple of (user_id, access_token)
        """
        reg = self.hs.get_handlers().registration_handler
        return reg.register(localpart=localpart)

    @defer.inlineCallbacks
    def invalidate_access_token(self, access_token):
        """Invalidate an access token for a user

        Args:
            access_token(str): access token

        Returns:
            twisted.internet.defer.Deferred - resolves once the access token
               has been removed.

        Raises:
            synapse.api.errors.AuthError: the access token is invalid
        """
        # see if the access token corresponds to a device
        user_info = yield self._auth.get_user_by_access_token(access_token)
        device_id = user_info.get("device_id")
        user_id = user_info["user"].to_string()
        if device_id:
            # delete the device, which will also delete its access tokens
            yield self.hs.get_device_handler().delete_device(user_id, device_id)
        else:
            # no associated device. Just delete the access token.
            yield self._auth_handler.delete_access_token(access_token)

    def run_db_interaction(self, desc, func, *args, **kwargs):
        """Run a function with a database connection

        Args:
            desc (str): description for the transaction, for metrics etc
            func (func): function to be run. Passed a database cursor object
                as well as *args and **kwargs
            *args: positional args to be passed to func
            **kwargs: named args to be passed to func

        Returns:
            Deferred[object]: result of func
        """
        return self._store.runInteraction(desc, func, *args, **kwargs)
