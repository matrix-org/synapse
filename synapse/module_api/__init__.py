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

from synapse.types import UserID


class ModuleApi(object):
    """A proxy object that gets passed to password auth providers so they
    can register new users etc if necessary.
    """
    def __init__(self, hs, auth_handler):
        self.hs = hs

        self._store = hs.get_datastore()
        self._auth_handler = auth_handler

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
