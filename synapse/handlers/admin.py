# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

from twisted.internet import defer

from ._base import BaseHandler

logger = logging.getLogger(__name__)


class AdminHandler(BaseHandler):

    def __init__(self, hs):
        super(AdminHandler, self).__init__(hs)

    @defer.inlineCallbacks
    def get_whois(self, user):
        connections = []

        sessions = yield self.store.get_user_ip_and_agents(user)
        for session in sessions:
            connections.append({
                "ip": session["ip"],
                "last_seen": session["last_seen"],
                "user_agent": session["user_agent"],
            })

        ret = {
            "user_id": user.to_string(),
            "devices": {
                "": {
                    "sessions": [
                        {
                            "connections": connections,
                        }
                    ]
                },
            },
        }

        defer.returnValue(ret)

    @defer.inlineCallbacks
    def get_users(self):
        """Function to reterive a list of users in users table.

        Args:
        Returns:
            defer.Deferred: resolves to list[dict[str, Any]]
        """
        ret = yield self.store.get_users()

        defer.returnValue(ret)

    @defer.inlineCallbacks
    def get_users_paginate(self, order, start, limit):
        """Function to reterive a paginated list of users from
        users list. This will return a json object, which contains
        list of users and the total number of users in users table.

        Args:
            order (str): column name to order the select by this column
            start (int): start number to begin the query from
            limit (int): number of rows to reterive
        Returns:
            defer.Deferred: resolves to json object {list[dict[str, Any]], count}
        """
        ret = yield self.store.get_users_paginate(order, start, limit)

        defer.returnValue(ret)

    @defer.inlineCallbacks
    def search_users(self, term):
        """Function to search users list for one or more users with
        the matched term.

        Args:
            term (str): search term
        Returns:
            defer.Deferred: resolves to list[dict[str, Any]]
        """
        ret = yield self.store.search_users(term)

        defer.returnValue(ret)
