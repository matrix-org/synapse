# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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

from synapse.api.errors import SynapseError, AuthError

from synapse.api.errors import CodeMessageException

from ._base import BaseHandler

import logging


logger = logging.getLogger(__name__)

PREFIX = "/matrix/client/api/v1"


class ProfileHandler(BaseHandler):

    def __init__(self, hs):
        super(ProfileHandler, self).__init__(hs)

        self.client = hs.get_http_client()

        distributor = hs.get_distributor()
        self.distributor = distributor

        distributor.observe("registered_user", self.registered_user)

        distributor.observe(
            "collect_presencelike_data", self.collect_presencelike_data
        )

    def registered_user(self, user):
        self.store.create_profile(user.localpart)

    @defer.inlineCallbacks
    def get_displayname(self, target_user, local_only=False):
        if target_user.is_mine:
            displayname = yield self.store.get_profile_displayname(
                target_user.localpart
            )

            defer.returnValue(displayname)
        elif not local_only:
            # TODO(paul): This should use the server-server API to ask another
            # HS. For now we'll just have it use the http client to talk to the
            # other HS's REST client API
            path = PREFIX + "/profile/%s/displayname?local_only=1" % (
                target_user.to_string()
            )

            try:
                result = yield self.client.get_json(
                    destination=target_user.domain,
                    path=path
                )
            except CodeMessageException as e:
                if e.code != 404:
                    logger.exception("Failed to get displayname")

                raise
            except:
                logger.exception("Failed to get displayname")

            defer.returnValue(result["displayname"])
        else:
            raise SynapseError(400, "User is not hosted on this Home Server")

    @defer.inlineCallbacks
    def set_displayname(self, target_user, auth_user, new_displayname):
        """target_user is the user whose displayname is to be changed;
        auth_user is the user attempting to make this change."""
        if not target_user.is_mine:
            raise SynapseError(400, "User is not hosted on this Home Server")

        if target_user != auth_user:
            raise AuthError(400, "Cannot set another user's displayname")

        yield self.store.set_profile_displayname(
            target_user.localpart, new_displayname
        )

        yield self.distributor.fire(
            "changed_presencelike_data", target_user, {
                "displayname": new_displayname,
            }
        )

    @defer.inlineCallbacks
    def get_avatar_url(self, target_user, local_only=False):
        if target_user.is_mine:
            avatar_url = yield self.store.get_profile_avatar_url(
                target_user.localpart
            )

            defer.returnValue(avatar_url)
        elif not local_only:
            # TODO(paul): This should use the server-server API to ask another
            # HS. For now we'll just have it use the http client to talk to the
            # other HS's REST client API
            destination = target_user.domain
            path = PREFIX + "/profile/%s/avatar_url?local_only=1" % (
                target_user.to_string(),
            )

            try:
                result = yield self.client.get_json(
                    destination=destination,
                    path=path
                )
            except CodeMessageException as e:
                if e.code != 404:
                    logger.exception("Failed to get avatar_url")
                raise
            except:
                logger.exception("Failed to get avatar_url")

            defer.returnValue(result["avatar_url"])
        else:
            raise SynapseError(400, "User is not hosted on this Home Server")

    @defer.inlineCallbacks
    def set_avatar_url(self, target_user, auth_user, new_avatar_url):
        """target_user is the user whose avatar_url is to be changed;
        auth_user is the user attempting to make this change."""
        if not target_user.is_mine:
            raise SynapseError(400, "User is not hosted on this Home Server")

        if target_user != auth_user:
            raise AuthError(400, "Cannot set another user's avatar_url")

        yield self.store.set_profile_avatar_url(
            target_user.localpart, new_avatar_url
        )

        yield self.distributor.fire(
            "changed_presencelike_data", target_user, {
                "avatar_url": new_avatar_url,
            }
        )

    @defer.inlineCallbacks
    def collect_presencelike_data(self, user, state):
        if not user.is_mine:
            defer.returnValue(None)

        (displayname, avatar_url) = yield defer.gatherResults([
            self.store.get_profile_displayname(user.localpart),
            self.store.get_profile_avatar_url(user.localpart),
        ])

        state["displayname"] = displayname
        state["avatar_url"] = avatar_url

        defer.returnValue(None)
