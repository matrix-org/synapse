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
from synapse.api.errors import SynapseError, AuthError, CodeMessageException
from synapse.types import UserID
from ._base import BaseHandler


logger = logging.getLogger(__name__)


class ProfileHandler(BaseHandler):

    def __init__(self, hs):
        super(ProfileHandler, self).__init__(hs)

        self.federation = hs.get_replication_layer()
        self.federation.register_query_handler(
            "profile", self.on_profile_query
        )

    @defer.inlineCallbacks
    def get_displayname(self, target_user):
        if self.hs.is_mine(target_user):
            displayname = yield self.store.get_profile_displayname(
                target_user.localpart
            )

            defer.returnValue(displayname)
        else:
            try:
                result = yield self.federation.make_query(
                    destination=target_user.domain,
                    query_type="profile",
                    args={
                        "user_id": target_user.to_string(),
                        "field": "displayname",
                    }
                )
            except CodeMessageException as e:
                if e.code != 404:
                    logger.exception("Failed to get displayname")

                raise
            except:
                logger.exception("Failed to get displayname")
            else:
                defer.returnValue(result["displayname"])

    @defer.inlineCallbacks
    def set_displayname(self, target_user, requester, new_displayname, by_admin=False):
        """target_user is the user whose displayname is to be changed;
        auth_user is the user attempting to make this change."""
        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "User is not hosted on this Home Server")

        if not by_admin and target_user != requester.user:
            raise AuthError(400, "Cannot set another user's displayname")

        if new_displayname == '':
            new_displayname = None

        old_profile = yield self.store.get_profile(target_user.localpart)

        yield self.store.set_profile_displayname(
            target_user.localpart, new_displayname
        )

        yield self._update_join_states(requester, old_profile)

    @defer.inlineCallbacks
    def get_avatar_url(self, target_user):
        if self.hs.is_mine(target_user):
            avatar_url = yield self.store.get_profile_avatar_url(
                target_user.localpart
            )

            defer.returnValue(avatar_url)
        else:
            try:
                result = yield self.federation.make_query(
                    destination=target_user.domain,
                    query_type="profile",
                    args={
                        "user_id": target_user.to_string(),
                        "field": "avatar_url",
                    }
                )
            except CodeMessageException as e:
                if e.code != 404:
                    logger.exception("Failed to get avatar_url")
                raise
            except:
                logger.exception("Failed to get avatar_url")

            defer.returnValue(result["avatar_url"])

    @defer.inlineCallbacks
    def set_avatar_url(self, target_user, requester, new_avatar_url, by_admin=False):
        """target_user is the user whose avatar_url is to be changed;
        auth_user is the user attempting to make this change."""
        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "User is not hosted on this Home Server")

        if not by_admin and target_user != requester.user:
            raise AuthError(400, "Cannot set another user's avatar_url")

        old_profile = yield self.store.get_profile(target_user.localpart)

        yield self.store.set_profile_avatar_url(
            target_user.localpart, new_avatar_url
        )

        yield self._update_join_states(requester, old_profile)

    @defer.inlineCallbacks
    def on_profile_query(self, args):
        user = UserID.from_string(args["user_id"])
        if not self.hs.is_mine(user):
            raise SynapseError(400, "User is not hosted on this Home Server")

        just_field = args.get("field", None)

        response = {}
        if just_field == "displayname":
            response["displayname"] = yield self.store.get_profile_displayname(
                user.localpart
            )
        elif just_field == "avatar_url":
            response["avatar_url"] = yield self.store.get_profile_avatar_url(
                user.localpart
            )
        else:
            response = yield self.store.get_profile(
                user.localpart
            )

        defer.returnValue(response)

    @defer.inlineCallbacks
    def _update_join_states(self, requester, old_profile):
        user = requester.user
        if not self.hs.is_mine(user):
            return

        self.ratelimit(requester)

        room_ids = yield self.store.get_rooms_for_user(
            user.to_string(),
        )

        for room_id in room_ids:
            handler = self.hs.get_handlers().room_member_handler
            member_event = yield handler.get_member_event(user, room_id)
            # This will be populated by update_membership for missing values.
            content = {

            }
            logger.info("Setting member event for " + room_id)
            if member_event:
                member_content = member_event.content
                # Don't overwrite custom changes to displayname
                if member_content.get("displayname") != old_profile.get("displayname"):
                    logger.info("Ignoring displayname, for '%s'", member_content)
                    content["displayname"] = member_content.get("displayname")
                # Don't overwrite custom changes to avatar_url
                if member_content.get("avatar_url") != old_profile.get("avatar_url"):
                    logger.info("Ignoring avatar_url")
                    content["avatar_url"] = member_content.get("avatar_url")
            try:
                # Assume the user isn't a guest because we don't let guests set
                # profile or avatar data.
                yield handler.update_membership(
                    requester,
                    user,
                    room_id,
                    "join",  # We treat a profile update like a join.
                    ratelimit=False,  # Try to hide that these events aren't atomic.
                    content=content
                )
            except Exception as e:
                logger.warn(
                    "Failed to update join event for room %s - %s",
                    room_id, str(e.message)
                )
