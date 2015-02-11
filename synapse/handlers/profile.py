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

from twisted.internet import defer

from synapse.api.errors import SynapseError, AuthError, CodeMessageException
from synapse.api.constants import EventTypes, Membership
from synapse.util.logcontext import PreserveLoggingContext
from synapse.types import UserID

from ._base import BaseHandler

import logging


logger = logging.getLogger(__name__)


class ProfileHandler(BaseHandler):

    def __init__(self, hs):
        super(ProfileHandler, self).__init__(hs)

        self.federation = hs.get_replication_layer()
        self.federation.register_query_handler(
            "profile", self.on_profile_query
        )

        distributor = hs.get_distributor()
        self.distributor = distributor

        distributor.observe("registered_user", self.registered_user)

        distributor.observe(
            "collect_presencelike_data", self.collect_presencelike_data
        )

    def registered_user(self, user):
        return self.store.create_profile(user.localpart)

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
    def set_displayname(self, target_user, auth_user, new_displayname):
        """target_user is the user whose displayname is to be changed;
        auth_user is the user attempting to make this change."""
        if not self.hs.is_mine(target_user):
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

        yield self._update_join_states(target_user)

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
    def set_avatar_url(self, target_user, auth_user, new_avatar_url):
        """target_user is the user whose avatar_url is to be changed;
        auth_user is the user attempting to make this change."""
        if not self.hs.is_mine(target_user):
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

        yield self._update_join_states(target_user)

    @defer.inlineCallbacks
    def collect_presencelike_data(self, user, state):
        if not self.hs.is_mine(user):
            defer.returnValue(None)

        with PreserveLoggingContext():
            (displayname, avatar_url) = yield defer.gatherResults(
                [
                    self.store.get_profile_displayname(user.localpart),
                    self.store.get_profile_avatar_url(user.localpart),
                ],
                consumeErrors=True
            )

        state["displayname"] = displayname
        state["avatar_url"] = avatar_url

        defer.returnValue(None)

    @defer.inlineCallbacks
    def on_profile_query(self, args):
        user = UserID.from_string(args["user_id"])
        if not self.hs.is_mine(user):
            raise SynapseError(400, "User is not hosted on this Home Server")

        just_field = args.get("field", None)

        response = {}

        if just_field is None or just_field == "displayname":
            response["displayname"] = yield self.store.get_profile_displayname(
                user.localpart
            )

        if just_field is None or just_field == "avatar_url":
            response["avatar_url"] = yield self.store.get_profile_avatar_url(
                user.localpart
            )

        defer.returnValue(response)

    @defer.inlineCallbacks
    def _update_join_states(self, user):
        if not self.hs.is_mine(user):
            return

        self.ratelimit(user.to_string())

        joins = yield self.store.get_rooms_for_user_where_membership_is(
            user.to_string(),
            [Membership.JOIN],
        )

        for j in joins:
            content = {
                "membership": Membership.JOIN,
            }

            yield self.distributor.fire(
                "collect_presencelike_data", user, content
            )

            msg_handler = self.hs.get_handlers().message_handler
            yield msg_handler.create_and_send_event({
                "type": EventTypes.Member,
                "room_id": j.room_id,
                "state_key": user.to_string(),
                "content": content,
                "sender": user.to_string()
            }, ratelimit=False)
