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

import synapse.types
from synapse.api.errors import SynapseError, AuthError, CodeMessageException
from synapse.types import UserID, get_domain_from_id
from ._base import BaseHandler

logger = logging.getLogger(__name__)


class ProfileHandler(BaseHandler):
    PROFILE_UPDATE_MS = 60 * 1000
    PROFILE_UPDATE_EVERY_MS = 24 * 60 * 60 * 1000

    def __init__(self, hs):
        super(ProfileHandler, self).__init__(hs)

        self.federation = hs.get_replication_layer()
        self.federation.register_query_handler(
            "profile", self.on_profile_query
        )

        self.clock.looping_call(self._update_remote_profile_cache, self.PROFILE_UPDATE_MS)

    @defer.inlineCallbacks
    def get_profile(self, user_id):
        target_user = UserID.from_string(user_id)
        if self.hs.is_mine(target_user):
            displayname = yield self.store.get_profile_displayname(
                target_user.localpart
            )
            avatar_url = yield self.store.get_profile_avatar_url(
                target_user.localpart
            )

            defer.returnValue({
                "displayname": displayname,
                "avatar_url": avatar_url,
            })
        else:
            try:
                result = yield self.federation.make_query(
                    destination=target_user.domain,
                    query_type="profile",
                    args={
                        "user_id": user_id,
                    },
                    ignore_backoff=True,
                )
                defer.returnValue(result)
            except CodeMessageException as e:
                if e.code != 404:
                    logger.exception("Failed to get displayname")

                raise

    @defer.inlineCallbacks
    def get_profile_from_cache(self, user_id):
        """Get the profile information from our local cache. If the user is
        ours then the profile information will always be corect. Otherwise,
        it may be out of date/missing.
        """
        target_user = UserID.from_string(user_id)
        if self.hs.is_mine(target_user):
            displayname = yield self.store.get_profile_displayname(
                target_user.localpart
            )
            avatar_url = yield self.store.get_profile_avatar_url(
                target_user.localpart
            )

            defer.returnValue({
                "displayname": displayname,
                "avatar_url": avatar_url,
            })
        else:
            profile = yield self.store.get_from_remote_profile_cache(user_id)
            defer.returnValue(profile or {})

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
                    },
                    ignore_backoff=True,
                )
            except CodeMessageException as e:
                if e.code != 404:
                    logger.exception("Failed to get displayname")

                raise
            except Exception:
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

        yield self.store.set_profile_displayname(
            target_user.localpart, new_displayname
        )

        yield self._update_join_states(requester)

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
                    },
                    ignore_backoff=True,
                )
            except CodeMessageException as e:
                if e.code != 404:
                    logger.exception("Failed to get avatar_url")
                raise
            except Exception:
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

        yield self.store.set_profile_avatar_url(
            target_user.localpart, new_avatar_url
        )

        yield self._update_join_states(requester)

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
    def _update_join_states(self, requester):
        user = requester.user
        if not self.hs.is_mine(user):
            return

        yield self.ratelimit(requester)

        room_ids = yield self.store.get_rooms_for_user(
            user.to_string(),
        )

        for room_id in room_ids:
            handler = self.hs.get_handlers().room_member_handler
            try:
                # Assume the user isn't a guest because we don't let guests set
                # profile or avatar data.
                # XXX why are we recreating `requester` here for each room?
                # what was wrong with the `requester` we were passed?
                requester = synapse.types.create_requester(user)
                yield handler.update_membership(
                    requester,
                    user,
                    room_id,
                    "join",  # We treat a profile update like a join.
                    ratelimit=False,  # Try to hide that these events aren't atomic.
                )
            except Exception as e:
                logger.warn(
                    "Failed to update join event for room %s - %s",
                    room_id, str(e.message)
                )

    def _update_remote_profile_cache(self):
        """Called periodically to check profiles of remote users we haven't
        checked in a while.
        """
        entries = yield self.store.get_remote_profile_cache_entries_that_expire(
            last_checked=self.clock.time_msec() - self.PROFILE_UPDATE_EVERY_MS
        )

        for user_id, displayname, avatar_url in entries:
            is_subscribed = yield self.store.is_subscribed_remote_profile_for_user(
                user_id,
            )
            if not is_subscribed:
                yield self.store.maybe_delete_remote_profile_cache(user_id)
                continue

            try:
                profile = yield self.federation.make_query(
                    destination=get_domain_from_id(user_id),
                    query_type="profile",
                    args={
                        "user_id": user_id,
                    },
                    ignore_backoff=True,
                )
            except Exception:
                logger.exception("Failed to get avatar_url")

                yield self.store.update_remote_profile_cache(
                    user_id, displayname, avatar_url
                )
                continue

            new_name = profile.get("displayname")
            new_avatar = profile.get("avatar_url")

            # We always hit update to update the last_check timestamp
            yield self.store.update_remote_profile_cache(
                user_id, new_name, new_avatar
            )
