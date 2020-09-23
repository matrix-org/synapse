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
import random

from synapse.api.errors import (
    AuthError,
    Codes,
    HttpResponseException,
    RequestSendFailed,
    StoreError,
    SynapseError,
)
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.types import UserID, create_requester, get_domain_from_id

from ._base import BaseHandler

logger = logging.getLogger(__name__)

MAX_DISPLAYNAME_LEN = 256
MAX_AVATAR_URL_LEN = 1000


class BaseProfileHandler(BaseHandler):
    """Handles fetching and updating user profile information.

    BaseProfileHandler can be instantiated directly on workers and will
    delegate to master when necessary. The master process should use the
    subclass MasterProfileHandler
    """

    def __init__(self, hs):
        super().__init__(hs)

        self.federation = hs.get_federation_client()
        hs.get_federation_registry().register_query_handler(
            "profile", self.on_profile_query
        )

        self.user_directory_handler = hs.get_user_directory_handler()

    async def get_profile(self, user_id):
        target_user = UserID.from_string(user_id)

        if self.hs.is_mine(target_user):
            try:
                displayname = await self.store.get_profile_displayname(
                    target_user.localpart
                )
                avatar_url = await self.store.get_profile_avatar_url(
                    target_user.localpart
                )
            except StoreError as e:
                if e.code == 404:
                    raise SynapseError(404, "Profile was not found", Codes.NOT_FOUND)
                raise

            return {"displayname": displayname, "avatar_url": avatar_url}
        else:
            try:
                result = await self.federation.make_query(
                    destination=target_user.domain,
                    query_type="profile",
                    args={"user_id": user_id},
                    ignore_backoff=True,
                )
                return result
            except RequestSendFailed as e:
                raise SynapseError(502, "Failed to fetch profile") from e
            except HttpResponseException as e:
                raise e.to_synapse_error()

    async def get_profile_from_cache(self, user_id):
        """Get the profile information from our local cache. If the user is
        ours then the profile information will always be corect. Otherwise,
        it may be out of date/missing.
        """
        target_user = UserID.from_string(user_id)
        if self.hs.is_mine(target_user):
            try:
                displayname = await self.store.get_profile_displayname(
                    target_user.localpart
                )
                avatar_url = await self.store.get_profile_avatar_url(
                    target_user.localpart
                )
            except StoreError as e:
                if e.code == 404:
                    raise SynapseError(404, "Profile was not found", Codes.NOT_FOUND)
                raise

            return {"displayname": displayname, "avatar_url": avatar_url}
        else:
            profile = await self.store.get_from_remote_profile_cache(user_id)
            return profile or {}

    async def get_displayname(self, target_user):
        if self.hs.is_mine(target_user):
            try:
                displayname = await self.store.get_profile_displayname(
                    target_user.localpart
                )
            except StoreError as e:
                if e.code == 404:
                    raise SynapseError(404, "Profile was not found", Codes.NOT_FOUND)
                raise

            return displayname
        else:
            try:
                result = await self.federation.make_query(
                    destination=target_user.domain,
                    query_type="profile",
                    args={"user_id": target_user.to_string(), "field": "displayname"},
                    ignore_backoff=True,
                )
            except RequestSendFailed as e:
                raise SynapseError(502, "Failed to fetch profile") from e
            except HttpResponseException as e:
                raise e.to_synapse_error()

            return result["displayname"]

    async def set_displayname(
        self, target_user, requester, new_displayname, by_admin=False
    ):
        """Set the displayname of a user

        Args:
            target_user (UserID): the user whose displayname is to be changed.
            requester (Requester): The user attempting to make this change.
            new_displayname (str): The displayname to give this user.
            by_admin (bool): Whether this change was made by an administrator.
        """
        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "User is not hosted on this homeserver")

        if not by_admin and target_user != requester.user:
            raise AuthError(400, "Cannot set another user's displayname")

        if not by_admin and not self.hs.config.enable_set_displayname:
            profile = await self.store.get_profileinfo(target_user.localpart)
            if profile.display_name:
                raise SynapseError(
                    400,
                    "Changing display name is disabled on this server",
                    Codes.FORBIDDEN,
                )

        if not isinstance(new_displayname, str):
            raise SynapseError(400, "Invalid displayname")

        if len(new_displayname) > MAX_DISPLAYNAME_LEN:
            raise SynapseError(
                400, "Displayname is too long (max %i)" % (MAX_DISPLAYNAME_LEN,)
            )

        if new_displayname == "":
            new_displayname = None

        # If the admin changes the display name of a user, the requesting user cannot send
        # the join event to update the displayname in the rooms.
        # This must be done by the target user himself.
        if by_admin:
            requester = create_requester(target_user)

        await self.store.set_profile_displayname(target_user.localpart, new_displayname)

        if self.hs.config.user_directory_search_all_users:
            profile = await self.store.get_profileinfo(target_user.localpart)
            await self.user_directory_handler.handle_local_profile_change(
                target_user.to_string(), profile
            )

        await self._update_join_states(requester, target_user)

    async def get_avatar_url(self, target_user):
        if self.hs.is_mine(target_user):
            try:
                avatar_url = await self.store.get_profile_avatar_url(
                    target_user.localpart
                )
            except StoreError as e:
                if e.code == 404:
                    raise SynapseError(404, "Profile was not found", Codes.NOT_FOUND)
                raise
            return avatar_url
        else:
            try:
                result = await self.federation.make_query(
                    destination=target_user.domain,
                    query_type="profile",
                    args={"user_id": target_user.to_string(), "field": "avatar_url"},
                    ignore_backoff=True,
                )
            except RequestSendFailed as e:
                raise SynapseError(502, "Failed to fetch profile") from e
            except HttpResponseException as e:
                raise e.to_synapse_error()

            return result["avatar_url"]

    async def set_avatar_url(
        self, target_user, requester, new_avatar_url, by_admin=False
    ):
        """Set a new avatar URL for a user.

        Args:
            target_user (UserID): the user whose avatar URL is to be changed.
            requester (Requester): The user attempting to make this change.
            new_avatar_url (str): The avatar URL to give this user.
            by_admin (bool): Whether this change was made by an administrator.
        """
        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "User is not hosted on this homeserver")

        if not by_admin and target_user != requester.user:
            raise AuthError(400, "Cannot set another user's avatar_url")

        if not by_admin and not self.hs.config.enable_set_avatar_url:
            profile = await self.store.get_profileinfo(target_user.localpart)
            if profile.avatar_url:
                raise SynapseError(
                    400, "Changing avatar is disabled on this server", Codes.FORBIDDEN
                )

        if not isinstance(new_avatar_url, str):
            raise SynapseError(400, "Invalid displayname")

        if len(new_avatar_url) > MAX_AVATAR_URL_LEN:
            raise SynapseError(
                400, "Avatar URL is too long (max %i)" % (MAX_AVATAR_URL_LEN,)
            )

        # Same like set_displayname
        if by_admin:
            requester = create_requester(target_user)

        await self.store.set_profile_avatar_url(target_user.localpart, new_avatar_url)

        if self.hs.config.user_directory_search_all_users:
            profile = await self.store.get_profileinfo(target_user.localpart)
            await self.user_directory_handler.handle_local_profile_change(
                target_user.to_string(), profile
            )

        await self._update_join_states(requester, target_user)

    async def on_profile_query(self, args):
        user = UserID.from_string(args["user_id"])
        if not self.hs.is_mine(user):
            raise SynapseError(400, "User is not hosted on this homeserver")

        just_field = args.get("field", None)

        response = {}
        try:
            if just_field is None or just_field == "displayname":
                response["displayname"] = await self.store.get_profile_displayname(
                    user.localpart
                )

            if just_field is None or just_field == "avatar_url":
                response["avatar_url"] = await self.store.get_profile_avatar_url(
                    user.localpart
                )
        except StoreError as e:
            if e.code == 404:
                raise SynapseError(404, "Profile was not found", Codes.NOT_FOUND)
            raise

        return response

    async def _update_join_states(self, requester, target_user):
        if not self.hs.is_mine(target_user):
            return

        await self.ratelimit(requester)

        # Do not actually update the room state for shadow-banned users.
        if requester.shadow_banned:
            # We randomly sleep a bit just to annoy the requester.
            await self.clock.sleep(random.randint(1, 10))
            return

        room_ids = await self.store.get_rooms_for_user(target_user.to_string())

        for room_id in room_ids:
            handler = self.hs.get_room_member_handler()
            try:
                # Assume the target_user isn't a guest,
                # because we don't let guests set profile or avatar data.
                await handler.update_membership(
                    requester,
                    target_user,
                    room_id,
                    "join",  # We treat a profile update like a join.
                    ratelimit=False,  # Try to hide that these events aren't atomic.
                )
            except Exception as e:
                logger.warning(
                    "Failed to update join event for room %s - %s", room_id, str(e)
                )

    async def check_profile_query_allowed(self, target_user, requester=None):
        """Checks whether a profile query is allowed. If the
        'require_auth_for_profile_requests' config flag is set to True and a
        'requester' is provided, the query is only allowed if the two users
        share a room.

        Args:
            target_user (UserID): The owner of the queried profile.
            requester (None|UserID): The user querying for the profile.

        Raises:
            SynapseError(403): The two users share no room, or ne user couldn't
                be found to be in any room the server is in, and therefore the query
                is denied.
        """

        # Implementation of MSC1301: don't allow looking up profiles if the
        # requester isn't in the same room as the target. We expect requester to
        # be None when this function is called outside of a profile query, e.g.
        # when building a membership event. In this case, we must allow the
        # lookup.
        if (
            not self.hs.config.limit_profile_requests_to_users_who_share_rooms
            or not requester
        ):
            return

        # Always allow the user to query their own profile.
        if target_user.to_string() == requester.to_string():
            return

        try:
            requester_rooms = await self.store.get_rooms_for_user(requester.to_string())
            target_user_rooms = await self.store.get_rooms_for_user(
                target_user.to_string()
            )

            # Check if the room lists have no elements in common.
            if requester_rooms.isdisjoint(target_user_rooms):
                raise SynapseError(403, "Profile isn't available", Codes.FORBIDDEN)
        except StoreError as e:
            if e.code == 404:
                # This likely means that one of the users doesn't exist,
                # so we act as if we couldn't find the profile.
                raise SynapseError(403, "Profile isn't available", Codes.FORBIDDEN)
            raise


class MasterProfileHandler(BaseProfileHandler):
    PROFILE_UPDATE_MS = 60 * 1000
    PROFILE_UPDATE_EVERY_MS = 24 * 60 * 60 * 1000

    def __init__(self, hs):
        super().__init__(hs)

        assert hs.config.worker_app is None

        self.clock.looping_call(
            self._start_update_remote_profile_cache, self.PROFILE_UPDATE_MS
        )

    def _start_update_remote_profile_cache(self):
        return run_as_background_process(
            "Update remote profile", self._update_remote_profile_cache
        )

    async def _update_remote_profile_cache(self):
        """Called periodically to check profiles of remote users we haven't
        checked in a while.
        """
        entries = await self.store.get_remote_profile_cache_entries_that_expire(
            last_checked=self.clock.time_msec() - self.PROFILE_UPDATE_EVERY_MS
        )

        for user_id, displayname, avatar_url in entries:
            is_subscribed = await self.store.is_subscribed_remote_profile_for_user(
                user_id
            )
            if not is_subscribed:
                await self.store.maybe_delete_remote_profile_cache(user_id)
                continue

            try:
                profile = await self.federation.make_query(
                    destination=get_domain_from_id(user_id),
                    query_type="profile",
                    args={"user_id": user_id},
                    ignore_backoff=True,
                )
            except Exception:
                logger.exception("Failed to get avatar_url")

                await self.store.update_remote_profile_cache(
                    user_id, displayname, avatar_url
                )
                continue

            new_name = profile.get("displayname")
            new_avatar = profile.get("avatar_url")

            # We always hit update to update the last_check timestamp
            await self.store.update_remote_profile_cache(user_id, new_name, new_avatar)
