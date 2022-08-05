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
from typing import TYPE_CHECKING, Optional

from synapse.api.errors import (
    AuthError,
    Codes,
    HttpResponseException,
    RequestSendFailed,
    StoreError,
    SynapseError,
)
from synapse.types import JsonDict, Requester, UserID, create_requester
from synapse.util.caches.descriptors import cached
from synapse.util.stringutils import parse_and_validate_mxc_uri

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

MAX_DISPLAYNAME_LEN = 256
MAX_AVATAR_URL_LEN = 1000


class ProfileHandler:
    """Handles fetching and updating user profile information.

    ProfileHandler can be instantiated directly on workers and will
    delegate to master when necessary.
    """

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self.clock = hs.get_clock()
        self.hs = hs

        self.federation = hs.get_federation_client()
        hs.get_federation_registry().register_query_handler(
            "profile", self.on_profile_query
        )

        self.user_directory_handler = hs.get_user_directory_handler()
        self.request_ratelimiter = hs.get_request_ratelimiter()

        self.max_avatar_size = hs.config.server.max_avatar_size
        self.allowed_avatar_mimetypes = hs.config.server.allowed_avatar_mimetypes

        self.server_name = hs.config.server.server_name

        self._third_party_rules = hs.get_third_party_event_rules()

    async def get_profile(self, user_id: str) -> JsonDict:
        target_user = UserID.from_string(user_id)

        if self.hs.is_mine(target_user):
            profileinfo = await self.store.get_profileinfo(target_user.localpart)
            if profileinfo.display_name is None:
                raise SynapseError(404, "Profile was not found", Codes.NOT_FOUND)

            return {
                "displayname": profileinfo.display_name,
                "avatar_url": profileinfo.avatar_url,
            }
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
                if e.code < 500 and e.code != 404:
                    # Other codes are not allowed in c2s API
                    logger.info(
                        "Server replied with wrong response: %s %s", e.code, e.msg
                    )

                    raise SynapseError(502, "Failed to fetch profile")
                raise e.to_synapse_error()

    async def get_displayname(self, target_user: UserID) -> Optional[str]:
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

            return result.get("displayname")

    async def set_displayname(
        self,
        target_user: UserID,
        requester: Requester,
        new_displayname: str,
        by_admin: bool = False,
        deactivation: bool = False,
    ) -> None:
        """Set the displayname of a user

        Args:
            target_user: the user whose displayname is to be changed.
            requester: The user attempting to make this change.
            new_displayname: The displayname to give this user.
            by_admin: Whether this change was made by an administrator.
            deactivation: Whether this change was made while deactivating the user.
        """
        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "User is not hosted on this homeserver")

        if not by_admin and target_user != requester.user:
            raise AuthError(400, "Cannot set another user's displayname")

        if not by_admin and not self.hs.config.registration.enable_set_displayname:
            profile = await self.store.get_profileinfo(target_user.localpart)
            if profile.display_name:
                raise SynapseError(
                    400,
                    "Changing display name is disabled on this server",
                    Codes.FORBIDDEN,
                )

        if not isinstance(new_displayname, str):
            raise SynapseError(
                400, "'displayname' must be a string", errcode=Codes.INVALID_PARAM
            )

        if len(new_displayname) > MAX_DISPLAYNAME_LEN:
            raise SynapseError(
                400, "Displayname is too long (max %i)" % (MAX_DISPLAYNAME_LEN,)
            )

        displayname_to_set: Optional[str] = new_displayname
        if new_displayname == "":
            displayname_to_set = None

        # If the admin changes the display name of a user, the requesting user cannot send
        # the join event to update the displayname in the rooms.
        # This must be done by the target user himself.
        if by_admin:
            requester = create_requester(
                target_user,
                authenticated_entity=requester.authenticated_entity,
            )

        await self.store.set_profile_displayname(
            target_user.localpart, displayname_to_set
        )

        profile = await self.store.get_profileinfo(target_user.localpart)
        await self.user_directory_handler.handle_local_profile_change(
            target_user.to_string(), profile
        )

        await self._third_party_rules.on_profile_update(
            target_user.to_string(), profile, by_admin, deactivation
        )

        await self._update_join_states(requester, target_user)

    async def get_avatar_url(self, target_user: UserID) -> Optional[str]:
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

            return result.get("avatar_url")

    async def set_avatar_url(
        self,
        target_user: UserID,
        requester: Requester,
        new_avatar_url: str,
        by_admin: bool = False,
        deactivation: bool = False,
    ) -> None:
        """Set a new avatar URL for a user.

        Args:
            target_user: the user whose avatar URL is to be changed.
            requester: The user attempting to make this change.
            new_avatar_url: The avatar URL to give this user.
            by_admin: Whether this change was made by an administrator.
            deactivation: Whether this change was made while deactivating the user.
        """
        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "User is not hosted on this homeserver")

        if not by_admin and target_user != requester.user:
            raise AuthError(400, "Cannot set another user's avatar_url")

        if not by_admin and not self.hs.config.registration.enable_set_avatar_url:
            profile = await self.store.get_profileinfo(target_user.localpart)
            if profile.avatar_url:
                raise SynapseError(
                    400, "Changing avatar is disabled on this server", Codes.FORBIDDEN
                )

        if not isinstance(new_avatar_url, str):
            raise SynapseError(
                400, "'avatar_url' must be a string", errcode=Codes.INVALID_PARAM
            )

        if len(new_avatar_url) > MAX_AVATAR_URL_LEN:
            raise SynapseError(
                400, "Avatar URL is too long (max %i)" % (MAX_AVATAR_URL_LEN,)
            )

        if not await self.check_avatar_size_and_mime_type(new_avatar_url):
            raise SynapseError(403, "This avatar is not allowed", Codes.FORBIDDEN)

        avatar_url_to_set: Optional[str] = new_avatar_url
        if new_avatar_url == "":
            avatar_url_to_set = None

        # Same like set_displayname
        if by_admin:
            requester = create_requester(
                target_user, authenticated_entity=requester.authenticated_entity
            )

        await self.store.set_profile_avatar_url(
            target_user.localpart, avatar_url_to_set
        )

        profile = await self.store.get_profileinfo(target_user.localpart)
        await self.user_directory_handler.handle_local_profile_change(
            target_user.to_string(), profile
        )

        await self._third_party_rules.on_profile_update(
            target_user.to_string(), profile, by_admin, deactivation
        )

        await self._update_join_states(requester, target_user)

    @cached()
    async def check_avatar_size_and_mime_type(self, mxc: str) -> bool:
        """Check that the size and content type of the avatar at the given MXC URI are
        within the configured limits.

        If the given `mxc` is empty, no checks are performed. (Users are always able to
        unset their avatar.)

        Args:
            mxc: The MXC URI at which the avatar can be found.

        Returns:
             A boolean indicating whether the file can be allowed to be set as an avatar.
        """
        if mxc == "":
            return True

        if not self.max_avatar_size and not self.allowed_avatar_mimetypes:
            return True

        server_name, _, media_id = parse_and_validate_mxc_uri(mxc)

        if server_name == self.server_name:
            media_info = await self.store.get_local_media(media_id)
        else:
            media_info = await self.store.get_cached_remote_media(server_name, media_id)

        if media_info is None:
            # Both configuration options need to access the file's metadata, and
            # retrieving remote avatars just for this becomes a bit of a faff, especially
            # if e.g. the file is too big. It's also generally safe to assume most files
            # used as avatar are uploaded locally, or if the upload didn't happen as part
            # of a PUT request on /avatar_url that the file was at least previewed by the
            # user locally (and therefore downloaded to the remote media cache).
            logger.warning("Forbidding avatar change to %s: avatar not on server", mxc)
            return False

        if self.max_avatar_size:
            # Ensure avatar does not exceed max allowed avatar size
            if media_info["media_length"] > self.max_avatar_size:
                logger.warning(
                    "Forbidding avatar change to %s: %d bytes is above the allowed size "
                    "limit",
                    mxc,
                    media_info["media_length"],
                )
                return False

        if self.allowed_avatar_mimetypes:
            # Ensure the avatar's file type is allowed
            if (
                self.allowed_avatar_mimetypes
                and media_info["media_type"] not in self.allowed_avatar_mimetypes
            ):
                logger.warning(
                    "Forbidding avatar change to %s: mimetype %s not allowed",
                    mxc,
                    media_info["media_type"],
                )
                return False

        return True

    async def on_profile_query(self, args: JsonDict) -> JsonDict:
        """Handles federation profile query requests."""

        if not self.hs.config.federation.allow_profile_lookup_over_federation:
            raise SynapseError(
                403,
                "Profile lookup over federation is disabled on this homeserver",
                Codes.FORBIDDEN,
            )

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

    async def _update_join_states(
        self, requester: Requester, target_user: UserID
    ) -> None:
        if not self.hs.is_mine(target_user):
            return

        await self.request_ratelimiter.ratelimit(requester)

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

    async def check_profile_query_allowed(
        self, target_user: UserID, requester: Optional[UserID] = None
    ) -> None:
        """Checks whether a profile query is allowed. If the
        'require_auth_for_profile_requests' config flag is set to True and a
        'requester' is provided, the query is only allowed if the two users
        share a room.

        Args:
            target_user: The owner of the queried profile.
            requester: The user querying for the profile.

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
            not self.hs.config.server.limit_profile_requests_to_users_who_share_rooms
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
