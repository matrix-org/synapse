# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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
from typing import TYPE_CHECKING, List, Optional

from signedjson.sign import sign_json

from twisted.internet import reactor

from synapse.api.errors import (
    AuthError,
    Codes,
    HttpResponseException,
    RequestSendFailed,
    StoreError,
    SynapseError,
)
from synapse.logging.context import run_in_background
from synapse.metrics.background_process_metrics import (
    run_as_background_process,
    wrap_as_background_process,
)
from synapse.types import (
    JsonDict,
    Requester,
    UserID,
    create_requester,
    get_domain_from_id,
)

from ._base import BaseHandler

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

MAX_DISPLAYNAME_LEN = 256
MAX_AVATAR_URL_LEN = 1000


class ProfileHandler(BaseHandler):
    """Handles fetching and updating user profile information.

    ProfileHandler can be instantiated directly on workers and will
    delegate to master when necessary.
    """

    PROFILE_UPDATE_MS = 60 * 1000
    PROFILE_UPDATE_EVERY_MS = 24 * 60 * 60 * 1000

    PROFILE_REPLICATE_INTERVAL = 2 * 60 * 1000

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.federation = hs.get_federation_client()
        hs.get_federation_registry().register_query_handler(
            "profile", self.on_profile_query
        )

        self.user_directory_handler = hs.get_user_directory_handler()

        self.http_client = hs.get_simple_http_client()

        self.max_avatar_size = hs.config.max_avatar_size
        self.allowed_avatar_mimetypes = hs.config.allowed_avatar_mimetypes
        self.replicate_user_profiles_to = hs.config.replicate_user_profiles_to

        if hs.config.worker.run_background_tasks:
            self.clock.looping_call(
                self._update_remote_profile_cache, self.PROFILE_UPDATE_MS
            )

            if len(self.hs.config.replicate_user_profiles_to) > 0:
                reactor.callWhenRunning(self._do_assign_profile_replication_batches)  # type: ignore
                reactor.callWhenRunning(self._start_replicate_profiles)  # type: ignore
                # Add a looping call to replicate_profiles: this handles retries
                # if the replication is unsuccessful when the user updated their
                # profile.
                self.clock.looping_call(
                    self._start_replicate_profiles, self.PROFILE_REPLICATE_INTERVAL
                )

    def _do_assign_profile_replication_batches(self):
        return run_as_background_process(
            "_assign_profile_replication_batches",
            self._assign_profile_replication_batches,
        )

    def _start_replicate_profiles(self):
        return run_as_background_process(
            "_replicate_profiles", self._replicate_profiles
        )

    async def _assign_profile_replication_batches(self):
        """If no profile replication has been done yet, allocate replication batch
        numbers to each profile to start the replication process.
        """
        logger.info("Assigning profile batch numbers...")
        total = 0
        while True:
            assigned = await self.store.assign_profile_batch()
            total += assigned
            if assigned == 0:
                break
        logger.info("Assigned %d profile batch numbers", total)

    async def _replicate_profiles(self):
        """If any profile data has been updated and not pushed to the replication targets,
        replicate it.
        """
        host_batches = await self.store.get_replication_hosts()
        latest_batch = await self.store.get_latest_profile_replication_batch_number()
        if latest_batch is None:
            latest_batch = -1
        for repl_host in self.hs.config.replicate_user_profiles_to:
            if repl_host not in host_batches:
                host_batches[repl_host] = -1
            try:
                for i in range(host_batches[repl_host] + 1, latest_batch + 1):
                    await self._replicate_host_profile_batch(repl_host, i)
            except Exception:
                logger.exception(
                    "Exception while replicating to %s: aborting for now", repl_host
                )

    async def _replicate_host_profile_batch(self, host, batchnum):
        logger.info("Replicating profile batch %d to %s", batchnum, host)
        batch_rows = await self.store.get_profile_batch(batchnum)
        batch = {
            UserID(r["user_id"], self.hs.hostname).to_string(): (
                {"display_name": r["displayname"], "avatar_url": r["avatar_url"]}
                if r["active"]
                else None
            )
            for r in batch_rows
        }

        url = "https://%s/_matrix/identity/api/v1/replicate_profiles" % (host,)
        body = {"batchnum": batchnum, "batch": batch, "origin_server": self.hs.hostname}
        signed_body = sign_json(body, self.hs.hostname, self.hs.config.signing_key[0])
        try:
            await self.http_client.post_json_get_json(url, signed_body)
            await self.store.update_replication_batch_for_host(host, batchnum)
            logger.info(
                "Successfully replicated profile batch %d to %s", batchnum, host
            )
        except Exception:
            # This will get retried when the looping call next comes around
            logger.exception(
                "Failed to replicate profile batch %d to %s", batchnum, host
            )
            raise

    async def get_profile(self, user_id: str) -> JsonDict:
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
                if e.code < 500 and e.code != 404:
                    # Other codes are not allowed in c2s API
                    logger.info(
                        "Server replied with wrong response: %s %s", e.code, e.msg
                    )

                    raise SynapseError(502, "Failed to fetch profile")
                raise e.to_synapse_error()

    async def get_profile_from_cache(self, user_id: str) -> JsonDict:
        """Get the profile information from our local cache. If the user is
        ours then the profile information will always be correct. Otherwise,
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
    ) -> None:
        """Set the displayname of a user

        Args:
            target_user: the user whose displayname is to be changed.
            requester: The user attempting to make this change.
            new_displayname: The displayname to give this user.
            by_admin: Whether this change was made by an administrator.
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

        if len(self.hs.config.replicate_user_profiles_to) > 0:
            cur_batchnum = (
                await self.store.get_latest_profile_replication_batch_number()
            )
            new_batchnum = 0 if cur_batchnum is None else cur_batchnum + 1
        else:
            new_batchnum = None

        await self.store.set_profile_displayname(
            target_user.localpart, displayname_to_set, new_batchnum
        )

        profile = await self.store.get_profileinfo(target_user.localpart)
        await self.user_directory_handler.handle_local_profile_change(
            target_user.to_string(), profile
        )

        # Don't ratelimit when the admin makes the change.
        # FIXME: this is because we call this function on registration to update DINUM's
        #  custom userdir.
        await self._update_join_states(requester, target_user, ratelimit=not by_admin)

        # start a profile replication push
        run_in_background(self._replicate_profiles)

    async def set_active(
        self,
        users: List[UserID],
        active: bool,
        hide: bool,
    ):
        """
        Sets the 'active' flag on a set of user profiles. If set to false, the
        accounts are considered deactivated or hidden.

        If 'hide' is true, then we interpret active=False as a request to try to
        hide the users rather than deactivating them. This means withholding the
        profiles from replication (and mark it as inactive) rather than clearing
        the profile from the HS DB.

        Note that unlike set_displayname and set_avatar_url, this does *not*
        perform authorization checks! This is because the only place it's used
        currently is in account deactivation where we've already done these
        checks anyway.

        Args:
            users: The users to modify
            active: Whether to set the user to active or inactive
            hide: Whether to hide the user (withold from replication). If
                False and active is False, user will have their profile
                erased
        """
        if len(self.replicate_user_profiles_to) > 0:
            cur_batchnum = (
                await self.store.get_latest_profile_replication_batch_number()
            )
            new_batchnum = 0 if cur_batchnum is None else cur_batchnum + 1
        else:
            new_batchnum = None

        await self.store.set_profiles_active(users, active, hide, new_batchnum)

        # start a profile replication push
        run_in_background(self._replicate_profiles)

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
    ) -> None:
        """Set a new avatar URL for a user.

        Args:
            target_user: the user whose avatar URL is to be changed.
            requester: The user attempting to make this change.
            new_avatar_url: The avatar URL to give this user.
            by_admin: Whether this change was made by an administrator.
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
            raise SynapseError(
                400, "'avatar_url' must be a string", errcode=Codes.INVALID_PARAM
            )

        if len(new_avatar_url) > MAX_AVATAR_URL_LEN:
            raise SynapseError(
                400, "Avatar URL is too long (max %i)" % (MAX_AVATAR_URL_LEN,)
            )

        avatar_url_to_set: Optional[str] = new_avatar_url
        if new_avatar_url == "":
            avatar_url_to_set = None

        # Enforce a max avatar size if one is defined
        if avatar_url_to_set and (
            self.max_avatar_size or self.allowed_avatar_mimetypes
        ):
            media_id = self._validate_and_parse_media_id_from_avatar_url(
                avatar_url_to_set
            )

            # Check that this media exists locally
            media_info = await self.store.get_local_media(media_id)
            if not media_info:
                raise SynapseError(
                    400, "Unknown media id supplied", errcode=Codes.NOT_FOUND
                )

            # Ensure avatar does not exceed max allowed avatar size
            media_size = media_info["media_length"]
            if self.max_avatar_size and media_size > self.max_avatar_size:
                raise SynapseError(
                    400,
                    "Avatars must be less than %s bytes in size"
                    % (self.max_avatar_size,),
                    errcode=Codes.TOO_LARGE,
                )

            # Ensure the avatar's file type is allowed
            if (
                self.allowed_avatar_mimetypes
                and media_info["media_type"] not in self.allowed_avatar_mimetypes
            ):
                raise SynapseError(
                    400, "Avatar file type '%s' not allowed" % media_info["media_type"]
                )

        # Same like set_displayname
        if by_admin:
            requester = create_requester(
                target_user, authenticated_entity=requester.authenticated_entity
            )

        if len(self.hs.config.replicate_user_profiles_to) > 0:
            cur_batchnum = (
                await self.store.get_latest_profile_replication_batch_number()
            )
            new_batchnum = 0 if cur_batchnum is None else cur_batchnum + 1
        else:
            new_batchnum = None

        await self.store.set_profile_avatar_url(
            target_user.localpart, avatar_url_to_set, new_batchnum
        )

        profile = await self.store.get_profileinfo(target_user.localpart)
        await self.user_directory_handler.handle_local_profile_change(
            target_user.to_string(), profile
        )

        await self._update_join_states(requester, target_user)

        # start a profile replication push
        run_in_background(self._replicate_profiles)

    def _validate_and_parse_media_id_from_avatar_url(self, mxc):
        """Validate and parse a provided avatar url and return the local media id

        Args:
            mxc (str): A mxc URL

        Returns:
            str: The ID of the media
        """
        avatar_pieces = mxc.split("/")
        if len(avatar_pieces) != 4 or avatar_pieces[0] != "mxc:":
            raise SynapseError(400, "Invalid avatar URL '%s' supplied" % mxc)
        return avatar_pieces[-1]

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
        self,
        requester: Requester,
        target_user: UserID,
        ratelimit: bool = True,
    ) -> None:
        if not self.hs.is_mine(target_user):
            return

        if ratelimit:
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

    @wrap_as_background_process("Update remote profile")
    async def _update_remote_profile_cache(self) -> None:
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
