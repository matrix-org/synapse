# Copyright 2017 New Vector Ltd
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING, Any, Generator, Iterable, List, Optional, Tuple

from twisted.internet import defer
from twisted.web.resource import IResource

from synapse.events import EventBase
from synapse.http.client import SimpleHttpClient
from synapse.http.site import SynapseRequest
from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.storage.state import StateFilter
from synapse.types import JsonDict, UserID, create_requester

if TYPE_CHECKING:
    from synapse.server import HomeServer

"""
This package defines the 'stable' API which can be used by extension modules which
are loaded into Synapse.
"""

__all__ = ["errors", "make_deferred_yieldable", "run_in_background", "ModuleApi"]

logger = logging.getLogger(__name__)


class ModuleApi:
    """A proxy object that gets passed to various plugin modules so they
    can register new users etc if necessary.
    """

    def __init__(self, hs: "HomeServer", auth_handler):
        self._hs = hs

        self._store = hs.get_datastore()
        self._auth = hs.get_auth()
        self._auth_handler = auth_handler
        self._server_name = hs.hostname
        self._presence_stream = hs.get_event_sources().sources["presence"]
        self._state = hs.get_state_handler()

        # We expose these as properties below in order to attach a helpful docstring.
        self._http_client = hs.get_simple_http_client()  # type: SimpleHttpClient
        self._public_room_list_manager = PublicRoomListManager(hs)

        self._spam_checker = hs.get_spam_checker()

    #################################################################################
    # The following methods should only be called during the module's initialisation.

    @property
    def register_spam_checker_callbacks(self):
        """Registers callbacks for spam checking capabilities."""
        return self._spam_checker.register_callbacks

    def register_web_resource(self, path: str, resource: IResource):
        """Registers a web resource to be served at the given path.

        This function should be called during initialisation of the module.

        If multiple modules register a resource for the same path, the module that
        appears the highest in the configuration file takes priority.

        Args:
            path: The path to register the resource for.
            resource: The resource to attach to this path.
        """
        self._hs.register_module_web_resource(path, resource)

    #########################################################################
    # The following methods can be called by the module at any point in time.

    @property
    def http_client(self):
        """Allows making outbound HTTP requests to remote resources.

        An instance of synapse.http.client.SimpleHttpClient
        """
        return self._http_client

    @property
    def public_room_list_manager(self):
        """Allows adding to, removing from and checking the status of rooms in the
        public room list.

        An instance of synapse.module_api.PublicRoomListManager
        """
        return self._public_room_list_manager

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
        if username.startswith("@"):
            return username
        return UserID(username, self._hs.hostname).to_string()

    def check_user_exists(self, user_id):
        """Check if user exists.

        Args:
            user_id (str): Complete @user:id

        Returns:
            Deferred[str|None]: Canonical (case-corrected) user_id, or None
               if the user is not registered.
        """
        return defer.ensureDeferred(self._auth_handler.check_user_exists(user_id))

    @defer.inlineCallbacks
    def register(self, localpart, displayname=None, emails: Optional[List[str]] = None):
        """Registers a new user with given localpart and optional displayname, emails.

        Also returns an access token for the new user.

        Deprecated: avoid this, as it generates a new device with no way to
        return that device to the user. Prefer separate calls to register_user and
        register_device.

        Args:
            localpart (str): The localpart of the new user.
            displayname (str|None): The displayname of the new user.
            emails (List[str]): Emails to bind to the new user.

        Returns:
            Deferred[tuple[str, str]]: a 2-tuple of (user_id, access_token)
        """
        logger.warning(
            "Using deprecated ModuleApi.register which creates a dummy user device."
        )
        user_id = yield self.register_user(localpart, displayname, emails or [])
        _, access_token, _, _ = yield self.register_device(user_id)
        return user_id, access_token

    def register_user(
        self, localpart, displayname=None, emails: Optional[List[str]] = None
    ):
        """Registers a new user with given localpart and optional displayname, emails.

        Args:
            localpart (str): The localpart of the new user.
            displayname (str|None): The displayname of the new user.
            emails (List[str]): Emails to bind to the new user.

        Raises:
            SynapseError if there is an error performing the registration. Check the
                'errcode' property for more information on the reason for failure

        Returns:
            defer.Deferred[str]: user_id
        """
        return defer.ensureDeferred(
            self._hs.get_registration_handler().register_user(
                localpart=localpart,
                default_display_name=displayname,
                bind_emails=emails or [],
            )
        )

    def register_device(self, user_id, device_id=None, initial_display_name=None):
        """Register a device for a user and generate an access token.

        Args:
            user_id (str): full canonical @user:id
            device_id (str|None): The device ID to check, or None to generate
                a new one.
            initial_display_name (str|None): An optional display name for the
                device.

        Returns:
            defer.Deferred[tuple[str, str]]: Tuple of device ID and access token
        """
        return defer.ensureDeferred(
            self._hs.get_registration_handler().register_device(
                user_id=user_id,
                device_id=device_id,
                initial_display_name=initial_display_name,
            )
        )

    def record_user_external_id(
        self, auth_provider_id: str, remote_user_id: str, registered_user_id: str
    ) -> defer.Deferred:
        """Record a mapping from an external user id to a mxid

        Args:
            auth_provider: identifier for the remote auth provider
            external_id: id on that system
            user_id: complete mxid that it is mapped to
        """
        return defer.ensureDeferred(
            self._store.record_user_external_id(
                auth_provider_id, remote_user_id, registered_user_id
            )
        )

    def generate_short_term_login_token(
        self,
        user_id: str,
        duration_in_ms: int = (2 * 60 * 1000),
        auth_provider_id: str = "",
    ) -> str:
        """Generate a login token suitable for m.login.token authentication

        Args:
            user_id: gives the ID of the user that the token is for

            duration_in_ms: the time that the token will be valid for

            auth_provider_id: the ID of the SSO IdP that the user used to authenticate
               to get this token, if any. This is encoded in the token so that
               /login can report stats on number of successful logins by IdP.
        """
        return self._hs.get_macaroon_generator().generate_short_term_login_token(
            user_id,
            auth_provider_id,
            duration_in_ms,
        )

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
        user_info = yield defer.ensureDeferred(
            self._auth.get_user_by_access_token(access_token)
        )
        device_id = user_info.get("device_id")
        user_id = user_info["user"].to_string()
        if device_id:
            # delete the device, which will also delete its access tokens
            yield defer.ensureDeferred(
                self._hs.get_device_handler().delete_device(user_id, device_id)
            )
        else:
            # no associated device. Just delete the access token.
            yield defer.ensureDeferred(
                self._auth_handler.delete_access_token(access_token)
            )

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
        return defer.ensureDeferred(
            self._store.db_pool.runInteraction(desc, func, *args, **kwargs)
        )

    def complete_sso_login(
        self, registered_user_id: str, request: SynapseRequest, client_redirect_url: str
    ):
        """Complete a SSO login by redirecting the user to a page to confirm whether they
        want their access token sent to `client_redirect_url`, or redirect them to that
        URL with a token directly if the URL matches with one of the whitelisted clients.

        This is deprecated in favor of complete_sso_login_async.

        Args:
            registered_user_id: The MXID that has been registered as a previous step of
                of this SSO login.
            request: The request to respond to.
            client_redirect_url: The URL to which to offer to redirect the user (or to
                redirect them directly if whitelisted).
        """
        self._auth_handler._complete_sso_login(
            registered_user_id,
            "<unknown>",
            request,
            client_redirect_url,
        )

    async def complete_sso_login_async(
        self,
        registered_user_id: str,
        request: SynapseRequest,
        client_redirect_url: str,
        new_user: bool = False,
        auth_provider_id: str = "<unknown>",
    ):
        """Complete a SSO login by redirecting the user to a page to confirm whether they
        want their access token sent to `client_redirect_url`, or redirect them to that
        URL with a token directly if the URL matches with one of the whitelisted clients.

        Args:
            registered_user_id: The MXID that has been registered as a previous step of
                of this SSO login.
            request: The request to respond to.
            client_redirect_url: The URL to which to offer to redirect the user (or to
                redirect them directly if whitelisted).
            new_user: set to true to use wording for the consent appropriate to a user
                who has just registered.
            auth_provider_id: the ID of the SSO IdP which was used to log in. This
                is used to track counts of sucessful logins by IdP.
        """
        await self._auth_handler.complete_sso_login(
            registered_user_id,
            auth_provider_id,
            request,
            client_redirect_url,
            new_user=new_user,
        )

    @defer.inlineCallbacks
    def get_state_events_in_room(
        self, room_id: str, types: Iterable[Tuple[str, Optional[str]]]
    ) -> Generator[defer.Deferred, Any, defer.Deferred]:
        """Gets current state events for the given room.

        (This is exposed for compatibility with the old SpamCheckerApi. We should
        probably deprecate it and replace it with an async method in a subclass.)

        Args:
            room_id: The room ID to get state events in.
            types: The event type and state key (using None
                to represent 'any') of the room state to acquire.

        Returns:
            twisted.internet.defer.Deferred[list(synapse.events.FrozenEvent)]:
                The filtered state events in the room.
        """
        state_ids = yield defer.ensureDeferred(
            self._store.get_filtered_current_state_ids(
                room_id=room_id, state_filter=StateFilter.from_types(types)
            )
        )
        state = yield defer.ensureDeferred(self._store.get_events(state_ids.values()))
        return state.values()

    async def create_and_send_event_into_room(self, event_dict: JsonDict) -> EventBase:
        """Create and send an event into a room. Membership events are currently not supported.

        Args:
            event_dict: A dictionary representing the event to send.
                Required keys are `type`, `room_id`, `sender` and `content`.

        Returns:
            The event that was sent. If state event deduplication happened, then
                the previous, duplicate event instead.

        Raises:
            SynapseError if the event was not allowed.
        """
        # Create a requester object
        requester = create_requester(
            event_dict["sender"], authenticated_entity=self._server_name
        )

        # Create and send the event
        (
            event,
            _,
        ) = await self._hs.get_event_creation_handler().create_and_send_nonmember_event(
            requester,
            event_dict,
            ratelimit=False,
            ignore_shadow_ban=True,
        )

        return event

    async def send_local_online_presence_to(self, users: Iterable[str]) -> None:
        """
        Forces the equivalent of a presence initial_sync for a set of local or remote
        users. The users will receive presence for all currently online users that they
        are considered interested in.

        Updates to remote users will be sent immediately, whereas local users will receive
        them on their next sync attempt.

        Note that this method can only be run on the process that is configured to write to the
        presence stream. By default this is the main process.
        """
        if self._hs._instance_name not in self._hs.config.worker.writers.presence:
            raise Exception(
                "send_local_online_presence_to can only be run "
                "on the process that is configured to write to the "
                "presence stream (by default this is the main process)",
            )

        local_users = set()
        remote_users = set()
        for user in users:
            if self._hs.is_mine_id(user):
                local_users.add(user)
            else:
                remote_users.add(user)

        # We pull out the presence handler here to break a cyclic
        # dependency between the presence router and module API.
        presence_handler = self._hs.get_presence_handler()

        if local_users:
            # Force a presence initial_sync for these users next time they sync.
            await presence_handler.send_full_presence_to_users(local_users)

        for user in remote_users:
            # Retrieve presence state for currently online users that this user
            # is considered interested in.
            presence_events, _ = await self._presence_stream.get_new_events(
                UserID.from_string(user), from_key=None, include_offline=False
            )

            # Send to remote destinations.
            destination = UserID.from_string(user).domain
            presence_handler.get_federation_queue().send_presence_to_destinations(
                presence_events, destination
            )


class PublicRoomListManager:
    """Contains methods for adding to, removing from and querying whether a room
    is in the public room list.
    """

    def __init__(self, hs: "HomeServer"):
        self._store = hs.get_datastore()

    async def room_is_in_public_room_list(self, room_id: str) -> bool:
        """Checks whether a room is in the public room list.

        Args:
            room_id: The ID of the room.

        Returns:
            Whether the room is in the public room list. Returns False if the room does
            not exist.
        """
        room = await self._store.get_room(room_id)
        if not room:
            return False

        return room.get("is_public", False)

    async def add_room_to_public_room_list(self, room_id: str) -> None:
        """Publishes a room to the public room list.

        Args:
            room_id: The ID of the room.
        """
        await self._store.set_room_is_public(room_id, True)

    async def remove_room_from_public_room_list(self, room_id: str) -> None:
        """Removes a room from the public room list.

        Args:
            room_id: The ID of the room.
        """
        await self._store.set_room_is_public(room_id, False)
