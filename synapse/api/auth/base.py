# Copyright 2023 The Matrix.org Foundation.
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
from typing import TYPE_CHECKING, Optional, Tuple

from netaddr import IPAddress

from twisted.web.server import Request

from synapse import event_auth
from synapse.api.constants import EventTypes, HistoryVisibility, Membership
from synapse.api.errors import (
    AuthError,
    Codes,
    MissingClientTokenError,
    UnstableSpecAuthError,
)
from synapse.appservice import ApplicationService
from synapse.http import get_request_user_agent
from synapse.http.site import SynapseRequest
from synapse.logging.opentracing import trace
from synapse.types import Requester, create_requester
from synapse.util.cancellation import cancellable

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class BaseAuth:
    """Common base class for all auth implementations."""

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.store = hs.get_datastores().main
        self._storage_controllers = hs.get_storage_controllers()

        self._track_appservice_user_ips = hs.config.appservice.track_appservice_user_ips
        self._track_puppeted_user_ips = hs.config.api.track_puppeted_user_ips

    async def check_user_in_room(
        self,
        room_id: str,
        requester: Requester,
        allow_departed_users: bool = False,
    ) -> Tuple[str, Optional[str]]:
        """Check if the user is in the room, or was at some point.
        Args:
            room_id: The room to check.

            requester: The user making the request, according to the access token.

            current_state: Optional map of the current state of the room.
                If provided then that map is used to check whether they are a
                member of the room. Otherwise the current membership is
                loaded from the database.

            allow_departed_users: if True, accept users that were previously
                members but have now departed.

        Raises:
            AuthError if the user is/was not in the room.
        Returns:
            The current membership of the user in the room and the
            membership event ID of the user.
        """

        user_id = requester.user.to_string()
        (
            membership,
            member_event_id,
        ) = await self.store.get_local_current_membership_for_user_in_room(
            user_id=user_id,
            room_id=room_id,
        )

        if membership:
            if membership == Membership.JOIN:
                return membership, member_event_id

            # XXX this looks totally bogus. Why do we not allow users who have been banned,
            # or those who were members previously and have been re-invited?
            if allow_departed_users and membership == Membership.LEAVE:
                forgot = await self.store.did_forget(user_id, room_id)
                if not forgot:
                    return membership, member_event_id
        raise UnstableSpecAuthError(
            403,
            "User %s not in room %s" % (user_id, room_id),
            errcode=Codes.NOT_JOINED,
        )

    @trace
    async def check_user_in_room_or_world_readable(
        self, room_id: str, requester: Requester, allow_departed_users: bool = False
    ) -> Tuple[str, Optional[str]]:
        """Checks that the user is or was in the room or the room is world
        readable. If it isn't then an exception is raised.

        Args:
            room_id: room to check
            user_id: user to check
            allow_departed_users: if True, accept users that were previously
                members but have now departed

        Returns:
            Resolves to the current membership of the user in the room and the
            membership event ID of the user. If the user is not in the room and
            never has been, then `(Membership.JOIN, None)` is returned.
        """

        try:
            # check_user_in_room will return the most recent membership
            # event for the user if:
            #  * The user is a non-guest user, and was ever in the room
            #  * The user is a guest user, and has joined the room
            # else it will throw.
            return await self.check_user_in_room(
                room_id, requester, allow_departed_users=allow_departed_users
            )
        except AuthError:
            visibility = await self._storage_controllers.state.get_current_state_event(
                room_id, EventTypes.RoomHistoryVisibility, ""
            )
            if (
                visibility
                and visibility.content.get("history_visibility")
                == HistoryVisibility.WORLD_READABLE
            ):
                return Membership.JOIN, None
            raise AuthError(
                403,
                "User %r not in room %s, and room previews are disabled"
                % (requester.user, room_id),
            )

    async def validate_appservice_can_control_user_id(
        self, app_service: ApplicationService, user_id: str
    ) -> None:
        """Validates that the app service is allowed to control
        the given user.

        Args:
            app_service: The app service that controls the user
            user_id: The author MXID that the app service is controlling

        Raises:
            AuthError: If the application service is not allowed to control the user
                (user namespace regex does not match, wrong homeserver, etc)
                or if the user has not been registered yet.
        """

        # It's ok if the app service is trying to use the sender from their registration
        if app_service.sender == user_id:
            pass
        # Check to make sure the app service is allowed to control the user
        elif not app_service.is_interested_in_user(user_id):
            raise AuthError(
                403,
                "Application service cannot masquerade as this user (%s)." % user_id,
            )
        # Check to make sure the user is already registered on the homeserver
        elif not (await self.store.get_user_by_id(user_id)):
            raise AuthError(
                403, "Application service has not registered this user (%s)" % user_id
            )

    async def is_server_admin(self, requester: Requester) -> bool:
        """Check if the given user is a local server admin.

        Args:
            requester: user to check

        Returns:
            True if the user is an admin
        """
        raise NotImplementedError()

    async def check_can_change_room_list(
        self, room_id: str, requester: Requester
    ) -> bool:
        """Determine whether the user is allowed to edit the room's entry in the
        published room list.

        Args:
            room_id
            user
        """

        is_admin = await self.is_server_admin(requester)
        if is_admin:
            return True

        await self.check_user_in_room(room_id, requester)

        # We currently require the user is a "moderator" in the room. We do this
        # by checking if they would (theoretically) be able to change the
        # m.room.canonical_alias events

        power_level_event = (
            await self._storage_controllers.state.get_current_state_event(
                room_id, EventTypes.PowerLevels, ""
            )
        )

        auth_events = {}
        if power_level_event:
            auth_events[(EventTypes.PowerLevels, "")] = power_level_event

        send_level = event_auth.get_send_level(
            EventTypes.CanonicalAlias, "", power_level_event
        )
        user_level = event_auth.get_user_power_level(
            requester.user.to_string(), auth_events
        )

        return user_level >= send_level

    @staticmethod
    def has_access_token(request: Request) -> bool:
        """Checks if the request has an access_token.

        Returns:
            False if no access_token was given, True otherwise.
        """
        # This will always be set by the time Twisted calls us.
        assert request.args is not None

        query_params = request.args.get(b"access_token")
        auth_headers = request.requestHeaders.getRawHeaders(b"Authorization")
        return bool(query_params) or bool(auth_headers)

    @staticmethod
    def get_access_token_from_request(request: Request) -> str:
        """Extracts the access_token from the request.

        Args:
            request: The http request.
        Returns:
            The access_token
        Raises:
            MissingClientTokenError: If there isn't a single access_token in the
                request
        """
        # This will always be set by the time Twisted calls us.
        assert request.args is not None

        auth_headers = request.requestHeaders.getRawHeaders(b"Authorization")
        query_params = request.args.get(b"access_token")
        if auth_headers:
            # Try the get the access_token from a "Authorization: Bearer"
            # header
            if query_params is not None:
                raise MissingClientTokenError(
                    "Mixing Authorization headers and access_token query parameters."
                )
            if len(auth_headers) > 1:
                raise MissingClientTokenError("Too many Authorization headers.")
            parts = auth_headers[0].split(b" ")
            if parts[0] == b"Bearer" and len(parts) == 2:
                return parts[1].decode("ascii")
            else:
                raise MissingClientTokenError("Invalid Authorization header.")
        else:
            # Try to get the access_token from the query params.
            if not query_params:
                raise MissingClientTokenError()

            return query_params[0].decode("ascii")

    @cancellable
    async def get_appservice_user(
        self, request: Request, access_token: str
    ) -> Optional[Requester]:
        """
        Given a request, reads the request parameters to determine:
        - whether it's an application service that's making this request
        - what user the application service should be treated as controlling
          (the user_id URI parameter allows an application service to masquerade
          any applicable user in its namespace)
        - what device the application service should be treated as controlling
          (the device_id[^1] URI parameter allows an application service to masquerade
          as any device that exists for the relevant user)

        [^1] Unstable and provided by MSC3202.
             Must use `org.matrix.msc3202.device_id` in place of `device_id` for now.

        Returns:
            the application service `Requester` of that request

        Postconditions:
        - The `app_service` field in the returned `Requester` is set
        - The `user_id` field in the returned `Requester` is either the application
          service sender or the controlled user set by the `user_id` URI parameter
        - The returned application service is permitted to control the returned user ID.
        - The returned device ID, if present, has been checked to be a valid device ID
          for the returned user ID.
        """
        DEVICE_ID_ARG_NAME = b"org.matrix.msc3202.device_id"

        app_service = self.store.get_app_service_by_token(access_token)
        if app_service is None:
            return None

        if app_service.ip_range_whitelist:
            ip_address = IPAddress(request.getClientAddress().host)
            if ip_address not in app_service.ip_range_whitelist:
                return None

        # This will always be set by the time Twisted calls us.
        assert request.args is not None

        if b"user_id" in request.args:
            effective_user_id = request.args[b"user_id"][0].decode("utf8")
            await self.validate_appservice_can_control_user_id(
                app_service, effective_user_id
            )
        else:
            effective_user_id = app_service.sender

        effective_device_id: Optional[str] = None

        if (
            self.hs.config.experimental.msc3202_device_masquerading_enabled
            and DEVICE_ID_ARG_NAME in request.args
        ):
            effective_device_id = request.args[DEVICE_ID_ARG_NAME][0].decode("utf8")
            # We only just set this so it can't be None!
            assert effective_device_id is not None
            device_opt = await self.store.get_device(
                effective_user_id, effective_device_id
            )
            if device_opt is None:
                # For now, use 400 M_EXCLUSIVE if the device doesn't exist.
                # This is an open thread of discussion on MSC3202 as of 2021-12-09.
                raise AuthError(
                    400,
                    f"Application service trying to use a device that doesn't exist ('{effective_device_id}' for {effective_user_id})",
                    Codes.EXCLUSIVE,
                )

        return create_requester(
            effective_user_id, app_service=app_service, device_id=effective_device_id
        )

    async def _record_request(
        self, request: SynapseRequest, requester: Requester
    ) -> None:
        """Record that this request was made.

        This updates the client_ips and monthly_active_user tables.
        """
        ip_addr = request.get_client_ip_if_available()

        if ip_addr and (not requester.app_service or self._track_appservice_user_ips):
            user_agent = get_request_user_agent(request)
            access_token = self.get_access_token_from_request(request)

            # XXX(quenting): I'm 95% confident that we could skip setting the
            # device_id to "dummy-device" for appservices, and that the only impact
            # would be some rows which whould not deduplicate in the 'user_ips'
            # table during the transition
            recorded_device_id = (
                "dummy-device"
                if requester.device_id is None and requester.app_service is not None
                else requester.device_id
            )
            await self.store.insert_client_ip(
                user_id=requester.authenticated_entity,
                access_token=access_token,
                ip=ip_addr,
                user_agent=user_agent,
                device_id=recorded_device_id,
            )

            # Track also the puppeted user client IP if enabled and the user is puppeting
            if (
                requester.user.to_string() != requester.authenticated_entity
                and self._track_puppeted_user_ips
            ):
                await self.store.insert_client_ip(
                    user_id=requester.user.to_string(),
                    access_token=access_token,
                    ip=ip_addr,
                    user_agent=user_agent,
                    device_id=requester.device_id,
                )
