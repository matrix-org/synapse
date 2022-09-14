# Copyright 2014 - 2016 OpenMarket Ltd
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

import pymacaroons
from netaddr import IPAddress

from twisted.web.server import Request

from synapse import event_auth
from synapse.api.constants import EventTypes, HistoryVisibility, Membership
from synapse.api.errors import (
    AuthError,
    Codes,
    InvalidClientTokenError,
    MissingClientTokenError,
    UnstableSpecAuthError,
)
from synapse.appservice import ApplicationService
from synapse.http import get_request_user_agent
from synapse.http.site import SynapseRequest
from synapse.logging.opentracing import (
    SynapseTags,
    active_span,
    force_tracing,
    start_active_span,
    trace,
)
from synapse.types import Requester, create_requester
from synapse.util.cancellation import cancellable

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


# guests always get this device id.
GUEST_DEVICE_ID = "guest_device"


class Auth:
    """
    This class contains functions for authenticating users of our client-server API.
    """

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.clock = hs.get_clock()
        self.store = hs.get_datastores().main
        self._account_validity_handler = hs.get_account_validity_handler()
        self._storage_controllers = hs.get_storage_controllers()
        self._macaroon_generator = hs.get_macaroon_generator()

        self._track_appservice_user_ips = hs.config.appservice.track_appservice_user_ips
        self._track_puppeted_user_ips = hs.config.api.track_puppeted_user_ips
        self._force_tracing_for_users = hs.config.tracing.force_tracing_for_users

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

    @cancellable
    async def get_user_by_req(
        self,
        request: SynapseRequest,
        allow_guest: bool = False,
        allow_expired: bool = False,
    ) -> Requester:
        """Get a registered user's ID.

        Args:
            request: An HTTP request with an access_token query parameter.
            allow_guest: If False, will raise an AuthError if the user making the
                request is a guest.
            allow_expired: If True, allow the request through even if the account
                is expired, or session token lifetime has ended. Note that
                /login will deliver access tokens regardless of expiration.

        Returns:
            Resolves to the requester
        Raises:
            InvalidClientCredentialsError if no user by that token exists or the token
                is invalid.
            AuthError if access is denied for the user in the access token
        """
        parent_span = active_span()
        with start_active_span("get_user_by_req"):
            requester = await self._wrapped_get_user_by_req(
                request, allow_guest, allow_expired
            )

            if parent_span:
                if requester.authenticated_entity in self._force_tracing_for_users:
                    # request tracing is enabled for this user, so we need to force it
                    # tracing on for the parent span (which will be the servlet span).
                    #
                    # It's too late for the get_user_by_req span to inherit the setting,
                    # so we also force it on for that.
                    force_tracing()
                    force_tracing(parent_span)
                parent_span.set_tag(
                    "authenticated_entity", requester.authenticated_entity
                )
                # We tag the Synapse instance name so that it's an easy jumping
                # off point into the logs. Can also be used to filter for an
                # instance that is under load.
                parent_span.set_tag(
                    SynapseTags.INSTANCE_NAME, self.hs.get_instance_name()
                )
                parent_span.set_tag("user_id", requester.user.to_string())
                if requester.device_id is not None:
                    parent_span.set_tag("device_id", requester.device_id)
                if requester.app_service is not None:
                    parent_span.set_tag("appservice_id", requester.app_service.id)
            return requester

    @cancellable
    async def _wrapped_get_user_by_req(
        self,
        request: SynapseRequest,
        allow_guest: bool,
        allow_expired: bool,
    ) -> Requester:
        """Helper for get_user_by_req

        Once get_user_by_req has set up the opentracing span, this does the actual work.
        """
        try:
            ip_addr = request.getClientAddress().host
            user_agent = get_request_user_agent(request)

            access_token = self.get_access_token_from_request(request)

            # First check if it could be a request from an appservice
            requester = await self._get_appservice_user(request)
            if not requester:
                # If not, it should be from a regular user
                requester = await self.get_user_by_access_token(
                    access_token, allow_expired=allow_expired
                )

                # Deny the request if the user account has expired.
                # This check is only done for regular users, not appservice ones.
                if not allow_expired:
                    if await self._account_validity_handler.is_user_expired(
                        requester.user.to_string()
                    ):
                        # Raise the error if either an account validity module has determined
                        # the account has expired, or the legacy account validity
                        # implementation is enabled and determined the account has expired
                        raise AuthError(
                            403,
                            "User account has expired",
                            errcode=Codes.EXPIRED_ACCOUNT,
                        )

            if ip_addr and (
                not requester.app_service or self._track_appservice_user_ips
            ):
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

            if requester.is_guest and not allow_guest:
                raise AuthError(
                    403,
                    "Guest access not allowed",
                    errcode=Codes.GUEST_ACCESS_FORBIDDEN,
                )

            request.requester = requester
            return requester
        except KeyError:
            raise MissingClientTokenError()

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

    @cancellable
    async def _get_appservice_user(self, request: Request) -> Optional[Requester]:
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

        app_service = self.store.get_app_service_by_token(
            self.get_access_token_from_request(request)
        )
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

    async def get_user_by_access_token(
        self,
        token: str,
        allow_expired: bool = False,
    ) -> Requester:
        """Validate access token and get user_id from it

        Args:
            token: The access token to get the user by
            allow_expired: If False, raises an InvalidClientTokenError
                if the token is expired

        Raises:
            InvalidClientTokenError if a user by that token exists, but the token is
                expired
            InvalidClientCredentialsError if no user by that token exists or the token
                is invalid
        """

        # First look in the database to see if the access token is present
        # as an opaque token.
        user_info = await self.store.get_user_by_access_token(token)
        if user_info:
            valid_until_ms = user_info.valid_until_ms
            if (
                not allow_expired
                and valid_until_ms is not None
                and valid_until_ms < self.clock.time_msec()
            ):
                # there was a valid access token, but it has expired.
                # soft-logout the user.
                raise InvalidClientTokenError(
                    msg="Access token has expired", soft_logout=True
                )

            # Mark the token as used. This is used to invalidate old refresh
            # tokens after some time.
            await self.store.mark_access_token_as_used(user_info.token_id)

            requester = create_requester(
                user_id=user_info.user_id,
                access_token_id=user_info.token_id,
                is_guest=user_info.is_guest,
                shadow_banned=user_info.shadow_banned,
                device_id=user_info.device_id,
                authenticated_entity=user_info.token_owner,
            )

            return requester

        # If the token isn't found in the database, then it could still be a
        # macaroon for a guest, so we check that here.
        try:
            user_id = self._macaroon_generator.verify_guest_token(token)

            # Guest access tokens are not stored in the database (there can
            # only be one access token per guest, anyway).
            #
            # In order to prevent guest access tokens being used as regular
            # user access tokens (and hence getting around the invalidation
            # process), we look up the user id and check that it is indeed
            # a guest user.
            #
            # It would of course be much easier to store guest access
            # tokens in the database as well, but that would break existing
            # guest tokens.
            stored_user = await self.store.get_user_by_id(user_id)
            if not stored_user:
                raise InvalidClientTokenError("Unknown user_id %s" % user_id)
            if not stored_user["is_guest"]:
                raise InvalidClientTokenError(
                    "Guest access token used for regular user"
                )

            return create_requester(
                user_id=user_id,
                is_guest=True,
                # all guests get the same device id
                device_id=GUEST_DEVICE_ID,
                authenticated_entity=user_id,
            )
        except (
            pymacaroons.exceptions.MacaroonException,
            TypeError,
            ValueError,
        ) as e:
            logger.warning(
                "Invalid access token in auth: %s %s.",
                type(e),
                e,
            )
            raise InvalidClientTokenError("Invalid access token passed.")

    async def is_server_admin(self, requester: Requester) -> bool:
        """Check if the given user is a local server admin.

        Args:
            requester: The user making the request, according to the access token.

        Returns:
            True if the user is an admin
        """
        return await self.store.is_server_admin(requester.user)

    async def check_can_change_room_list(
        self, room_id: str, requester: Requester
    ) -> bool:
        """Determine whether the user is allowed to edit the room's entry in the
        published room list.

        Args:
            room_id: The room to check.
            requester: The user making the request, according to the access token.
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
    @cancellable
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

    @trace
    async def check_user_in_room_or_world_readable(
        self, room_id: str, requester: Requester, allow_departed_users: bool = False
    ) -> Tuple[str, Optional[str]]:
        """Checks that the user is or was in the room or the room is world
        readable. If it isn't then an exception is raised.

        Args:
            room_id: The room to check.
            requester: The user making the request, according to the access token.
            allow_departed_users: If True, accept users that were previously
                members but have now departed.

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
            raise UnstableSpecAuthError(
                403,
                "User %s not in room %s, and room previews are disabled"
                % (requester.user, room_id),
                errcode=Codes.NOT_JOINED,
            )
