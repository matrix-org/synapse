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
from typing import TYPE_CHECKING

import pymacaroons

from synapse.api.errors import (
    AuthError,
    Codes,
    InvalidClientTokenError,
    MissingClientTokenError,
)
from synapse.http.site import SynapseRequest
from synapse.logging.opentracing import active_span, force_tracing, start_active_span
from synapse.types import Requester, create_requester
from synapse.util.cancellation import cancellable

from . import GUEST_DEVICE_ID
from .base import BaseAuth

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class InternalAuth(BaseAuth):
    """
    This class contains functions for authenticating users of our client-server API.
    """

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.clock = hs.get_clock()
        self._account_validity_handler = hs.get_account_validity_handler()
        self._macaroon_generator = hs.get_macaroon_generator()

        self._force_tracing_for_users = hs.config.tracing.force_tracing_for_users

    @cancellable
    async def get_user_by_req(
        self,
        request: SynapseRequest,
        allow_guest: bool = False,
        allow_expired: bool = False,
        allow_locked: bool = False,
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
                request, allow_guest, allow_expired, allow_locked
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
        allow_locked: bool,
    ) -> Requester:
        """Helper for get_user_by_req

        Once get_user_by_req has set up the opentracing span, this does the actual work.
        """
        try:
            access_token = self.get_access_token_from_request(request)

            # First check if it could be a request from an appservice
            requester = await self.get_appservice_user(request, access_token)
            if not requester:
                # If not, it should be from a regular user
                requester = await self.get_user_by_access_token(
                    access_token, allow_expired=allow_expired
                )

                # Deny the request if the user account is locked.
                if not allow_locked and await self.store.get_user_locked_status(
                    requester.user.to_string()
                ):
                    raise AuthError(
                        401,
                        "User account has been locked",
                        errcode=Codes.USER_LOCKED,
                        additional_fields={"soft_logout": True},
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

            await self._record_request(request, requester)

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
            if not stored_user.is_guest:
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
