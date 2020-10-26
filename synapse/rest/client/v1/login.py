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
from typing import Awaitable, Callable, Dict, Optional

from synapse.api.errors import Codes, LoginError, SynapseError
from synapse.api.ratelimiting import Ratelimiter
from synapse.appservice import ApplicationService
from synapse.handlers.auth import (
    convert_client_dict_legacy_fields_to_identifier,
    login_id_phone_to_thirdparty,
)
from synapse.http.server import finish_request
from synapse.http.servlet import (
    RestServlet,
    parse_json_object_from_request,
    parse_string,
)
from synapse.http.site import SynapseRequest
from synapse.rest.client.v2_alpha._base import client_patterns
from synapse.rest.well_known import WellKnownBuilder
from synapse.types import JsonDict, UserID
from synapse.util.threepids import canonicalise_email

logger = logging.getLogger(__name__)


class LoginRestServlet(RestServlet):
    PATTERNS = client_patterns("/login$", v1=True)
    CAS_TYPE = "m.login.cas"
    SSO_TYPE = "m.login.sso"
    TOKEN_TYPE = "m.login.token"
    JWT_TYPE = "org.matrix.login.jwt"
    JWT_TYPE_DEPRECATED = "m.login.jwt"
    APPSERVICE_TYPE = "uk.half-shot.msc2778.login.application_service"

    def __init__(self, hs):
        super().__init__()
        self.hs = hs

        # JWT configuration variables.
        self.jwt_enabled = hs.config.jwt_enabled
        self.jwt_secret = hs.config.jwt_secret
        self.jwt_algorithm = hs.config.jwt_algorithm
        self.jwt_issuer = hs.config.jwt_issuer
        self.jwt_audiences = hs.config.jwt_audiences

        # SSO configuration.
        self.saml2_enabled = hs.config.saml2_enabled
        self.cas_enabled = hs.config.cas_enabled
        self.oidc_enabled = hs.config.oidc_enabled

        self.auth = hs.get_auth()

        self.auth_handler = self.hs.get_auth_handler()
        self.registration_handler = hs.get_registration_handler()
        self._well_known_builder = WellKnownBuilder(hs)
        self._address_ratelimiter = Ratelimiter(
            clock=hs.get_clock(),
            rate_hz=self.hs.config.rc_login_address.per_second,
            burst_count=self.hs.config.rc_login_address.burst_count,
        )
        self._account_ratelimiter = Ratelimiter(
            clock=hs.get_clock(),
            rate_hz=self.hs.config.rc_login_account.per_second,
            burst_count=self.hs.config.rc_login_account.burst_count,
        )
        self._failed_attempts_ratelimiter = Ratelimiter(
            clock=hs.get_clock(),
            rate_hz=self.hs.config.rc_login_failed_attempts.per_second,
            burst_count=self.hs.config.rc_login_failed_attempts.burst_count,
        )

    def on_GET(self, request: SynapseRequest):
        flows = []
        if self.jwt_enabled:
            flows.append({"type": LoginRestServlet.JWT_TYPE})
            flows.append({"type": LoginRestServlet.JWT_TYPE_DEPRECATED})

        if self.cas_enabled:
            # we advertise CAS for backwards compat, though MSC1721 renamed it
            # to SSO.
            flows.append({"type": LoginRestServlet.CAS_TYPE})

        if self.cas_enabled or self.saml2_enabled or self.oidc_enabled:
            flows.append({"type": LoginRestServlet.SSO_TYPE})
            # While its valid for us to advertise this login type generally,
            # synapse currently only gives out these tokens as part of the
            # SSO login flow.
            # Generally we don't want to advertise login flows that clients
            # don't know how to implement, since they (currently) will always
            # fall back to the fallback API if they don't understand one of the
            # login flow types returned.
            flows.append({"type": LoginRestServlet.TOKEN_TYPE})

        flows.extend(
            ({"type": t} for t in self.auth_handler.get_supported_login_types())
        )

        flows.append({"type": LoginRestServlet.APPSERVICE_TYPE})

        return 200, {"flows": flows}

    async def on_POST(self, request: SynapseRequest):
        self._address_ratelimiter.ratelimit(request.getClientIP())

        login_submission = parse_json_object_from_request(request)

        try:
            if login_submission["type"] == LoginRestServlet.APPSERVICE_TYPE:
                appservice = self.auth.get_appservice_by_req(request)
                result = await self._do_appservice_login(login_submission, appservice)
            elif self.jwt_enabled and (
                login_submission["type"] == LoginRestServlet.JWT_TYPE
                or login_submission["type"] == LoginRestServlet.JWT_TYPE_DEPRECATED
            ):
                result = await self._do_jwt_login(login_submission)
            elif login_submission["type"] == LoginRestServlet.TOKEN_TYPE:
                result = await self._do_token_login(login_submission)
            else:
                result = await self._do_other_login(login_submission)
        except KeyError:
            raise SynapseError(400, "Missing JSON keys.")

        well_known_data = self._well_known_builder.get_well_known()
        if well_known_data:
            result["well_known"] = well_known_data
        return 200, result

    def _get_qualified_user_id(self, identifier):
        if identifier["type"] != "m.id.user":
            raise SynapseError(400, "Unknown login identifier type")
        if "user" not in identifier:
            raise SynapseError(400, "User identifier is missing 'user' key")

        if identifier["user"].startswith("@"):
            return identifier["user"]
        else:
            return UserID(identifier["user"], self.hs.hostname).to_string()

    async def _do_appservice_login(
        self, login_submission: JsonDict, appservice: ApplicationService
    ):
        logger.info(
            "Got appservice login request with identifier: %r",
            login_submission.get("identifier"),
        )

        identifier = convert_client_dict_legacy_fields_to_identifier(login_submission)
        qualified_user_id = self._get_qualified_user_id(identifier)

        if not appservice.is_interested_in_user(qualified_user_id):
            raise LoginError(403, "Invalid access_token", errcode=Codes.FORBIDDEN)

        return await self._complete_login(qualified_user_id, login_submission)

    async def _do_other_login(self, login_submission: JsonDict) -> Dict[str, str]:
        """Handle non-token/saml/jwt logins

        Args:
            login_submission:

        Returns:
            HTTP response
        """
        # Log the request we got, but only certain fields to minimise the chance of
        # logging someone's password (even if they accidentally put it in the wrong
        # field)
        logger.info(
            "Got login request with identifier: %r, medium: %r, address: %r, user: %r",
            login_submission.get("identifier"),
            login_submission.get("medium"),
            login_submission.get("address"),
            login_submission.get("user"),
        )
        identifier = convert_client_dict_legacy_fields_to_identifier(login_submission)

        # convert phone type identifiers to generic threepids
        if identifier["type"] == "m.id.phone":
            identifier = login_id_phone_to_thirdparty(identifier)

        # convert threepid identifiers to user IDs
        if identifier["type"] == "m.id.thirdparty":
            address = identifier.get("address")
            medium = identifier.get("medium")

            if medium is None or address is None:
                raise SynapseError(400, "Invalid thirdparty identifier")

            # For emails, canonicalise the address.
            # We store all email addresses canonicalised in the DB.
            # (See add_threepid in synapse/handlers/auth.py)
            if medium == "email":
                try:
                    address = canonicalise_email(address)
                except ValueError as e:
                    raise SynapseError(400, str(e))

            # We also apply account rate limiting using the 3PID as a key, as
            # otherwise using 3PID bypasses the ratelimiting based on user ID.
            self._failed_attempts_ratelimiter.ratelimit((medium, address), update=False)

            # Check for login providers that support 3pid login types
            (
                canonical_user_id,
                callback_3pid,
            ) = await self.auth_handler.check_password_provider_3pid(
                medium, address, login_submission["password"]
            )
            if canonical_user_id:
                # Authentication through password provider and 3pid succeeded

                result = await self._complete_login(
                    canonical_user_id, login_submission, callback_3pid
                )
                return result

            # No password providers were able to handle this 3pid
            # Check local store
            user_id = await self.hs.get_datastore().get_user_id_by_threepid(
                medium, address
            )
            if not user_id:
                logger.warning(
                    "unknown 3pid identifier medium %s, address %r", medium, address
                )
                # We mark that we've failed to log in here, as
                # `check_password_provider_3pid` might have returned `None` due
                # to an incorrect password, rather than the account not
                # existing.
                #
                # If it returned None but the 3PID was bound then we won't hit
                # this code path, which is fine as then the per-user ratelimit
                # will kick in below.
                self._failed_attempts_ratelimiter.can_do_action((medium, address))
                raise LoginError(403, "", errcode=Codes.FORBIDDEN)

            identifier = {"type": "m.id.user", "user": user_id}

        # by this point, the identifier should be an m.id.user: if it's anything
        # else, we haven't understood it.
        qualified_user_id = self._get_qualified_user_id(identifier)

        # Check if we've hit the failed ratelimit (but don't update it)
        self._failed_attempts_ratelimiter.ratelimit(
            qualified_user_id.lower(), update=False
        )

        try:
            canonical_user_id, callback = await self.auth_handler.validate_login(
                identifier["user"], login_submission
            )
        except LoginError:
            # The user has failed to log in, so we need to update the rate
            # limiter. Using `can_do_action` avoids us raising a ratelimit
            # exception and masking the LoginError. The actual ratelimiting
            # should have happened above.
            self._failed_attempts_ratelimiter.can_do_action(qualified_user_id.lower())
            raise

        result = await self._complete_login(
            canonical_user_id, login_submission, callback
        )
        return result

    async def _complete_login(
        self,
        user_id: str,
        login_submission: JsonDict,
        callback: Optional[Callable[[Dict[str, str]], Awaitable[None]]] = None,
        create_non_existent_users: bool = False,
    ) -> Dict[str, str]:
        """Called when we've successfully authed the user and now need to
        actually login them in (e.g. create devices). This gets called on
        all successful logins.

        Applies the ratelimiting for successful login attempts against an
        account.

        Args:
            user_id: ID of the user to register.
            login_submission: Dictionary of login information.
            callback: Callback function to run after login.
            create_non_existent_users: Whether to create the user if they don't
                exist. Defaults to False.

        Returns:
            result: Dictionary of account information after successful login.
        """

        # Before we actually log them in we check if they've already logged in
        # too often. This happens here rather than before as we don't
        # necessarily know the user before now.
        self._account_ratelimiter.ratelimit(user_id.lower())

        if create_non_existent_users:
            canonical_uid = await self.auth_handler.check_user_exists(user_id)
            if not canonical_uid:
                canonical_uid = await self.registration_handler.register_user(
                    localpart=UserID.from_string(user_id).localpart
                )
            user_id = canonical_uid

        device_id = login_submission.get("device_id")
        initial_display_name = login_submission.get("initial_device_display_name")
        device_id, access_token = await self.registration_handler.register_device(
            user_id, device_id, initial_display_name
        )

        result = {
            "user_id": user_id,
            "access_token": access_token,
            "home_server": self.hs.hostname,
            "device_id": device_id,
        }

        if callback is not None:
            await callback(result)

        return result

    async def _do_token_login(self, login_submission: JsonDict) -> Dict[str, str]:
        """
        Handle the final stage of SSO login.

        Args:
             login_submission: The JSON request body.

        Returns:
            The body of the JSON response.
        """
        token = login_submission["token"]
        auth_handler = self.auth_handler
        user_id = await auth_handler.validate_short_term_login_token_and_get_user_id(
            token
        )

        return await self._complete_login(
            user_id, login_submission, self.auth_handler._sso_login_callback
        )

    async def _do_jwt_login(self, login_submission: JsonDict) -> Dict[str, str]:
        token = login_submission.get("token", None)
        if token is None:
            raise LoginError(
                403, "Token field for JWT is missing", errcode=Codes.FORBIDDEN
            )

        import jwt

        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=[self.jwt_algorithm],
                issuer=self.jwt_issuer,
                audience=self.jwt_audiences,
            )
        except jwt.PyJWTError as e:
            # A JWT error occurred, return some info back to the client.
            raise LoginError(
                403, "JWT validation failed: %s" % (str(e),), errcode=Codes.FORBIDDEN,
            )

        user = payload.get("sub", None)
        if user is None:
            raise LoginError(403, "Invalid JWT", errcode=Codes.FORBIDDEN)

        user_id = UserID(user, self.hs.hostname).to_string()
        result = await self._complete_login(
            user_id, login_submission, create_non_existent_users=True
        )
        return result


class BaseSSORedirectServlet(RestServlet):
    """Common base class for /login/sso/redirect impls"""

    PATTERNS = client_patterns("/login/(cas|sso)/redirect", v1=True)

    async def on_GET(self, request: SynapseRequest):
        args = request.args
        if b"redirectUrl" not in args:
            return 400, "Redirect URL not specified for SSO auth"
        client_redirect_url = args[b"redirectUrl"][0]
        sso_url = await self.get_sso_url(request, client_redirect_url)
        request.redirect(sso_url)
        finish_request(request)

    async def get_sso_url(
        self, request: SynapseRequest, client_redirect_url: bytes
    ) -> bytes:
        """Get the URL to redirect to, to perform SSO auth

        Args:
            request: The client request to redirect.
            client_redirect_url: the URL that we should redirect the
                client to when everything is done

        Returns:
            URL to redirect to
        """
        # to be implemented by subclasses
        raise NotImplementedError()


class CasRedirectServlet(BaseSSORedirectServlet):
    def __init__(self, hs):
        self._cas_handler = hs.get_cas_handler()

    async def get_sso_url(
        self, request: SynapseRequest, client_redirect_url: bytes
    ) -> bytes:
        return self._cas_handler.get_redirect_url(
            {"redirectUrl": client_redirect_url}
        ).encode("ascii")


class CasTicketServlet(RestServlet):
    PATTERNS = client_patterns("/login/cas/ticket", v1=True)

    def __init__(self, hs):
        super().__init__()
        self._cas_handler = hs.get_cas_handler()

    async def on_GET(self, request: SynapseRequest) -> None:
        client_redirect_url = parse_string(request, "redirectUrl")
        ticket = parse_string(request, "ticket", required=True)

        # Maybe get a session ID (if this ticket is from user interactive
        # authentication).
        session = parse_string(request, "session")

        # Either client_redirect_url or session must be provided.
        if not client_redirect_url and not session:
            message = "Missing string query parameter redirectUrl or session"
            raise SynapseError(400, message, errcode=Codes.MISSING_PARAM)

        await self._cas_handler.handle_ticket(
            request, ticket, client_redirect_url, session
        )


class SAMLRedirectServlet(BaseSSORedirectServlet):
    PATTERNS = client_patterns("/login/sso/redirect", v1=True)

    def __init__(self, hs):
        self._saml_handler = hs.get_saml_handler()

    async def get_sso_url(
        self, request: SynapseRequest, client_redirect_url: bytes
    ) -> bytes:
        return self._saml_handler.handle_redirect_request(client_redirect_url)


class OIDCRedirectServlet(BaseSSORedirectServlet):
    """Implementation for /login/sso/redirect for the OIDC login flow."""

    PATTERNS = client_patterns("/login/sso/redirect", v1=True)

    def __init__(self, hs):
        self._oidc_handler = hs.get_oidc_handler()

    async def get_sso_url(
        self, request: SynapseRequest, client_redirect_url: bytes
    ) -> bytes:
        return await self._oidc_handler.handle_redirect_request(
            request, client_redirect_url
        )


def register_servlets(hs, http_server):
    LoginRestServlet(hs).register(http_server)
    if hs.config.cas_enabled:
        CasRedirectServlet(hs).register(http_server)
        CasTicketServlet(hs).register(http_server)
    elif hs.config.saml2_enabled:
        SAMLRedirectServlet(hs).register(http_server)
    elif hs.config.oidc_enabled:
        OIDCRedirectServlet(hs).register(http_server)
