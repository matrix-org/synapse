# Copyright 2019 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING, Any

from twisted.web.client import PartialDownloadError

from synapse.api.constants import LoginType
from synapse.api.errors import Codes, LoginError, SynapseError
from synapse.util import json_decoder

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class UserInteractiveAuthChecker:
    """Abstract base class for an interactive auth checker"""

    def __init__(self, hs: "HomeServer"):
        pass

    def is_enabled(self) -> bool:
        """Check if the configuration of the homeserver allows this checker to work

        Returns:
            True if this login type is enabled.
        """

    async def check_auth(self, authdict: dict, clientip: str) -> Any:
        """Given the authentication dict from the client, attempt to check this step

        Args:
            authdict: authentication dictionary from the client
            clientip: The IP address of the client.

        Raises:
            LoginError if authentication failed.

        Returns:
            The result of authentication (to pass back to the client?)
        """
        raise NotImplementedError()


class DummyAuthChecker(UserInteractiveAuthChecker):
    AUTH_TYPE = LoginType.DUMMY

    def is_enabled(self) -> bool:
        return True

    async def check_auth(self, authdict: dict, clientip: str) -> Any:
        return True


class TermsAuthChecker(UserInteractiveAuthChecker):
    AUTH_TYPE = LoginType.TERMS

    def is_enabled(self) -> bool:
        return True

    async def check_auth(self, authdict: dict, clientip: str) -> Any:
        return True


class RecaptchaAuthChecker(UserInteractiveAuthChecker):
    AUTH_TYPE = LoginType.RECAPTCHA

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self._enabled = bool(hs.config.captcha.recaptcha_private_key)
        self._http_client = hs.get_proxied_http_client()
        self._url = hs.config.captcha.recaptcha_siteverify_api
        self._secret = hs.config.captcha.recaptcha_private_key

    def is_enabled(self) -> bool:
        return self._enabled

    async def check_auth(self, authdict: dict, clientip: str) -> Any:
        try:
            user_response = authdict["response"]
        except KeyError:
            # Client tried to provide captcha but didn't give the parameter:
            # bad request.
            raise LoginError(
                400, "Captcha response is required", errcode=Codes.CAPTCHA_NEEDED
            )

        logger.info(
            "Submitting recaptcha response %s with remoteip %s", user_response, clientip
        )

        # TODO: get this from the homeserver rather than creating a new one for
        # each request
        try:
            assert self._secret is not None

            resp_body = await self._http_client.post_urlencoded_get_json(
                self._url,
                args={
                    "secret": self._secret,
                    "response": user_response,
                    "remoteip": clientip,
                },
            )
        except PartialDownloadError as pde:
            # Twisted is silly
            data = pde.response
            # For mypy's benefit. A general Error.response is Optional[bytes], but
            # a PartialDownloadError.response should be bytes AFAICS.
            assert data is not None
            resp_body = json_decoder.decode(data.decode("utf-8"))

        if "success" in resp_body:
            # Note that we do NOT check the hostname here: we explicitly
            # intend the CAPTCHA to be presented by whatever client the
            # user is using, we just care that they have completed a CAPTCHA.
            logger.info(
                "%s reCAPTCHA from hostname %s",
                "Successful" if resp_body["success"] else "Failed",
                resp_body.get("hostname"),
            )
            if resp_body["success"]:
                return True
        raise LoginError(
            401, "Captcha authentication failed", errcode=Codes.UNAUTHORIZED
        )


class _BaseThreepidAuthChecker:
    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.store = hs.get_datastores().main

    async def _check_threepid(self, medium: str, authdict: dict) -> dict:
        if "threepid_creds" not in authdict:
            raise LoginError(400, "Missing threepid_creds", Codes.MISSING_PARAM)

        threepid_creds = authdict["threepid_creds"]

        identity_handler = self.hs.get_identity_handler()

        logger.info("Getting validated threepid. threepidcreds: %r", (threepid_creds,))

        # msisdns are currently always verified via the IS
        if medium == "msisdn":
            if not self.hs.config.registration.account_threepid_delegate_msisdn:
                raise SynapseError(
                    400, "Phone number verification is not enabled on this homeserver"
                )
            threepid = await identity_handler.threepid_from_creds(
                self.hs.config.registration.account_threepid_delegate_msisdn,
                threepid_creds,
            )
        elif medium == "email":
            if self.hs.config.email.can_verify_email:
                threepid = None
                row = await self.store.get_threepid_validation_session(
                    medium,
                    threepid_creds["client_secret"],
                    sid=threepid_creds["sid"],
                    validated=True,
                )

                if row:
                    threepid = {
                        "medium": row["medium"],
                        "address": row["address"],
                        "validated_at": row["validated_at"],
                    }

                    # Valid threepid returned, delete from the db
                    await self.store.delete_threepid_session(threepid_creds["sid"])
            else:
                raise SynapseError(
                    400, "Email address verification is not enabled on this homeserver"
                )
        else:
            # this can't happen!
            raise AssertionError("Unrecognized threepid medium: %s" % (medium,))

        if not threepid:
            raise LoginError(
                401, "Unable to get validated threepid", errcode=Codes.UNAUTHORIZED
            )

        if threepid["medium"] != medium:
            raise LoginError(
                401,
                "Expecting threepid of type '%s', got '%s'"
                % (medium, threepid["medium"]),
                errcode=Codes.UNAUTHORIZED,
            )

        threepid["threepid_creds"] = authdict["threepid_creds"]

        return threepid


class EmailIdentityAuthChecker(UserInteractiveAuthChecker, _BaseThreepidAuthChecker):
    AUTH_TYPE = LoginType.EMAIL_IDENTITY

    def __init__(self, hs: "HomeServer"):
        UserInteractiveAuthChecker.__init__(self, hs)
        _BaseThreepidAuthChecker.__init__(self, hs)

    def is_enabled(self) -> bool:
        return self.hs.config.email.can_verify_email

    async def check_auth(self, authdict: dict, clientip: str) -> Any:
        return await self._check_threepid("email", authdict)


class MsisdnAuthChecker(UserInteractiveAuthChecker, _BaseThreepidAuthChecker):
    AUTH_TYPE = LoginType.MSISDN

    def __init__(self, hs: "HomeServer"):
        UserInteractiveAuthChecker.__init__(self, hs)
        _BaseThreepidAuthChecker.__init__(self, hs)

    def is_enabled(self) -> bool:
        return bool(self.hs.config.registration.account_threepid_delegate_msisdn)

    async def check_auth(self, authdict: dict, clientip: str) -> Any:
        return await self._check_threepid("msisdn", authdict)


class RegistrationTokenAuthChecker(UserInteractiveAuthChecker):
    AUTH_TYPE = LoginType.REGISTRATION_TOKEN

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.hs = hs
        self._enabled = bool(
            hs.config.registration.registration_requires_token
        ) or bool(hs.config.registration.enable_registration_token_3pid_bypass)
        self.store = hs.get_datastores().main

    def is_enabled(self) -> bool:
        return self._enabled

    async def check_auth(self, authdict: dict, clientip: str) -> Any:
        if "token" not in authdict:
            raise LoginError(400, "Missing registration token", Codes.MISSING_PARAM)
        if not isinstance(authdict["token"], str):
            raise LoginError(
                400, "Registration token must be a string", Codes.INVALID_PARAM
            )
        if "session" not in authdict:
            raise LoginError(400, "Missing UIA session", Codes.MISSING_PARAM)

        # Get these here to avoid cyclic dependencies
        from synapse.handlers.ui_auth import UIAuthSessionDataConstants

        auth_handler = self.hs.get_auth_handler()

        session = authdict["session"]
        token = authdict["token"]

        # If the LoginType.REGISTRATION_TOKEN stage has already been completed,
        # return early to avoid incrementing `pending` again.
        stored_token = await auth_handler.get_session_data(
            session, UIAuthSessionDataConstants.REGISTRATION_TOKEN
        )
        if stored_token:
            if token != stored_token:
                raise LoginError(
                    400, "Registration token has changed", Codes.INVALID_PARAM
                )
            else:
                return token

        if await self.store.registration_token_is_valid(token):
            # Increment pending counter, so that if token has limited uses it
            # can't be used up by someone else in the meantime.
            await self.store.set_registration_token_pending(token)
            # Store the token in the UIA session, so that once registration
            # is complete `completed` can be incremented.
            await auth_handler.set_session_data(
                session,
                UIAuthSessionDataConstants.REGISTRATION_TOKEN,
                token,
            )
            # The token will be stored as the result of the authentication stage
            # in ui_auth_sessions_credentials. This allows the pending counter
            # for tokens to be decremented when expired sessions are deleted.
            return token
        else:
            raise LoginError(
                401, "Invalid registration token", errcode=Codes.UNAUTHORIZED
            )


INTERACTIVE_AUTH_CHECKERS = [
    DummyAuthChecker,
    TermsAuthChecker,
    RecaptchaAuthChecker,
    EmailIdentityAuthChecker,
    MsisdnAuthChecker,
    RegistrationTokenAuthChecker,
]
"""A list of UserInteractiveAuthChecker classes"""
