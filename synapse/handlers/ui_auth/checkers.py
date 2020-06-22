# -*- coding: utf-8 -*-
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
from typing import Any, Dict, Optional

from canonicaljson import json

from twisted.internet import defer
from twisted.web.client import PartialDownloadError

from synapse.api.constants import LoginType
from synapse.api.errors import Codes, LoginError, SynapseError
from synapse.config.emailconfig import ThreepidBehaviour, ThreepidService

logger = logging.getLogger(__name__)


class UserInteractiveAuthChecker:
    """Abstract base class for an interactive auth checker"""

    def __init__(self, hs):
        pass

    def is_enabled(self):
        """Check if the configuration of the homeserver allows this checker to work

        Returns:
            bool: True if this login type is enabled.
        """

    def check_auth(self, authdict, clientip):
        """Given the authentication dict from the client, attempt to check this step

        Args:
            authdict (dict): authentication dictionary from the client
            clientip (str): The IP address of the client.

        Raises:
            SynapseError if authentication failed

        Returns:
            Deferred: the result of authentication (to pass back to the client?)
        """
        raise NotImplementedError()


class DummyAuthChecker(UserInteractiveAuthChecker):
    AUTH_TYPE = LoginType.DUMMY

    def is_enabled(self):
        return True

    def check_auth(self, authdict, clientip):
        return defer.succeed(True)


class TermsAuthChecker(UserInteractiveAuthChecker):
    AUTH_TYPE = LoginType.TERMS

    def is_enabled(self):
        return True

    def check_auth(self, authdict, clientip):
        return defer.succeed(True)


class RecaptchaAuthChecker(UserInteractiveAuthChecker):
    AUTH_TYPE = LoginType.RECAPTCHA

    def __init__(self, hs):
        super().__init__(hs)
        self._enabled = bool(hs.config.recaptcha_private_key)
        self._http_client = hs.get_proxied_http_client()
        self._url = hs.config.recaptcha_siteverify_api
        self._secret = hs.config.recaptcha_private_key

    def is_enabled(self):
        return self._enabled

    @defer.inlineCallbacks
    def check_auth(self, authdict, clientip):
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
            resp_body = yield self._http_client.post_urlencoded_get_json(
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
            resp_body = json.loads(data)

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
        raise LoginError(401, "", errcode=Codes.UNAUTHORIZED)


class _BaseThreepidAuthChecker:
    def __init__(self, hs):
        self.hs = hs
        self.store = hs.get_datastore()

        self._account_threepid_delegate_email = (
            self.hs.config.account_threepid_delegate_email
        )
        self._account_threepid_delegate_msisdn = (
            self.hs.config.account_threepid_delegate_msisdn
        )

        self._threepid_behaviour_email_add_threepid = (
            self.hs.config.threepid_behaviour_email_add_threepid
        )
        self._threepid_behaviour_email_password_reset = (
            self.hs.config.threepid_behaviour_email_password_reset
        )

    async def _check_threepid(self, medium: str, authdict: Dict[str, Any]):
        if "threepid_creds" not in authdict:
            raise LoginError(400, "Missing threepid_creds", Codes.MISSING_PARAM)

        threepid_creds = authdict["threepid_creds"]

        identity_handler = self.hs.get_handlers().identity_handler

        logger.info("Getting validated threepid. threepidcreds: %r", (threepid_creds,))

        # msisdns are currently always ThreepidBehaviour.REMOTE
        if medium == "msisdn":
            if not self._account_threepid_delegate_msisdn:
                raise SynapseError(
                    400, "Phone number verification is not enabled on this homeserver"
                )
            threepid = await identity_handler.threepid_from_creds(
                self._account_threepid_delegate_msisdn, threepid_creds
            )
        elif medium == "email":
            # Determine why this check is happening. This will help us decide whether
            # Synapse or an account threepid delegate should complete the validation
            service = None  # type: Optional[ThreepidService]

            session = await self.store.get_threepid_validation_session(
                medium,
                threepid_creds["client_secret"],
                sid=threepid_creds["sid"],
                validated=True,
            )

            if session:
                # We found a local session.
                # Determine which service this was intended to authorise
                service = ThreepidService(session["service"])

                if service == ThreepidService.ADDING_THREEPID:
                    threepid_behaviour = self._threepid_behaviour_email_add_threepid
                elif service == ThreepidService.PASSWORD_RESET:
                    threepid_behaviour = self._threepid_behaviour_email_password_reset
                else:
                    raise SynapseError(500, "Unknown threepid service")
            else:
                # We can't find a local, matching session.
                # Do we have a threepid delegate configured?
                if not self.hs.config.account_threepid_delegate_email:
                    raise LoginError(401, "", errcode=Codes.UNAUTHORIZED)

                # We do. Presume that this is a remote session
                threepid_behaviour = ThreepidBehaviour.REMOTE

            if threepid_behaviour == ThreepidBehaviour.REMOTE:
                assert self.hs.config.account_threepid_delegate_email

                # Ask our threepid delegate about this validation attempt
                threepid = await identity_handler.threepid_from_creds(
                    self.hs.config.account_threepid_delegate_email, threepid_creds
                )
            elif threepid_behaviour == ThreepidBehaviour.LOCAL:
                # Attempt to validate locally
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
            raise LoginError(401, "", errcode=Codes.UNAUTHORIZED)

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

    def __init__(self, hs):
        UserInteractiveAuthChecker.__init__(self, hs)
        _BaseThreepidAuthChecker.__init__(self, hs)

    def is_enabled(self):
        add_threepid_enabled = (
            self.hs.config.threepid_behaviour_email_add_threepid
            != ThreepidBehaviour.OFF
        )
        password_reset_enabled = (
            self.hs.config.threepid_behaviour_email_password_reset
            != ThreepidBehaviour.OFF
        )
        return add_threepid_enabled or password_reset_enabled

    def check_auth(self, authdict, clientip):
        return defer.ensureDeferred(self._check_threepid("email", authdict))


class MsisdnAuthChecker(UserInteractiveAuthChecker, _BaseThreepidAuthChecker):
    AUTH_TYPE = LoginType.MSISDN

    def __init__(self, hs):
        UserInteractiveAuthChecker.__init__(self, hs)
        _BaseThreepidAuthChecker.__init__(self, hs)

    def is_enabled(self):
        return bool(self.hs.config.account_threepid_delegate_msisdn)

    def check_auth(self, authdict, clientip):
        return defer.ensureDeferred(self._check_threepid("msisdn", authdict))


INTERACTIVE_AUTH_CHECKERS = [
    DummyAuthChecker,
    TermsAuthChecker,
    RecaptchaAuthChecker,
    EmailIdentityAuthChecker,
    MsisdnAuthChecker,
]
"""A list of UserInteractiveAuthChecker classes"""
