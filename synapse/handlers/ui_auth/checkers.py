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
from typing import Any

from twisted.web.client import PartialDownloadError

from synapse.api.constants import LoginType
from synapse.api.errors import Codes, LoginError, SynapseError
from synapse.config.emailconfig import ThreepidBehaviour
from synapse.util import json_decoder

logger = logging.getLogger(__name__)


class UserInteractiveAuthChecker:
    """Abstract base class for an interactive auth checker"""

    def __init__(self, hs):
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
            SynapseError if authentication failed

        Returns:
            The result of authentication (to pass back to the client?)
        """
        raise NotImplementedError()


class DummyAuthChecker(UserInteractiveAuthChecker):
    AUTH_TYPE = LoginType.DUMMY

    def is_enabled(self):
        return True

    async def check_auth(self, authdict, clientip):
        return True


class TermsAuthChecker(UserInteractiveAuthChecker):
    AUTH_TYPE = LoginType.TERMS

    def is_enabled(self):
        return True

    async def check_auth(self, authdict, clientip):
        return True


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

    async def check_auth(self, authdict, clientip):
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
        raise LoginError(401, "", errcode=Codes.UNAUTHORIZED)


class _BaseThreepidAuthChecker:
    def __init__(self, hs):
        self.hs = hs
        self.store = hs.get_datastore()

    async def _check_threepid(self, medium, authdict):
        if "threepid_creds" not in authdict:
            raise LoginError(400, "Missing threepid_creds", Codes.MISSING_PARAM)

        threepid_creds = authdict["threepid_creds"]

        identity_handler = self.hs.get_identity_handler()

        logger.info("Getting validated threepid. threepidcreds: %r", (threepid_creds,))

        # msisdns are currently always ThreepidBehaviour.REMOTE
        if medium == "msisdn":
            if not self.hs.config.account_threepid_delegate_msisdn:
                raise SynapseError(
                    400, "Phone number verification is not enabled on this homeserver"
                )
            threepid = await identity_handler.threepid_from_creds(
                self.hs.config.account_threepid_delegate_msisdn, threepid_creds
            )
        elif medium == "email":
            if self.hs.config.threepid_behaviour_email == ThreepidBehaviour.REMOTE:
                assert self.hs.config.account_threepid_delegate_email
                threepid = await identity_handler.threepid_from_creds(
                    self.hs.config.account_threepid_delegate_email, threepid_creds
                )
            elif self.hs.config.threepid_behaviour_email == ThreepidBehaviour.LOCAL:
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
        return self.hs.config.threepid_behaviour_email in (
            ThreepidBehaviour.REMOTE,
            ThreepidBehaviour.LOCAL,
        )

    async def check_auth(self, authdict, clientip):
        return await self._check_threepid("email", authdict)


class MsisdnAuthChecker(UserInteractiveAuthChecker, _BaseThreepidAuthChecker):
    AUTH_TYPE = LoginType.MSISDN

    def __init__(self, hs):
        UserInteractiveAuthChecker.__init__(self, hs)
        _BaseThreepidAuthChecker.__init__(self, hs)

    def is_enabled(self):
        return bool(self.hs.config.account_threepid_delegate_msisdn)

    async def check_auth(self, authdict, clientip):
        return await self._check_threepid("msisdn", authdict)


INTERACTIVE_AUTH_CHECKERS = [
    DummyAuthChecker,
    TermsAuthChecker,
    RecaptchaAuthChecker,
    EmailIdentityAuthChecker,
    MsisdnAuthChecker,
]
"""A list of UserInteractiveAuthChecker classes"""
