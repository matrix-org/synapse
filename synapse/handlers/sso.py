# -*- coding: utf-8 -*-
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
from typing import TYPE_CHECKING, Awaitable, Callable, List, Optional

import attr

from synapse.handlers._base import BaseHandler
from synapse.http.server import respond_with_html
from synapse.types import UserID, contains_invalid_mxid_characters

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class MappingException(Exception):
    """Used to catch errors when mapping the UserInfo object
    """


@attr.s
class UserAttributes:
    localpart = attr.ib(type=str)
    display_name = attr.ib(type=Optional[str], default=None)
    emails = attr.ib(type=List[str], default=attr.Factory(list))


class SsoHandler(BaseHandler):
    # The number of attempts to ask the mapping provider for when generating an MXID.
    _MAP_USERNAME_RETRIES = 1000

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self._registration_handler = hs.get_registration_handler()
        self._error_template = hs.config.sso_error_template

    def render_error(
        self, request, error: str, error_description: Optional[str] = None
    ) -> None:
        """Renders the error template and responds with it.

        This is used to show errors to the user. The template of this page can
        be found under `synapse/res/templates/sso_error.html`.

        Args:
            request: The incoming request from the browser.
                We'll respond with an HTML page describing the error.
            error: A technical identifier for this error.
            error_description: A human-readable description of the error.
        """
        html = self._error_template.render(
            error=error, error_description=error_description
        )
        respond_with_html(request, 400, html)

    async def get_sso_user_by_remote_user_id(
        self, auth_provider_id: str, remote_user_id: str
    ) -> Optional[str]:
        """
        Maps the user ID of a remote IdP to a mxid for a previously seen user.

        If the user has not been seen yet, this will return None.

        Args:
            auth_provider_id: A unique identifier for this SSO provider, e.g.
                "oidc" or "saml".
            remote_user_id: The user ID according to the remote IdP. This might
                be an e-mail address, a GUID, or some other form. It must be
                unique and immutable.

        Returns:
            The mxid of a previously seen user.
        """
        logger.debug(
            "Looking for existing mapping for user %s:%s",
            auth_provider_id,
            remote_user_id,
        )

        # Check if we already have a mapping for this user.
        previously_registered_user_id = await self.store.get_user_by_external_id(
            auth_provider_id, remote_user_id,
        )

        # A match was found, return the user ID.
        if previously_registered_user_id is not None:
            logger.info(
                "Found existing mapping for IdP '%s' and remote_user_id '%s': %s",
                auth_provider_id,
                remote_user_id,
                previously_registered_user_id,
            )
            return previously_registered_user_id

        # No match.
        return None

    async def get_mxid_from_sso(
        self,
        auth_provider_id: str,
        remote_user_id: str,
        user_agent: str,
        ip_address: str,
        sso_to_matrix_id_mapper: Callable[[int], Awaitable[UserAttributes]],
        allow_existing_users: bool = False,
    ):
        """

        Args:
            auth_provider_id: A unique identifier for this SSO provider, e.g.
                "oidc" or "saml".
            remote_user_id: The unique identifier from the SSO provider.
            user_agent: The user agent of the client making the request.
            ip_address: The IP address of the client making the request.
            sso_to_matrix_id_mapper: A callable to generate the user attributes.
                The only parameter is an integer which represents the amount of
                times the returned mxid localpart mapping has failed.
            allow_existing_users: True if the localpart returned from the
                mapping provider can be linked to an existing matrix ID.

        Returns:
             The user ID associated with the SSO response.

        Raises:
            MappingException if there was a problem mapping the response to a user.
            RedirectException: some mapping providers may raise this if they need
                to redirect to an interstitial page.

        """
        # first of all, check if we already have a mapping for this user
        previously_registered_user_id = await self.get_sso_user_by_remote_user_id(
            auth_provider_id, remote_user_id,
        )
        if previously_registered_user_id:
            return previously_registered_user_id

        # Otherwise, generate a new user.
        for i in range(self._MAP_USERNAME_RETRIES):
            try:
                attributes = await sso_to_matrix_id_mapper(i)
            except Exception as e:
                raise MappingException(
                    "Could not extract user attributes from SSO response: " + str(e)
                )

            logger.debug(
                "Retrieved user attributes from user mapping provider: %r (attempt %d)",
                attributes,
                i,
            )

            if not attributes.localpart:
                raise MappingException(
                    "Error parsing SSO response: SSO mapping provider plugin "
                    "did not return a localpart value"
                )

            # Check if this mxid already exists
            user_id = UserID(attributes.localpart, self.server_name).to_string()
            users = await self.store.get_users_by_id_case_insensitive(user_id)
            if users and allow_existing_users:
                # If an existing matrix ID is returned, then use it.
                if len(users) == 1:
                    previously_registered_user_id = next(iter(users))
                elif user_id in users:
                    previously_registered_user_id = user_id
                else:
                    # Do not attempt to continue generating Matrix IDs.
                    raise MappingException(
                        "Attempted to login as '{}' but it matches more than one user inexactly: {}".format(
                            user_id, users
                        )
                    )

                # Future logins should also match this user ID.
                await self.store.record_user_external_id(
                    auth_provider_id, remote_user_id, previously_registered_user_id
                )

                return previously_registered_user_id

            elif not users:
                # This mxid is free
                break
        else:
            # Unable to generate a username in 1000 iterations
            # Break and return error to the user
            raise MappingException(
                "Unable to generate a Matrix ID from the SSO response"
            )

        # Since the localpart is provided via a potentially untrusted module,
        # ensure the MXID is valid before registering.
        if contains_invalid_mxid_characters(attributes.localpart):
            raise MappingException("localpart is invalid: %s" % (attributes.localpart,))

        logger.debug("Mapped SSO user to local part %s", attributes.localpart)
        registered_user_id = await self._registration_handler.register_user(
            localpart=attributes.localpart,
            default_display_name=attributes.display_name,
            bind_emails=attributes.emails,
            user_agent_ips=[(user_agent, ip_address)],
        )

        await self.store.record_user_external_id(
            auth_provider_id, remote_user_id, registered_user_id
        )
        return registered_user_id
