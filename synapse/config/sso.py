# Copyright 2020-2021 The Matrix.org Foundation C.I.C.
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

import attr

from ._base import Config

logger = logging.getLogger(__name__)

LEGACY_TEMPLATE_DIR_WARNING = """
This server's configuration file is using the deprecated 'template_dir' setting in the
'sso' section. Support for this setting has been deprecated and will be removed in a
future version of Synapse. Server admins should instead use the new
'custom_templates_directory' setting documented here:
https://matrix-org.github.io/synapse/latest/templates.html
---------------------------------------------------------------------------------------"""


@attr.s(frozen=True, auto_attribs=True)
class SsoAttributeRequirement:
    """Object describing a single requirement for SSO attributes."""

    attribute: str
    # If a value is not given, than the attribute must simply exist.
    value: Optional[str]

    JSON_SCHEMA = {
        "type": "object",
        "properties": {"attribute": {"type": "string"}, "value": {"type": "string"}},
        "required": ["attribute", "value"],
    }


class SSOConfig(Config):
    """SSO Configuration"""

    section = "sso"

    def read_config(self, config, **kwargs) -> None:
        sso_config: Dict[str, Any] = config.get("sso") or {}

        # The sso-specific template_dir
        self.sso_template_dir = sso_config.get("template_dir")
        if self.sso_template_dir is not None:
            logger.warning(LEGACY_TEMPLATE_DIR_WARNING)

        # Read templates from disk
        custom_template_directories = (
            self.root.server.custom_template_directory,
            self.sso_template_dir,
        )

        (
            self.sso_login_idp_picker_template,
            self.sso_redirect_confirm_template,
            self.sso_auth_confirm_template,
            self.sso_error_template,
            sso_account_deactivated_template,
            sso_auth_success_template,
            self.sso_auth_bad_user_template,
        ) = self.read_templates(
            [
                "sso_login_idp_picker.html",
                "sso_redirect_confirm.html",
                "sso_auth_confirm.html",
                "sso_error.html",
                "sso_account_deactivated.html",
                "sso_auth_success.html",
                "sso_auth_bad_user.html",
            ],
            (td for td in custom_template_directories if td),
        )

        # These templates have no placeholders, so render them here
        self.sso_account_deactivated_template = (
            sso_account_deactivated_template.render()
        )
        self.sso_auth_success_template = sso_auth_success_template.render()

        self.sso_client_whitelist = sso_config.get("client_whitelist") or []

        self.sso_update_profile_information = (
            sso_config.get("update_profile_information") or False
        )

        # Attempt to also whitelist the server's login fallback, since that fallback sets
        # the redirect URL to itself (so it can process the login token then return
        # gracefully to the client). This would make it pointless to ask the user for
        # confirmation, since the URL the confirmation page would be showing wouldn't be
        # the client's.
        login_fallback_url = (
            self.root.server.public_baseurl + "_matrix/static/client/login"
        )
        self.sso_client_whitelist.append(login_fallback_url)

    def generate_config_section(self, **kwargs) -> str:
        return """\
        # Additional settings to use with single-sign on systems such as OpenID Connect,
        # SAML2 and CAS.
        #
        # Server admins can configure custom templates for pages related to SSO. See
        # https://matrix-org.github.io/synapse/latest/templates.html for more information.
        #
        sso:
            # A list of client URLs which are whitelisted so that the user does not
            # have to confirm giving access to their account to the URL. Any client
            # whose URL starts with an entry in the following list will not be subject
            # to an additional confirmation step after the SSO login is completed.
            #
            # WARNING: An entry such as "https://my.client" is insecure, because it
            # will also match "https://my.client.evil.site", exposing your users to
            # phishing attacks from evil.site. To avoid this, include a slash after the
            # hostname: "https://my.client/".
            #
            # The login fallback page (used by clients that don't natively support the
            # required login flows) is whitelisted in addition to any URLs in this list.
            #
            # By default, this list contains only the login fallback page.
            #
            #client_whitelist:
            #  - https://riot.im/develop
            #  - https://my.custom.client/

            # Uncomment to keep a user's profile fields in sync with information from
            # the identity provider. Currently only syncing the displayname is
            # supported. Fields are checked on every SSO login, and are updated
            # if necessary.
            #
            # Note that enabling this option will override user profile information,
            # regardless of whether users have opted-out of syncing that
            # information when first signing in. Defaults to false.
            #
            #update_profile_information: true
        """
