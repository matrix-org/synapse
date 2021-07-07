# Copyright 2018 New Vector Ltd
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

from os import path

from synapse.config import ConfigError

from ._base import Config

DEFAULT_CONFIG = """\
# User Consent configuration
#
# for detailed instructions, see
# https://matrix-org.github.io/synapse/latest/consent_tracking.html
#
# Parts of this section are required if enabling the 'consent' resource under
# 'listeners', in particular 'template_dir' and 'version'.
#
# 'template_dir' gives the location of the templates for the HTML forms.
# This directory should contain one subdirectory per language (eg, 'en', 'fr'),
# and each language directory should contain the policy document (named as
# '<version>.html') and a success page (success.html).
#
# 'version' specifies the 'current' version of the policy document. It defines
# the version to be served by the consent resource if there is no 'v'
# parameter.
#
# 'server_notice_content', if enabled, will send a user a "Server Notice"
# asking them to consent to the privacy policy. The 'server_notices' section
# must also be configured for this to work. Notices will *not* be sent to
# guest users unless 'send_server_notice_to_guests' is set to true.
#
# 'block_events_error', if set, will block any attempts to send events
# until the user consents to the privacy policy. The value of the setting is
# used as the text of the error.
#
# 'require_at_registration', if enabled, will add a step to the registration
# process, similar to how captcha works. Users will be required to accept the
# policy before their account is created.
#
# 'policy_name' is the display name of the policy users will see when registering
# for an account. Has no effect unless `require_at_registration` is enabled.
# Defaults to "Privacy Policy".
#
#user_consent:
#  template_dir: res/templates/privacy
#  version: 1.0
#  server_notice_content:
#    msgtype: m.text
#    body: >-
#      To continue using this homeserver you must review and agree to the
#      terms and conditions at %(consent_uri)s
#  send_server_notice_to_guests: true
#  block_events_error: >-
#    To continue using this homeserver you must review and agree to the
#    terms and conditions at %(consent_uri)s
#  require_at_registration: false
#  policy_name: Privacy Policy
#
"""


class ConsentConfig(Config):

    section = "consent"

    def __init__(self, *args):
        super().__init__(*args)

        self.user_consent_version = None
        self.user_consent_template_dir = None
        self.user_consent_server_notice_content = None
        self.user_consent_server_notice_to_guests = False
        self.block_events_without_consent_error = None
        self.user_consent_at_registration = False
        self.user_consent_policy_name = "Privacy Policy"

    def read_config(self, config, **kwargs):
        consent_config = config.get("user_consent")
        self.terms_template = self.read_template("terms.html")

        if consent_config is None:
            return
        self.user_consent_version = str(consent_config["version"])
        self.user_consent_template_dir = self.abspath(consent_config["template_dir"])
        if not path.isdir(self.user_consent_template_dir):
            raise ConfigError(
                "Could not find template directory '%s'"
                % (self.user_consent_template_dir,)
            )
        self.user_consent_server_notice_content = consent_config.get(
            "server_notice_content"
        )
        self.block_events_without_consent_error = consent_config.get(
            "block_events_error"
        )
        self.user_consent_server_notice_to_guests = bool(
            consent_config.get("send_server_notice_to_guests", False)
        )
        self.user_consent_at_registration = bool(
            consent_config.get("require_at_registration", False)
        )
        self.user_consent_policy_name = consent_config.get(
            "policy_name", "Privacy Policy"
        )

    def generate_config_section(self, **kwargs):
        return DEFAULT_CONFIG
