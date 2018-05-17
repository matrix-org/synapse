# -*- coding: utf-8 -*-
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

from ._base import Config

DEFAULT_CONFIG = """\
# User Consent configuration
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
# must also be configured for this to work.
#
# user_consent:
#   template_dir: res/templates/privacy
#   version: 1.0
#   server_notice_content:
#     msgtype: m.text
#     body: |
#       Pls do consent kthx
"""


class ConsentConfig(Config):
    def read_config(self, config):
        self.consent_config = config.get("user_consent")

    def default_config(self, **kwargs):
        return DEFAULT_CONFIG
