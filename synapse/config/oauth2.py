# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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


class OAuth2Config(Config):
    """OAuth2 Configuration

    oauth_server_url: URL of OAuth2 server
    """

    section = "oauth2"

    def read_config(self, config, **kwargs):
        oauth2_config = config.get("oauth2_config", None)
        if oauth2_config:
            self.oauth2_enabled = oauth2_config.get("enabled", True)
            self.oauth2_server_authorization_url = oauth2_config["server_authorization_url"]
            self.oauth2_server_token_url = oauth2_config["server_token_url"]
            self.oauth2_server_userinfo_url = oauth2_config["server_userinfo_url"]
            self.oauth2_client_id = oauth2_config["client_id"]
            self.oauth2_client_secret = oauth2_config["client_secret"]
        else:
            self.oauth2_enabled = False
            self.oauth2_server_authorization_url = None
            self.oauth2_server_token_url = None
            self.oauth2_server_userinfo_url = None
            self.oauth2_client_id = None
            self.oauth2_client_secret = None

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return """
        # Enable OAuth2 for registration and login.
        #
        #oauth_config:
        #   enabled: true
        #   server_authorization_url: "https://oauth.server.com/oauth2/authorize"
        #   server_token_url: "https://oauth.server.com/oauth2/token"
        #   server_userinfo_url: "https://oauth.server.com/oauth2/userinfo"
        #   client_id: "FORM_OAUTH_SERVER"
        #   client_secret: "FORM_OAUTH_SERVER"
        """
