# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd.
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

"""Contains the URL paths to prefix various aspects of the server with. """
import hmac
from hashlib import sha256

from six.moves.urllib.parse import urlencode

from synapse.config import ConfigError

CLIENT_PREFIX = "/_matrix/client/api/v1"
CLIENT_V2_ALPHA_PREFIX = "/_matrix/client/v2_alpha"
FEDERATION_PREFIX = "/_matrix/federation/v1"
STATIC_PREFIX = "/_matrix/static"
WEB_CLIENT_PREFIX = "/_matrix/client"
CONTENT_REPO_PREFIX = "/_matrix/content"
SERVER_KEY_PREFIX = "/_matrix/key/v1"
SERVER_KEY_V2_PREFIX = "/_matrix/key/v2"
MEDIA_PREFIX = "/_matrix/media/r0"
LEGACY_MEDIA_PREFIX = "/_matrix/media/v1"


class ConsentURIBuilder(object):
    def __init__(self, hs_config):
        """
        Args:
            hs_config (synapse.config.homeserver.HomeServerConfig):
        """
        if hs_config.form_secret is None:
            raise ConfigError(
                "form_secret not set in config",
            )
        if hs_config.public_baseurl is None:
            raise ConfigError(
                "public_baseurl not set in config",
            )

        self._hmac_secret = hs_config.form_secret.encode("utf-8")
        self._public_baseurl = hs_config.public_baseurl

    def build_user_consent_uri(self, user_id):
        """Build a URI which we can give to the user to do their privacy
        policy consent

        Args:
            user_id (str): mxid or username of user

        Returns
            (str) the URI where the user can do consent
        """
        mac = hmac.new(
            key=self._hmac_secret,
            msg=user_id,
            digestmod=sha256,
        ).hexdigest()
        consent_uri = "%s_matrix/consent?%s" % (
            self._public_baseurl,
            urlencode({
                "u": user_id,
                "h": mac
            }),
        )
        return consent_uri
