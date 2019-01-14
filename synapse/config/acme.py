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


class ACMEConfig(Config):
    """
    Configuration for the ACME subservice.
    """

    def read_config(self, config):
        acme_config = config.get("acme", {})
        self.acme_enabled = acme_config.get("enabled", False)
        self.acme_url = acme_config.get(
            "url", "https://acme-v01.api.letsencrypt.org/directory"
        )
        self.acme_port = acme_config.get("port", 8449)

    def default_config(self, config_dir_path, server_name, **kwargs):
        return """
        ## Support for ACME certificate auto-provisioning.
        # acme:
        #    enabled: false
        ##   ACME path. Default: https://acme-staging.api.letsencrypt.org/directory
        #    url: https://acme-v01.api.letsencrypt.org/directory
        ##   Port number (to listen for the HTTP-01 challenge).
        ##   Using port 80 requires utilising something like authbind, or proxying to it.
        #    port: 8449
        """
