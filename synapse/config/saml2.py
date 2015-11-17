# -*- coding: utf-8 -*-
# Copyright 2015 Ericsson
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


class SAML2Config(Config):
    """SAML2 Configuration
    Synapse uses pysaml2 libraries for providing SAML2 support

    config_path:      Path to the sp_conf.py configuration file
    idp_redirect_url: Identity provider URL which will redirect
                      the user back to /login/saml2 with proper info.

    sp_conf.py file is something like:
    https://github.com/rohe/pysaml2/blob/master/example/sp-repoze/sp_conf.py.example

    More information: https://pythonhosted.org/pysaml2/howto/config.html
    """

    def read_config(self, config):
        saml2_config = config.get("saml2_config", None)
        if saml2_config:
            self.saml2_enabled = saml2_config.get("enabled", True)
            self.saml2_config_path = saml2_config["config_path"]
            self.saml2_idp_redirect_url = saml2_config["idp_redirect_url"]
        else:
            self.saml2_enabled = False
            self.saml2_config_path = None
            self.saml2_idp_redirect_url = None

    def default_config(self, config_dir_path, server_name, **kwargs):
        return """
        # Enable SAML2 for registration and login. Uses pysaml2
        # config_path:      Path to the sp_conf.py configuration file
        # idp_redirect_url: Identity provider URL which will redirect
        #                   the user back to /login/saml2 with proper info.
        # See pysaml2 docs for format of config.
        #saml2_config:
        #   enabled: true
        #   config_path: "%s/sp_conf.py"
        #   idp_redirect_url: "http://%s/idp"
        """ % (config_dir_path, server_name)
