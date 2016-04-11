# -*- coding: utf-8 -*-
# Copyright 2015 Niklas Riekenbrauck
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


class LDAPConfig(Config):
    def read_config(self, config):
        ldap_config = config.get("ldap_config", None)
        if ldap_config:
            self.ldap_enabled = ldap_config.get("enabled", False)
            self.ldap_server = ldap_config["server"]
            self.ldap_port = ldap_config["port"]
            self.ldap_tls = ldap_config.get("tls", False)
            self.ldap_search_base = ldap_config["search_base"]
            self.ldap_search_property = ldap_config["search_property"]
            self.ldap_email_property = ldap_config["email_property"]
            self.ldap_full_name_property = ldap_config["full_name_property"]
        else:
            self.ldap_enabled = False
            self.ldap_server = None
            self.ldap_port = None
            self.ldap_tls = False
            self.ldap_search_base = None
            self.ldap_search_property = None
            self.ldap_email_property = None
            self.ldap_full_name_property = None

    def default_config(self, **kwargs):
        return """\
        # ldap_config:
        #   enabled: true
        #   server: "ldap://localhost"
        #   port: 389
        #   tls: false
        #   search_base: "ou=Users,dc=example,dc=com"
        #   search_property: "cn"
        #   email_property: "email"
        #   full_name_property: "givenName"
        """
