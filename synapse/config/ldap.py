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

from ._base import Config, ConfigError


MISSING_LDAP3 = (
    "Missing ldap3 library. This is required for LDAP Authentication."
)


class LDAPMode(object):
    SIMPLE = "simple",
    SEARCH = "search",

    LIST = (SIMPLE, SEARCH)


class LDAPConfig(Config):
    def read_config(self, config):
        ldap_config = config.get("ldap_config", {})

        self.ldap_enabled = ldap_config.get("enabled", False)

        if self.ldap_enabled:
            # verify dependencies are available
            try:
                import ldap3
                ldap3  # to stop unused lint
            except ImportError:
                raise ConfigError(MISSING_LDAP3)

            self.ldap_mode = LDAPMode.SIMPLE

            # verify config sanity
            self.require_keys(ldap_config, [
                "uri",
                "base",
                "attributes",
            ])

            self.ldap_uri = ldap_config["uri"]
            self.ldap_start_tls = ldap_config.get("start_tls", False)
            self.ldap_base = ldap_config["base"]
            self.ldap_attributes = ldap_config["attributes"]

            if "bind_dn" in ldap_config:
                self.ldap_mode = LDAPMode.SEARCH
                self.require_keys(ldap_config, [
                    "bind_dn",
                    "bind_password",
                ])

                self.ldap_bind_dn = ldap_config["bind_dn"]
                self.ldap_bind_password = ldap_config["bind_password"]
                self.ldap_filter = ldap_config.get("filter", None)

            # verify attribute lookup
            self.require_keys(ldap_config['attributes'], [
                "uid",
                "name",
                "mail",
            ])

    def require_keys(self, config, required):
        missing = [key for key in required if key not in config]
        if missing:
            raise ConfigError(
                "LDAP enabled but missing required config values: {}".format(
                    ", ".join(missing)
                )
            )

    def default_config(self, **kwargs):
        return """\
        # ldap_config:
        #   enabled: true
        #   uri: "ldap://ldap.example.com:389"
        #   start_tls: true
        #   base: "ou=users,dc=example,dc=com"
        #   attributes:
        #      uid: "cn"
        #      mail: "email"
        #      name: "givenName"
        #   #bind_dn:
        #   #bind_password:
        #   #filter: "(objectClass=posixAccount)"
        """
