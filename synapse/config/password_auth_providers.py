# -*- coding: utf-8 -*-
# Copyright 2016 Openmarket
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

import importlib


class PasswordAuthProviderConfig(Config):
    def read_config(self, config):
        self.password_providers = []

        # We want to be backwards compatible with the old `ldap_config`
        # param.
        ldap_config = config.get("ldap_config", {})
        self.ldap_enabled = ldap_config.get("enabled", False)
        if self.ldap_enabled:
            from ldap_auth_provider import LdapAuthProvider
            parsed_config = LdapAuthProvider.parse_config(ldap_config)
            self.password_providers.append((LdapAuthProvider, parsed_config))

        providers = config.get("password_providers", [])
        for provider in providers:
            # This is for backwards compat when the ldap auth provider resided
            # in this package.
            if provider['module'] == "synapse.util.ldap_auth_provider.LdapAuthProvider":
                from ldap_auth_provider import LdapAuthProvider
                provider_class = LdapAuthProvider
            else:
                # We need to import the module, and then pick the class out of
                # that, so we split based on the last dot.
                module, clz = provider['module'].rsplit(".", 1)
                module = importlib.import_module(module)
                provider_class = getattr(module, clz)

            try:
                provider_config = provider_class.parse_config(provider["config"])
            except Exception as e:
                raise ConfigError(
                    "Failed to parse config for %r: %r" % (provider['module'], e)
                )
            self.password_providers.append((provider_class, provider_config))

    def default_config(self, **kwargs):
        return """\
        # password_providers:
        #     - module: "ldap_auth_provider.LdapAuthProvider"
        #       config:
        #         enabled: true
        #         uri: "ldap://ldap.example.com:389"
        #         start_tls: true
        #         base: "ou=users,dc=example,dc=com"
        #         attributes:
        #            uid: "cn"
        #            mail: "email"
        #            name: "givenName"
        #         #bind_dn:
        #         #bind_password:
        #         #filter: "(objectClass=posixAccount)"
        """
