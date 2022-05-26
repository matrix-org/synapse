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

from typing import Any, List, Tuple, Type

from synapse.types import JsonDict
from synapse.util.module_loader import load_module

from ._base import Config

LDAP_PROVIDER = "ldap_auth_provider.LdapAuthProvider"


class PasswordAuthProviderConfig(Config):
    section = "authproviders"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        """Parses the old password auth providers config. The config format looks like this:

        password_providers:
           # Example config for an LDAP auth provider
           - module: "ldap_auth_provider.LdapAuthProvider"
             config:
               enabled: true
               uri: "ldap://ldap.example.com:389"
               start_tls: true
               base: "ou=users,dc=example,dc=com"
               attributes:
                  uid: "cn"
                  mail: "email"
                  name: "givenName"
               #bind_dn:
               #bind_password:
               #filter: "(objectClass=posixAccount)"

        We expect admins to use modules for this feature (which is why it doesn't appear
        in the sample config file), but we want to keep support for it around for a bit
        for backwards compatibility.
        """

        self.password_providers: List[Tuple[Type, Any]] = []
        providers = []

        # We want to be backwards compatible with the old `ldap_config`
        # param.
        ldap_config = config.get("ldap_config", {})
        if ldap_config.get("enabled", False):
            providers.append({"module": LDAP_PROVIDER, "config": ldap_config})

        providers.extend(config.get("password_providers") or [])
        for i, provider in enumerate(providers):
            mod_name = provider["module"]

            # This is for backwards compat when the ldap auth provider resided
            # in this package.
            if mod_name == "synapse.util.ldap_auth_provider.LdapAuthProvider":
                mod_name = LDAP_PROVIDER

            (provider_class, provider_config) = load_module(
                {"module": mod_name, "config": provider["config"]},
                ("password_providers", "<item %i>" % i),
            )

            self.password_providers.append((provider_class, provider_config))
