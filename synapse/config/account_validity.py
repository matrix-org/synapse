# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
import logging

from synapse.config._base import Config, ConfigError
from synapse.util.module_loader import load_module

logger = logging.getLogger(__name__)

LEGACY_ACCOUNT_VALIDITY_IN_USE = """
You are using the deprecated account validity feature. It is recommended to change your
configuration to be using one or more modules instead. This feature will be removed in a
future version of Synapse, at which point it will only be available through custom
modules.
See the sample configuration file for more information:
https://github.com/matrix-org/synapse/blob/master/docs/sample_config.yaml
The behaviour and features of the deprecated account validity feature have been ported
to a dedicated module:
https://github.com/matrix-org/synapse-email-account-validity
--------------------------------------------------------------------------------------"""


class AccountValidityConfig(Config):
    section = "account_validity"

    def read_config(self, config, **kwargs):
        # Consider legacy account validity disabled unless proven otherwise
        self.account_validity_enabled = False
        self.account_validity_renew_by_email_enabled = False

        # Read and store template content. We need to do that regardless of whether the
        # configuration is using modules or the legacy account validity implementation,
        # because we need these templates to register the account validity servlets.
        (
            self.account_validity_account_renewed_template,
            self.account_validity_account_previously_renewed_template,
            self.account_validity_invalid_token_template,
        ) = self.read_templates(
            [
                "account_renewed.html",
                "account_previously_renewed.html",
                "invalid_token.html",
            ],
        )

        # Initialise the list of modules, which will stay empty if no modules or the
        # legacy config was provided.
        self.account_validity_modules = []

        if config.get("account_validity_modules") is not None:
            for i, module in enumerate(config.get("account_validity_modules")):
                config_path = ("account_validity", "<item %i>" % i)
                if not isinstance(module, dict):
                    raise ConfigError("expected a mapping", config_path)

                self.account_validity_modules.append(load_module(module, config_path))
        elif config.get("account_validity") is not None:
            # If the configuration is for the legacy feature, then read it as such.
            self.read_legacy_config(config.get("account_validity"))

    def read_legacy_config(self, account_validity_config):
        logger.warning(LEGACY_ACCOUNT_VALIDITY_IN_USE)

        self.account_validity_enabled = account_validity_config.get("enabled", False)
        self.account_validity_renew_by_email_enabled = (
            "renew_at" in account_validity_config
        )

        if self.account_validity_enabled:
            if "period" in account_validity_config:
                self.account_validity_period = self.parse_duration(
                    account_validity_config["period"]
                )
            else:
                raise ConfigError("'period' is required when using account validity")

            if "renew_at" in account_validity_config:
                self.account_validity_renew_at = self.parse_duration(
                    account_validity_config["renew_at"]
                )

            if "renew_email_subject" in account_validity_config:
                self.account_validity_renew_email_subject = account_validity_config[
                    "renew_email_subject"
                ]
            else:
                self.account_validity_renew_email_subject = "Renew your %(app)s account"

            self.account_validity_startup_job_max_delta = (
                self.account_validity_period * 10.0 / 100.0
            )

        if self.account_validity_renew_by_email_enabled:
            if not self.public_baseurl:
                raise ConfigError("Can't send renewal emails without 'public_baseurl'")

    def generate_config_section(self, **kwargs):
        return """\
        ## Account Validity ##

        # Server admins can (optionally) get Synapse to check the validity of all user
        # accounts against one or more custom modules.
        #
        # See the documentation on how to write an account validity module:
        # https://github.com/matrix-org/synapse/blob/master/docs/account_validity.md
        #
        account_validity_modules:
            #- module: "my_custom_project.SomeAccountValidity"
            #  config:
            #    example_option: 'things'
            #- module: "my_custom_project.SomeOtherAccountValidity"
            #  config:
            #    other_example_option: 'stuff'
        """
