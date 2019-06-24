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

from ._base import Config, ConfigError

MISSING_SENTRY = """Missing sentry-sdk library. This is required to enable sentry
    integration.
    """


class MetricsConfig(Config):
    def read_config(self, config, **kwargs):
        self.enable_metrics = config.get("enable_metrics", False)
        self.report_stats = config.get("report_stats", None)
        self.metrics_port = config.get("metrics_port")
        self.metrics_bind_host = config.get("metrics_bind_host", "127.0.0.1")

        self.sentry_enabled = "sentry" in config
        if self.sentry_enabled:
            try:
                import sentry_sdk  # noqa F401
            except ImportError:
                raise ConfigError(MISSING_SENTRY)

            self.sentry_dsn = config["sentry"].get("dsn")
            if not self.sentry_dsn:
                raise ConfigError(
                    "sentry.dsn field is required when sentry integration is enabled"
                )

    def generate_config_section(self, report_stats=None, **kwargs):
        res = """\
        ## Metrics ###

        # Enable collection and rendering of performance metrics
        #
        #enable_metrics: False

        # Enable sentry integration
        # NOTE: While attempts are made to ensure that the logs don't contain
        # any sensitive information, this cannot be guaranteed. By enabling
        # this option the sentry server may therefore receive sensitive
        # information, and it in turn may then diseminate sensitive information
        # through insecure notification channels if so configured.
        #
        #sentry:
        #    dsn: "..."

        # Whether or not to report anonymized homeserver usage statistics.
        """

        if report_stats is None:
            res += "# report_stats: true|false\n"
        else:
            res += "report_stats: %s\n" % ("true" if report_stats else "false")

        return res
