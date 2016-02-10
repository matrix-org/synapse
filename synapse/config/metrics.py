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


class MetricsConfig(Config):
    def read_config(self, config):
        self.enable_metrics = config["enable_metrics"]
        self.report_stats = config.get("report_stats", None)
        self.metrics_port = config.get("metrics_port")
        self.metrics_bind_host = config.get("metrics_bind_host", "127.0.0.1")

    def default_config(self, report_stats=None, **kwargs):
        suffix = "" if report_stats is None else "report_stats: %(report_stats)s\n"
        return ("""\
        ## Metrics ###

        # Enable collection and rendering of performance metrics
        enable_metrics: False
        """ + suffix) % locals()
