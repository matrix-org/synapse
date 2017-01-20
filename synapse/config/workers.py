# -*- coding: utf-8 -*-
# Copyright 2016 matrix.org
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


class WorkerConfig(Config):
    """The workers are processes run separately to the main synapse process.
    They have their own pid_file and listener configuration. They use the
    replication_url to talk to the main synapse process."""

    def read_config(self, config):
        self.worker_app = config.get("worker_app")
        self.worker_listeners = config.get("worker_listeners")
        self.worker_daemonize = config.get("worker_daemonize")
        self.worker_pid_file = config.get("worker_pid_file")
        self.worker_log_file = config.get("worker_log_file")
        self.worker_log_config = config.get("worker_log_config")
        self.worker_replication_url = config.get("worker_replication_url")

        if self.worker_listeners:
            for listener in self.worker_listeners:
                bind_address = listener.pop("bind_address", None)
                bind_addresses = listener.setdefault("bind_addresses", [])

                if bind_address:
                    bind_addresses.append(bind_address)
                elif not bind_addresses:
                    bind_addresses.append('')
