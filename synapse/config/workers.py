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

import collections

from ._base import Config
from .server import read_gc_thresholds


Worker = collections.namedtuple("Worker", [
    "app",
    "listeners",
    "pid_file",
    "daemonize",
    "log_file",
    "log_config",
    "event_cache_size",
    "soft_file_limit",
    "gc_thresholds",
    "replication_url",
])


def clobber_with_worker_config(config, worker_config):
    """Overrides some of the keys of the main config with worker-specific
    values."""
    config.event_cache_size = worker_config.event_cache_size
    config.replication_url = worker_config.replication_url


def read_worker_config(config):
    return Worker(
        app=config["app"],
        listeners=config.get("listeners", []),
        pid_file=config.get("pid_file"),
        daemonize=config["daemonize"],
        log_file=config.get("log_file"),
        log_config=config.get("log_config"),
        event_cache_size=Config.parse_size(config.get("event_cache_size", "10K")),
        soft_file_limit=config.get("soft_file_limit"),
        gc_thresholds=read_gc_thresholds(config.get("gc_thresholds")),
        replication_url=config.get("replication_url"),
    )


class WorkerConfig(Config):
    """The workers are processes run separately to the main synapse process.
    Each worker has a name that identifies it within the config file.
    They have their own pid_file and listener configuration. They use the
    replication_url to talk to the main synapse process. They have their
    own cache size tuning, gc threshold tuning and open file limits."""

    def read_config(self, config):
        workers = config.get("workers", {})

        self.workers = {
            worker_name: read_worker_config(worker_config)
            for worker_name, worker_config in workers.items()
        }
