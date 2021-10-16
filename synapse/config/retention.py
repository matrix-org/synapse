#  Copyright 2021 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import logging
from typing import List, Optional

import attr

from synapse.config._base import Config, ConfigError

logger = logging.getLogger(__name__)


@attr.s(slots=True, frozen=True, auto_attribs=True)
class RetentionPurgeJob:
    """Object describing the configuration of the manhole"""

    interval: int
    shortest_max_lifetime: Optional[int]
    longest_max_lifetime: Optional[int]


class RetentionConfig(Config):
    section = "retention"

    def read_config(self, config, **kwargs):
        retention_config = config.get("retention")
        if retention_config is None:
            retention_config = {}

        self.retention_enabled = retention_config.get("enabled", False)

        retention_default_policy = retention_config.get("default_policy")

        if retention_default_policy is not None:
            self.retention_default_min_lifetime = retention_default_policy.get(
                "min_lifetime"
            )
            if self.retention_default_min_lifetime is not None:
                self.retention_default_min_lifetime = self.parse_duration(
                    self.retention_default_min_lifetime
                )

            self.retention_default_max_lifetime = retention_default_policy.get(
                "max_lifetime"
            )
            if self.retention_default_max_lifetime is not None:
                self.retention_default_max_lifetime = self.parse_duration(
                    self.retention_default_max_lifetime
                )

            if (
                self.retention_default_min_lifetime is not None
                and self.retention_default_max_lifetime is not None
                and (
                    self.retention_default_min_lifetime
                    > self.retention_default_max_lifetime
                )
            ):
                raise ConfigError(
                    "The default retention policy's 'min_lifetime' can not be greater"
                    " than its 'max_lifetime'"
                )
        else:
            self.retention_default_min_lifetime = None
            self.retention_default_max_lifetime = None

        if self.retention_enabled:
            logger.info(
                "Message retention policies support enabled with the following default"
                " policy: min_lifetime = %s ; max_lifetime = %s",
                self.retention_default_min_lifetime,
                self.retention_default_max_lifetime,
            )

        self.retention_allowed_lifetime_min = retention_config.get(
            "allowed_lifetime_min"
        )
        if self.retention_allowed_lifetime_min is not None:
            self.retention_allowed_lifetime_min = self.parse_duration(
                self.retention_allowed_lifetime_min
            )

        self.retention_allowed_lifetime_max = retention_config.get(
            "allowed_lifetime_max"
        )
        if self.retention_allowed_lifetime_max is not None:
            self.retention_allowed_lifetime_max = self.parse_duration(
                self.retention_allowed_lifetime_max
            )

        if (
            self.retention_allowed_lifetime_min is not None
            and self.retention_allowed_lifetime_max is not None
            and self.retention_allowed_lifetime_min
            > self.retention_allowed_lifetime_max
        ):
            raise ConfigError(
                "Invalid retention policy limits: 'allowed_lifetime_min' can not be"
                " greater than 'allowed_lifetime_max'"
            )

        self.retention_purge_jobs: List[RetentionPurgeJob] = []
        for purge_job_config in retention_config.get("purge_jobs", []):
            interval_config = purge_job_config.get("interval")

            if interval_config is None:
                raise ConfigError(
                    "A retention policy's purge jobs configuration must have the"
                    " 'interval' key set."
                )

            interval = self.parse_duration(interval_config)

            shortest_max_lifetime = purge_job_config.get("shortest_max_lifetime")

            if shortest_max_lifetime is not None:
                shortest_max_lifetime = self.parse_duration(shortest_max_lifetime)

            longest_max_lifetime = purge_job_config.get("longest_max_lifetime")

            if longest_max_lifetime is not None:
                longest_max_lifetime = self.parse_duration(longest_max_lifetime)

            if (
                shortest_max_lifetime is not None
                and longest_max_lifetime is not None
                and shortest_max_lifetime > longest_max_lifetime
            ):
                raise ConfigError(
                    "A retention policy's purge jobs configuration's"
                    " 'shortest_max_lifetime' value can not be greater than its"
                    " 'longest_max_lifetime' value."
                )

            self.retention_purge_jobs.append(
                RetentionPurgeJob(interval, shortest_max_lifetime, longest_max_lifetime)
            )

        if not self.retention_purge_jobs:
            self.retention_purge_jobs = [
                RetentionPurgeJob(self.parse_duration("1d"), None, None)
            ]

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return """\
        # Message retention policy at the server level.
        #
        # Room admins and mods can define a retention period for their rooms using the
        # 'm.room.retention' state event, and server admins can cap this period by setting
        # the 'allowed_lifetime_min' and 'allowed_lifetime_max' config options.
        #
        # If this feature is enabled, Synapse will regularly look for and purge events
        # which are older than the room's maximum retention period. Synapse will also
        # filter events received over federation so that events that should have been
        # purged are ignored and not stored again.
        #
        retention:
          # The message retention policies feature is disabled by default. Uncomment the
          # following line to enable it.
          #
          #enabled: true

          # Default retention policy. If set, Synapse will apply it to rooms that lack the
          # 'm.room.retention' state event. Currently, the value of 'min_lifetime' doesn't
          # matter much because Synapse doesn't take it into account yet.
          #
          #default_policy:
          #  min_lifetime: 1d
          #  max_lifetime: 1y

          # Retention policy limits. If set, and the state of a room contains a
          # 'm.room.retention' event in its state which contains a 'min_lifetime' or a
          # 'max_lifetime' that's out of these bounds, Synapse will cap the room's policy
          # to these limits when running purge jobs.
          #
          #allowed_lifetime_min: 1d
          #allowed_lifetime_max: 1y

          # Server admins can define the settings of the background jobs purging the
          # events which lifetime has expired under the 'purge_jobs' section.
          #
          # If no configuration is provided, a single job will be set up to delete expired
          # events in every room daily.
          #
          # Each job's configuration defines which range of message lifetimes the job
          # takes care of. For example, if 'shortest_max_lifetime' is '2d' and
          # 'longest_max_lifetime' is '3d', the job will handle purging expired events in
          # rooms whose state defines a 'max_lifetime' that's both higher than 2 days, and
          # lower than or equal to 3 days. Both the minimum and the maximum value of a
          # range are optional, e.g. a job with no 'shortest_max_lifetime' and a
          # 'longest_max_lifetime' of '3d' will handle every room with a retention policy
          # which 'max_lifetime' is lower than or equal to three days.
          #
          # The rationale for this per-job configuration is that some rooms might have a
          # retention policy with a low 'max_lifetime', where history needs to be purged
          # of outdated messages on a more frequent basis than for the rest of the rooms
          # (e.g. every 12h), but not want that purge to be performed by a job that's
          # iterating over every room it knows, which could be heavy on the server.
          #
          # If any purge job is configured, it is strongly recommended to have at least
          # a single job with neither 'shortest_max_lifetime' nor 'longest_max_lifetime'
          # set, or one job without 'shortest_max_lifetime' and one job without
          # 'longest_max_lifetime' set. Otherwise some rooms might be ignored, even if
          # 'allowed_lifetime_min' and 'allowed_lifetime_max' are set, because capping a
          # room's policy to these values is done after the policies are retrieved from
          # Synapse's database (which is done using the range specified in a purge job's
          # configuration).
          #
          #purge_jobs:
          #  - longest_max_lifetime: 3d
          #    interval: 12h
          #  - shortest_max_lifetime: 3d
          #    interval: 1d
        """
