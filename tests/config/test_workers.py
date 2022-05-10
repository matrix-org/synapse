# Copyright 2022 The Matrix.org Foundation C.I.C.
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
from typing import Any, Mapping, Optional
from unittest.mock import Mock

from frozendict import frozendict

from synapse.config import ConfigError
from synapse.config.workers import WorkerConfig

from tests.unittest import TestCase

_EMPTY_FROZENDICT: Mapping[str, Any] = frozendict()


class WorkerDutyConfigTestCase(TestCase):
    def _make_worker_config(
        self,
        worker_app: str,
        worker_name: Optional[str],
        extras: Mapping[str, Any] = _EMPTY_FROZENDICT,
    ) -> WorkerConfig:
        root_config = Mock()
        root_config.worker_app = worker_app
        root_config.worker_name = worker_name
        worker_config = WorkerConfig(root_config)
        worker_config_dict = {
            "worker_name": worker_name,
            "worker_app": worker_app,
            **extras,
        }
        worker_config.read_config(worker_config_dict)
        return worker_config

    def test_old_configs_master(self) -> None:
        """
        Tests old (legacy) config options. This is for the master's config.
        """
        main_process_config = self._make_worker_config(
            worker_app="synapse.app.homeserver", worker_name=None
        )

        self.assertTrue(
            main_process_config._should_this_worker_perform_duty(
                {},
                "notify_appservices",
                "synapse.app.appservice",
                "notify_appservices_from_worker",
            )
        )

        self.assertTrue(
            main_process_config._should_this_worker_perform_duty(
                {
                    "notify_appservices": True,
                },
                "notify_appservices",
                "synapse.app.appservice",
                "notify_appservices_from_worker",
            )
        )

        self.assertFalse(
            main_process_config._should_this_worker_perform_duty(
                {
                    "notify_appservices": False,
                },
                "notify_appservices",
                "synapse.app.appservice",
                "notify_appservices_from_worker",
            )
        )

    def test_old_configs_appservice_worker(self) -> None:
        """
        Tests old (legacy) config options. This is for the worker's config.
        """
        appservice_worker_config = self._make_worker_config(
            worker_app="synapse.app.appservice",
            worker_name="worker1",
            extras={
                # Set notify_appservices to false for the initialiser's config,
                # so that it doesn't raise an exception here.
                # (This is not read by `_should_this_worker_perform_duty`.)
                "notify_appservices": False,
            },
        )

        with self.assertRaises(ConfigError):
            # This raises because you need to set notify_appservices: False
            # before using the synapse.app.appservice worker type
            self.assertFalse(
                appservice_worker_config._should_this_worker_perform_duty(
                    {},
                    "notify_appservices",
                    "synapse.app.appservice",
                    "notify_appservices_from_worker",
                )
            )

        with self.assertRaises(ConfigError):
            # This also raises because you need to set notify_appservices: False
            # before using the synapse.app.appservice worker type
            appservice_worker_config._should_this_worker_perform_duty(
                {
                    "notify_appservices": True,
                },
                "notify_appservices",
                "synapse.app.appservice",
                "notify_appservices_from_worker",
            )

        self.assertTrue(
            appservice_worker_config._should_this_worker_perform_duty(
                {
                    "notify_appservices": False,
                },
                "notify_appservices",
                "synapse.app.appservice",
                "notify_appservices_from_worker",
            )
        )

    def test_transitional_configs_master(self) -> None:
        """
        Tests transitional (legacy + new) config options. This is for the master's config.
        """

        main_process_config = self._make_worker_config(
            worker_app="synapse.app.homeserver", worker_name=None
        )

        self.assertTrue(
            main_process_config._should_this_worker_perform_duty(
                {
                    "notify_appservices": True,
                    "notify_appservices_from_worker": "master",
                },
                "notify_appservices",
                "synapse.app.appservice",
                "notify_appservices_from_worker",
            )
        )

        self.assertFalse(
            main_process_config._should_this_worker_perform_duty(
                {
                    "notify_appservices": False,
                    "notify_appservices_from_worker": "worker1",
                },
                "notify_appservices",
                "synapse.app.appservice",
                "notify_appservices_from_worker",
            )
        )

        with self.assertRaises(ConfigError):
            # Contradictory because we say the master should notify appservices,
            # then we say worker1 is the designated worker to do that!
            main_process_config._should_this_worker_perform_duty(
                {
                    "notify_appservices": True,
                    "notify_appservices_from_worker": "worker1",
                },
                "notify_appservices",
                "synapse.app.appservice",
                "notify_appservices_from_worker",
            )

        with self.assertRaises(ConfigError):
            # Contradictory because we say the master shouldn't notify appservices,
            # then we say master is the designated worker to do that!
            main_process_config._should_this_worker_perform_duty(
                {
                    "notify_appservices": False,
                    "notify_appservices_from_worker": "master",
                },
                "notify_appservices",
                "synapse.app.appservice",
                "notify_appservices_from_worker",
            )

    def test_transitional_configs_appservice_worker(self) -> None:
        """
        Tests transitional (legacy + new) config options. This is for the worker's config.
        """
        appservice_worker_config = self._make_worker_config(
            worker_app="synapse.app.appservice",
            worker_name="worker1",
            extras={
                # Set notify_appservices to false for the initialiser's config,
                # so that it doesn't raise an exception here.
                # (This is not read by `_should_this_worker_perform_duty`.)
                "notify_appservices": False,
            },
        )

        self.assertTrue(
            appservice_worker_config._should_this_worker_perform_duty(
                {
                    "notify_appservices": False,
                    "notify_appservices_from_worker": "worker1",
                },
                "notify_appservices",
                "synapse.app.appservice",
                "notify_appservices_from_worker",
            )
        )

        with self.assertRaises(ConfigError):
            # This raises because this worker is the appservice app type, yet
            # another worker is the designated worker!
            appservice_worker_config._should_this_worker_perform_duty(
                {
                    "notify_appservices": False,
                    "notify_appservices_from_worker": "worker2",
                },
                "notify_appservices",
                "synapse.app.appservice",
                "notify_appservices_from_worker",
            )

    def test_new_configs_master(self) -> None:
        """
        Tests new config options. This is for the master's config.
        """
        main_process_config = self._make_worker_config(
            worker_app="synapse.app.homeserver", worker_name=None
        )

        self.assertTrue(
            main_process_config._should_this_worker_perform_duty(
                {"notify_appservices_from_worker": None},
                "notify_appservices",
                "synapse.app.appservice",
                "notify_appservices_from_worker",
            )
        )

        self.assertFalse(
            main_process_config._should_this_worker_perform_duty(
                {"notify_appservices_from_worker": "worker1"},
                "notify_appservices",
                "synapse.app.appservice",
                "notify_appservices_from_worker",
            )
        )

    def test_new_configs_appservice_worker(self) -> None:
        """
        Tests new config options. This is for the worker's config.
        """
        appservice_worker_config = self._make_worker_config(
            worker_app="synapse.app.generic_worker", worker_name="worker1"
        )

        self.assertTrue(
            appservice_worker_config._should_this_worker_perform_duty(
                {
                    "notify_appservices_from_worker": "worker1",
                },
                "notify_appservices",
                "synapse.app.appservice",
                "notify_appservices_from_worker",
            )
        )

        self.assertFalse(
            appservice_worker_config._should_this_worker_perform_duty(
                {
                    "notify_appservices_from_worker": "worker2",
                },
                "notify_appservices",
                "synapse.app.appservice",
                "notify_appservices_from_worker",
            )
        )

    def test_worker_duty_configs(self) -> None:
        """
        Additional tests for the worker duties
        """

        worker1_config = self._make_worker_config(
            worker_app="synapse.app.generic_worker",
            worker_name="worker1",
            extras={
                "notify_appservices_from_worker": "worker2",
                "update_user_directory_from_worker": "worker1",
            },
        )
        self.assertFalse(worker1_config.should_notify_appservices)
        self.assertTrue(worker1_config.should_update_user_directory)

        worker2_config = self._make_worker_config(
            worker_app="synapse.app.generic_worker",
            worker_name="worker2",
            extras={
                "notify_appservices_from_worker": "worker2",
                "update_user_directory_from_worker": "worker1",
            },
        )
        self.assertTrue(worker2_config.should_notify_appservices)
        self.assertFalse(worker2_config.should_update_user_directory)
