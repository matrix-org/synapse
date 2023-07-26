# Copyright 2023 The Matrix.org Foundation C.I.C.
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

from typing import Optional, Tuple

from twisted.internet.task import deferLater
from twisted.test.proto_helpers import MemoryReactor

from synapse.server import HomeServer
from synapse.types import JsonMapping, ScheduledTask, TaskStatus
from synapse.util import Clock
from synapse.util.task_scheduler import TaskScheduler

from tests import unittest


class TestTaskScheduler(unittest.HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.task_scheduler = hs.get_task_scheduler()
        self.task_scheduler.register_action(self._test_task, "_test_task")
        self.task_scheduler.register_action(self._raising_task, "_raising_task")
        self.task_scheduler.register_action(self._resumable_task, "_resumable_task")

    async def _test_task(
        self, task: ScheduledTask, first_launch: bool
    ) -> Tuple[TaskStatus, Optional[JsonMapping], Optional[str]]:
        # This test task will copy the parameters to the result
        result = None
        if task.params:
            result = task.params
        return (TaskStatus.COMPLETE, result, None)

    def test_schedule_task(self) -> None:
        """Schedule a task in the future with some parameters to be copied as a result and check it executed correctly.
        Also check that it get removed after `KEEP_TASKS_FOR_MS`."""
        timestamp = self.clock.time_msec() + 2 * 60 * 1000
        task_id = self.get_success(
            self.task_scheduler.schedule_task(
                "_test_task",
                timestamp=timestamp,
                params={"val": 1},
            )
        )

        task = self.get_success(self.task_scheduler.get_task(task_id))
        assert task is not None
        self.assertEqual(task.status, TaskStatus.SCHEDULED)
        self.assertIsNone(task.result)

        # The timestamp being 2mn after now the task should been executed
        # after the first scheduling loop is run
        self.reactor.advance((TaskScheduler.SCHEDULE_INTERVAL_MS / 1000) + 1)

        task = self.get_success(self.task_scheduler.get_task(task_id))
        assert task is not None
        self.assertEqual(task.status, TaskStatus.COMPLETE)
        assert task.result is not None
        # The passed parameter should have been copied to the result
        self.assertTrue(task.result.get("val") == 1)

        # Let's wait for the complete task to be deleted and hence unavailable
        self.reactor.advance((TaskScheduler.KEEP_TASKS_FOR_MS / 1000) + 1)

        task = self.get_success(self.task_scheduler.get_task(task_id))
        self.assertIsNone(task)

    def test_schedule_task_now(self) -> None:
        """Schedule a task now and check it runs fine to completion."""
        task_id = self.get_success(
            self.task_scheduler.schedule_task("_test_task", params={"val": 1})
        )

        task = self.get_success(self.task_scheduler.get_task(task_id))
        assert task is not None
        self.assertEqual(task.status, TaskStatus.COMPLETE)
        assert task.result is not None
        self.assertTrue(task.result.get("val") == 1)

    async def _raising_task(
        self, task: ScheduledTask, first_launch: bool
    ) -> Tuple[TaskStatus, Optional[JsonMapping], Optional[str]]:
        raise Exception("raising")

    def test_schedule_raising_task_now(self) -> None:
        """Schedule a task raising an exception and check it runs to failure and report exception content."""
        task_id = self.get_success(self.task_scheduler.schedule_task("_raising_task"))

        task = self.get_success(self.task_scheduler.get_task(task_id))
        assert task is not None
        self.assertEqual(task.status, TaskStatus.FAILED)
        self.assertEqual(task.error, "raising")

    async def _resumable_task(
        self, task: ScheduledTask, first_launch: bool
    ) -> Tuple[TaskStatus, Optional[JsonMapping], Optional[str]]:
        if task.result and "in_progress" in task.result:
            return TaskStatus.COMPLETE, {"success": True}, None
        else:
            await self.task_scheduler.update_task(task.id, result={"in_progress": True})
            # Await forever to simulate an aborted task because of a restart
            await deferLater(self.reactor, 2**16, None)
            # This should never been called
            return TaskStatus.ACTIVE, None, None

    def test_schedule_resumable_task_now(self) -> None:
        """Schedule a resumable task and check that it gets properly resumed and complete after simulating a synapse restart."""
        task_id = self.get_success(self.task_scheduler.schedule_task("_resumable_task"))

        task = self.get_success(self.task_scheduler.get_task(task_id))
        assert task is not None
        self.assertEqual(task.status, TaskStatus.ACTIVE)

        # Simulate a synapse restart by emptying the list of running tasks
        self.task_scheduler._running_tasks = set()
        self.reactor.advance((TaskScheduler.SCHEDULE_INTERVAL_MS / 1000) + 1)

        task = self.get_success(self.task_scheduler.get_task(task_id))
        assert task is not None
        self.assertEqual(task.status, TaskStatus.COMPLETE)
        assert task.result is not None
        self.assertTrue(task.result.get("success"))
