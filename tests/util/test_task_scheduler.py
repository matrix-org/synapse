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

from tests.replication._base import BaseMultiWorkerStreamTestCase
from tests.unittest import HomeserverTestCase, override_config


class TestTaskScheduler(HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.task_scheduler = hs.get_task_scheduler()
        self.task_scheduler.register_action(self._test_task, "_test_task")
        self.task_scheduler.register_action(self._sleeping_task, "_sleeping_task")
        self.task_scheduler.register_action(self._raising_task, "_raising_task")
        self.task_scheduler.register_action(self._resumable_task, "_resumable_task")

    async def _test_task(
        self, task: ScheduledTask
    ) -> Tuple[TaskStatus, Optional[JsonMapping], Optional[str]]:
        # This test task will copy the parameters to the result
        result = None
        if task.params:
            result = task.params
        return (TaskStatus.COMPLETE, result, None)

    def test_schedule_task(self) -> None:
        """Schedule a task in the future with some parameters to be copied as a result and check it executed correctly.
        Also check that it get removed after `KEEP_TASKS_FOR_MS`."""
        timestamp = self.clock.time_msec() + 30 * 1000
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

        # The timestamp being 30s after now the task should been executed
        # after the first scheduling loop is run
        self.reactor.advance(TaskScheduler.SCHEDULE_INTERVAL_MS / 1000)

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

    async def _sleeping_task(
        self, task: ScheduledTask
    ) -> Tuple[TaskStatus, Optional[JsonMapping], Optional[str]]:
        # Sleep for a second
        await deferLater(self.reactor, 1, lambda: None)
        return TaskStatus.COMPLETE, None, None

    def test_schedule_lot_of_tasks(self) -> None:
        """Schedule more than `TaskScheduler.MAX_CONCURRENT_RUNNING_TASKS` tasks and check the behavior."""
        task_ids = []
        for i in range(TaskScheduler.MAX_CONCURRENT_RUNNING_TASKS + 1):
            task_ids.append(
                self.get_success(
                    self.task_scheduler.schedule_task(
                        "_sleeping_task",
                        params={"val": i},
                    )
                )
            )

        # This is to give the time to the active tasks to finish
        self.reactor.advance(1)

        # Check that only MAX_CONCURRENT_RUNNING_TASKS tasks has run and that one
        # is still scheduled.
        tasks = [
            self.get_success(self.task_scheduler.get_task(task_id))
            for task_id in task_ids
        ]

        self.assertEquals(
            len(
                [t for t in tasks if t is not None and t.status == TaskStatus.COMPLETE]
            ),
            TaskScheduler.MAX_CONCURRENT_RUNNING_TASKS,
        )

        scheduled_tasks = [
            t for t in tasks if t is not None and t.status == TaskStatus.ACTIVE
        ]
        self.assertEquals(len(scheduled_tasks), 1)

        # We need to wait for the next run of the scheduler loop
        self.reactor.advance((TaskScheduler.SCHEDULE_INTERVAL_MS / 1000))
        self.reactor.advance(1)

        # Check that the last task has been properly executed after the next scheduler loop run
        prev_scheduled_task = self.get_success(
            self.task_scheduler.get_task(scheduled_tasks[0].id)
        )
        assert prev_scheduled_task is not None
        self.assertEquals(
            prev_scheduled_task.status,
            TaskStatus.COMPLETE,
        )

    async def _raising_task(
        self, task: ScheduledTask
    ) -> Tuple[TaskStatus, Optional[JsonMapping], Optional[str]]:
        raise Exception("raising")

    def test_schedule_raising_task(self) -> None:
        """Schedule a task raising an exception and check it runs to failure and report exception content."""
        task_id = self.get_success(self.task_scheduler.schedule_task("_raising_task"))

        task = self.get_success(self.task_scheduler.get_task(task_id))
        assert task is not None
        self.assertEqual(task.status, TaskStatus.FAILED)
        self.assertEqual(task.error, "raising")

    async def _resumable_task(
        self, task: ScheduledTask
    ) -> Tuple[TaskStatus, Optional[JsonMapping], Optional[str]]:
        if task.result and "in_progress" in task.result:
            return TaskStatus.COMPLETE, {"success": True}, None
        else:
            await self.task_scheduler.update_task(task.id, result={"in_progress": True})
            # Await forever to simulate an aborted task because of a restart
            await deferLater(self.reactor, 2**16, lambda: None)
            # This should never been called
            return TaskStatus.ACTIVE, None, None

    def test_schedule_resumable_task(self) -> None:
        """Schedule a resumable task and check that it gets properly resumed and complete after simulating a synapse restart."""
        task_id = self.get_success(self.task_scheduler.schedule_task("_resumable_task"))

        task = self.get_success(self.task_scheduler.get_task(task_id))
        assert task is not None
        self.assertEqual(task.status, TaskStatus.ACTIVE)

        # Simulate a synapse restart by emptying the list of running tasks
        self.task_scheduler._running_tasks = set()
        self.reactor.advance((TaskScheduler.SCHEDULE_INTERVAL_MS / 1000))

        task = self.get_success(self.task_scheduler.get_task(task_id))
        assert task is not None
        self.assertEqual(task.status, TaskStatus.COMPLETE)
        assert task.result is not None
        self.assertTrue(task.result.get("success"))


class TestTaskSchedulerWithBackgroundWorker(BaseMultiWorkerStreamTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.task_scheduler = hs.get_task_scheduler()
        self.task_scheduler.register_action(self._test_task, "_test_task")

    async def _test_task(
        self, task: ScheduledTask
    ) -> Tuple[TaskStatus, Optional[JsonMapping], Optional[str]]:
        return (TaskStatus.COMPLETE, None, None)

    @override_config({"run_background_tasks_on": "worker1"})
    def test_schedule_task(self) -> None:
        """Check that a task scheduled to run now is launch right away on the background worker."""
        bg_worker_hs = self.make_worker_hs(
            "synapse.app.generic_worker",
            extra_config={"worker_name": "worker1"},
        )
        bg_worker_hs.get_task_scheduler().register_action(self._test_task, "_test_task")

        task_id = self.get_success(
            self.task_scheduler.schedule_task(
                "_test_task",
            )
        )

        task = self.get_success(self.task_scheduler.get_task(task_id))
        assert task is not None
        self.assertEqual(task.status, TaskStatus.COMPLETE)
