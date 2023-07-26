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

import logging
from typing import TYPE_CHECKING, Awaitable, Callable, Dict, List, Optional, Set, Tuple

from twisted.python.failure import Failure

from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.types import JsonMapping, ScheduledTask, TaskStatus
from synapse.util.stringutils import random_string

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class TaskScheduler:
    # Precision of the scheduler, evaluation of tasks to run will only happen
    # every `SCHEDULE_INTERVAL_MS` ms
    SCHEDULE_INTERVAL_MS = 5 * 60 * 1000  # 5mn
    CLEAN_INTERVAL_MS = 60 * 60 * 1000  # 1hr
    # Time before a complete or failed task is deleted from the DB
    KEEP_TASKS_FOR_MS = 7 * 24 * 60 * 60 * 1000  # 1 week

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self.clock = hs.get_clock()
        self.running_tasks: Set[str] = set()
        self.actions: Dict[
            str,
            Callable[
                [ScheduledTask, bool],
                Awaitable[Tuple[TaskStatus, Optional[JsonMapping], Optional[str]]],
            ],
        ] = {}
        self.run_background_tasks = hs.config.worker.run_background_tasks

        if self.run_background_tasks:
            self.clock.looping_call(
                run_as_background_process,
                TaskScheduler.SCHEDULE_INTERVAL_MS,
                "run_scheduled_tasks",
                self._run_scheduled_tasks,
            )
            self.clock.looping_call(
                run_as_background_process,
                TaskScheduler.CLEAN_INTERVAL_MS,
                "clean_scheduled_tasks",
                self._clean_scheduled_tasks,
            )

    def register_action(
        self,
        function: Callable[
            [ScheduledTask, bool],
            Awaitable[Tuple[TaskStatus, Optional[JsonMapping], Optional[str]]],
        ],
        action_name: str,
    ) -> None:
        """Register a function to be executed when an action is scheduled with
        the specified action name.

        Actions need to be registered as early as possible so that a resumed action
        can find its matching function. It's usually better to NOT do that right before
        calling `schedule_task` but rather in an `__init__` method.

        Args:
            function: The function to be executed for this action. The parameters
            passed to the function when launched are the `ScheduledTask` being run,
            and a `first_launch` boolean to signal if it's a resumed task or the first
            launch of it. The function should return a tuple of new `status`, `result`
            and `error` as specified in `ScheduledTask`.
            action_name: The name of the action to be associated with the function
        """
        self.actions[action_name] = function

    async def schedule_task(
        self,
        action: str,
        *,
        resource_id: Optional[str] = None,
        timestamp: Optional[int] = None,
        params: Optional[JsonMapping] = None,
    ) -> str:
        """Schedule a new potentially resumable task. A function matching the specified
        `action` should have been previously registered with `register_action`.

        Args:
            action: the name of a previously registered action
            resource_id: a task can be associated with a resource id to facilitate
                getting all tasks associated with a specific resource
            timestamp: if `None`, the task will be launched immediately, otherwise it
                will be launch after the `timestamp` value. Note that this scheduler
                is not meant to be precise, and the scheduling could be delayed if
                too many tasks are already running
            params: a set of parameters that can be easily accessed from inside the
                executed function

        Returns: the id of the scheduled task
        """
        if action not in self.actions:
            raise Exception(
                f"No function associated with the action {action} of the scheduled task"
            )

        launch_now = False
        if timestamp is None or timestamp < self.clock.time_msec():
            timestamp = self.clock.time_msec()
            launch_now = True

        task = ScheduledTask(
            random_string(16),
            action,
            TaskStatus.SCHEDULED,
            timestamp,
            resource_id,
            params,
            None,
            None,
        )
        await self.store.upsert_scheduled_task(task)

        if launch_now and self.run_background_tasks:
            await self._launch_task(task, True)

        return task.id

    async def update_task(
        self,
        id: str,
        *,
        timestamp: Optional[int] = None,
        status: Optional[TaskStatus] = None,
        result: Optional[JsonMapping] = None,
        error: Optional[str] = None,
    ) -> bool:
        """Update some task associated values.

        This is used internally, and also exposed publically so it can be used inside task functions.
        This allows to store in DB the progress of a task so it can be resumed properly after a restart of synapse.

        Args:
            id: the id of the task to update
            status: the new `TaskStatus` of the task
            result: the new result of the task
            error: the new error of the task
        """
        if timestamp is None:
            timestamp = self.clock.time_msec()
        return await self.store.update_scheduled_task(
            id,
            timestamp=timestamp,
            status=status,
            result=result,
            error=error,
        )

    async def get_task(self, id: str) -> Optional[ScheduledTask]:
        """Get a specific task description by id.

        Args:
            id: the id of the task to retrieve

        Returns: the task description or `None` if it doesn't exist
            or it has already been cleaned
        """
        return await self.store.get_scheduled_task(id)

    async def get_tasks(
        self,
        *,
        actions: Optional[List[str]] = None,
        resource_ids: Optional[List[str]] = None,
        statuses: Optional[List[TaskStatus]] = None,
        max_timestamp: Optional[int] = None,
    ) -> List[ScheduledTask]:
        """Get a list of tasks associated with some action name(s) and/or
        with some resource id(s).

        Args:
            action: the action name of the tasks to retrieve
            resource_id: if `None`, returns all associated tasks for
                the specified action name, regardless of the resource id

        Returns: a list of `ScheduledTask`
        """
        return await self.store.get_scheduled_tasks(
            actions=actions,
            resource_ids=resource_ids,
            statuses=statuses,
            max_timestamp=max_timestamp,
        )

    async def _run_scheduled_tasks(self) -> None:
        """Main loop taking care of launching the scheduled tasks when needed."""
        for task in await self.get_tasks(statuses=[TaskStatus.ACTIVE]):
            if task.id not in self.running_tasks:
                await self._launch_task(task, first_launch=False)
        for task in await self.get_tasks(
            statuses=[TaskStatus.SCHEDULED], max_timestamp=self.clock.time_msec()
        ):
            if task.id not in self.running_tasks:
                await self._launch_task(task, first_launch=True)

    async def _clean_scheduled_tasks(self) -> None:
        """Clean loop taking care of removing old complete or failed jobs to avoid clutter the DB."""
        for task in await self.store.get_scheduled_tasks(
            statuses=[TaskStatus.FAILED, TaskStatus.COMPLETE]
        ):
            if task.id not in self.running_tasks:
                if (
                    self.clock.time_msec()
                    > task.timestamp + TaskScheduler.KEEP_TASKS_FOR_MS
                ):
                    await self.store.delete_scheduled_task(task.id)

    async def _launch_task(self, task: ScheduledTask, first_launch: bool) -> None:
        """Launch a scheduled task now.

        Args:
            task: the task to launch
            first_launch: `True` if it's the first time is launched, `False` otherwise
        """
        if task.action not in self.actions:
            raise Exception(
                f"No function associated with the action {task.action} of the scheduled task"
            )

        function = self.actions[task.action]

        async def wrapper() -> None:
            try:
                (status, result, error) = await function(task, first_launch)
            except Exception:
                f = Failure()
                logger.error(
                    f"scheduled task {task.id} failed",
                    exc_info=(f.type, f.value, f.getTracebackObject()),
                )
                status = TaskStatus.FAILED
                result = None
                error = f.getErrorMessage()

            await self.update_task(
                task.id,
                status=status,
                result=result,
                error=error,
            )
            self.running_tasks.remove(task.id)

        await self.update_task(task.id, status=TaskStatus.ACTIVE)
        self.running_tasks.add(task.id)
        description = task.action
        if task.resource_id:
            description += f"-{task.resource_id}"
        run_as_background_process(description, wrapper)
