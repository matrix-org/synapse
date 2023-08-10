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
    # Time before a complete or failed task is deleted from the DB
    KEEP_TASKS_FOR_MS = 7 * 24 * 60 * 60 * 1000  # 1 week
    # Maximum number of tasks that can run at the same time
    MAX_CONCURRENT_RUNNING_TASKS = 10

    def __init__(self, hs: "HomeServer"):
        self._store = hs.get_datastores().main
        self._clock = hs.get_clock()
        self._running_tasks: Set[str] = set()
        # A map between action names and their registered function
        self._actions: Dict[
            str,
            Callable[
                [ScheduledTask, bool],
                Awaitable[Tuple[TaskStatus, Optional[JsonMapping], Optional[str]]],
            ],
        ] = {}
        self._run_background_tasks = hs.config.worker.run_background_tasks

        if self._run_background_tasks:
            self._clock.looping_call(
                run_as_background_process,
                TaskScheduler.SCHEDULE_INTERVAL_MS,
                "handle_scheduled_tasks",
                self._handle_scheduled_tasks,
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
        self._actions[action_name] = function

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
            timestamp: if `None`, the task will be launched as soon as possible, otherwise it
                will be launch as soon as possible after the `timestamp` value.
                Note that this scheduler is not meant to be precise, and the scheduling
                could be delayed if too many tasks are already running
            params: a set of parameters that can be easily accessed from inside the
                executed function

        Returns:
            The id of the scheduled task
        """
        if action not in self._actions:
            raise Exception(
                f"No function associated with action {action} of the scheduled task"
            )

        if timestamp is None or timestamp < self._clock.time_msec():
            timestamp = self._clock.time_msec()

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
        await self._store.insert_scheduled_task(task)

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
        """Update some task associated values. This is exposed publically so it can
        be used inside task functions, mainly to update the result and be able to
        resume a task at a specific step after a restart of synapse.

        It can also be used to stage a task, by setting the `status` to `SCHEDULED` with
        a new timestamp.

        The `status` can only be set to `ACTIVE` or `SCHEDULED`, `COMPLETE` and `FAILED`
        are terminal status and can only be set by returning it in the function.

        Args:
            id: the id of the task to update
            timestamp: useful to schedule a new stage of the task at a later date
            status: the new `TaskStatus` of the task
            result: the new result of the task
            error: the new error of the task
        """
        if status == TaskStatus.COMPLETE or status == TaskStatus.FAILED:
            raise Exception(
                "update_task can't be called with a FAILED or COMPLETE status"
            )

        if timestamp is None:
            timestamp = self._clock.time_msec()
        return await self._store.update_scheduled_task(
            id,
            timestamp,
            status=status,
            result=result,
            error=error,
        )

    async def get_task(self, id: str) -> Optional[ScheduledTask]:
        """Get a specific task description by id.

        Args:
            id: the id of the task to retrieve

        Returns:
            The task information or `None` if it doesn't exist or it has
            already been removed because it's too old.
        """
        return await self._store.get_scheduled_task(id)

    async def get_tasks(
        self,
        *,
        actions: Optional[List[str]] = None,
        resource_ids: Optional[List[str]] = None,
        statuses: Optional[List[TaskStatus]] = None,
        max_timestamp: Optional[int] = None,
    ) -> List[ScheduledTask]:
        """Get a list of tasks. Returns all the tasks if no args is provided.

        If an arg is `None` all tasks matching the other args will be selected.
        If an arg is an empty list, the corresponding value of the task needs
        to be `None` to be selected.

        Args:
            actions: Limit the returned tasks to those specific action names
            resource_ids: Limit the returned tasks to the specific resource ids
            statuses: Limit the returned tasks to the specific statuses
            max_timestamp: Limit the returned tasks to the ones that have
                a timestamp inferior to the specified one

        Returns
            A list of `ScheduledTask`, ordered by increasing timestamps
        """
        return await self._store.get_scheduled_tasks(
            actions=actions,
            resource_ids=resource_ids,
            statuses=statuses,
            max_timestamp=max_timestamp,
        )

    async def _handle_scheduled_tasks(self) -> None:
        """Main loop taking care of launching tasks and cleaning up old ones."""
        await self._launch_scheduled_tasks()
        await self._clean_scheduled_tasks()

    async def _launch_scheduled_tasks(self) -> None:
        """Retrieve and launch scheduled tasks that should be running at that time."""
        for task in await self.get_tasks(statuses=[TaskStatus.ACTIVE]):
            if (
                task.id not in self._running_tasks
                and len(self._running_tasks)
                < TaskScheduler.MAX_CONCURRENT_RUNNING_TASKS
            ):
                await self._launch_task(task, first_launch=False)
        for task in await self.get_tasks(
            statuses=[TaskStatus.SCHEDULED], max_timestamp=self._clock.time_msec()
        ):
            if (
                task.id not in self._running_tasks
                and len(self._running_tasks)
                < TaskScheduler.MAX_CONCURRENT_RUNNING_TASKS
            ):
                await self._launch_task(task, first_launch=True)

    async def _clean_scheduled_tasks(self) -> None:
        """Clean old complete or failed jobs to avoid clutter the DB."""
        for task in await self._store.get_scheduled_tasks(
            statuses=[TaskStatus.FAILED, TaskStatus.COMPLETE]
        ):
            # FAILED and COMPLETE tasks should never be running
            assert task.id not in self._running_tasks
            if (
                self._clock.time_msec()
                > task.timestamp + TaskScheduler.KEEP_TASKS_FOR_MS
            ):
                await self._store.delete_scheduled_task(task.id)

    async def _launch_task(self, task: ScheduledTask, first_launch: bool) -> None:
        """Launch a scheduled task now.

        Args:
            task: the task to launch
            first_launch: `True` if it's the first time is launched, `False` otherwise
        """
        if task.action not in self._actions:
            logger.warn(
                f"Can't launch task {task.id} since no function associated with action {task.action}"
            )
            return

        function = self._actions[task.action]

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

            await self._store.update_scheduled_task(
                task.id,
                self._clock.time_msec(),
                status=status,
                result=result,
                error=error,
            )
            self._running_tasks.remove(task.id)

        self._running_tasks.add(task.id)
        await self.update_task(task.id, status=TaskStatus.ACTIVE)
        description = f"{task.id}-{task.action}"
        run_as_background_process(description, wrapper)
