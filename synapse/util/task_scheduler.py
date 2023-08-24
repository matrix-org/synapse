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

from prometheus_client import Gauge

from twisted.python.failure import Failure

from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.types import JsonMapping, ScheduledTask, TaskStatus
from synapse.util.stringutils import random_string

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


running_tasks_gauge = Gauge(
    "synapse_scheduler_running_tasks",
    "The number of concurrent running tasks handled by the TaskScheduler",
)


class TaskScheduler:
    """
    This is a simple task sheduler aimed at resumable tasks: usually we use `run_in_background`
    to launch a background task, or Twisted `deferLater` if we want to do so later on.

    The problem with that is that the tasks will just stop and never be resumed if synapse
    is stopped for whatever reason.

    How this works:
    - A function mapped to a named action should first be registered with `register_action`.
    This function will be called when trying to resuming tasks after a synapse shutdown,
    so this registration should happen when synapse is initialised, NOT right before scheduling
    a task.
    - A task can then be launched using this named action with `schedule_task`. A `params` dict
    can be passed, and it will be available to the registered function when launched. This task
    can be launch either now-ish, or later on by giving a `timestamp` parameter.

    The function may call `update_task` at any time to update the `result` of the task,
    and this can be used to resume the task at a specific point and/or to convey a result to
    the code launching the task.
    You can also specify the `result` (and/or an `error`) when returning from the function.

    The reconciliation loop runs every 5 mns, so this is not a precise scheduler. When wanting
    to launch now, the launch will still not happen before the next loop run.

    Tasks will be run on the worker specified with `run_background_tasks_on` config,
    or the main one by default.
    There is a limit of 10 concurrent tasks, so tasks may be delayed if the pool is already
    full. In this regard, please take great care that scheduled tasks can actually finished.
    For now there is no mechanism to stop a running task if it is stuck.
    """

    # Precision of the scheduler, evaluation of tasks to run will only happen
    # every `SCHEDULE_INTERVAL_MS` ms
    SCHEDULE_INTERVAL_MS = 1 * 60 * 1000  # 1mn
    # Time before a complete or failed task is deleted from the DB
    KEEP_TASKS_FOR_MS = 7 * 24 * 60 * 60 * 1000  # 1 week
    # Maximum number of tasks that can run at the same time
    MAX_CONCURRENT_RUNNING_TASKS = 10
    # Time from the last task update after which we will log a warning
    LAST_UPDATE_BEFORE_WARNING_MS = 24 * 60 * 60 * 1000  # 24hrs

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

        status = TaskStatus.SCHEDULED
        if timestamp is None or timestamp < self._clock.time_msec():
            timestamp = self._clock.time_msec()
            status = TaskStatus.ACTIVE

        task = ScheduledTask(
            random_string(16),
            action,
            status,
            timestamp,
            resource_id,
            params,
            result=None,
            error=None,
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
        resource_id: Optional[str] = None,
        statuses: Optional[List[TaskStatus]] = None,
        max_timestamp: Optional[int] = None,
    ) -> List[ScheduledTask]:
        """Get a list of tasks. Returns all the tasks if no args is provided.

        If an arg is `None` all tasks matching the other args will be selected.
        If an arg is an empty list, the corresponding value of the task needs
        to be `None` to be selected.

        Args:
            actions: Limit the returned tasks to those specific action names
            resource_id: Limit the returned tasks to the specific resource id, if specified
            statuses: Limit the returned tasks to the specific statuses
            max_timestamp: Limit the returned tasks to the ones that have
                a timestamp inferior to the specified one

        Returns
            A list of `ScheduledTask`, ordered by increasing timestamps
        """
        return await self._store.get_scheduled_tasks(
            actions=actions,
            resource_id=resource_id,
            statuses=statuses,
            max_timestamp=max_timestamp,
        )

    async def delete_task(self, id: str) -> None:
        """Delete a task. Running tasks can't be deleted.

        Can only be called from the worker handling the task scheduling.

        Args:
            id: id of the task to delete
        """
        if self.task_is_running(id):
            raise Exception(f"Task {id} is currently running and can't be deleted")
        await self._store.delete_scheduled_task(id)

    def task_is_running(self, id: str) -> bool:
        """Check if a task is currently running.

        Can only be called from the worker handling the task scheduling.

        Args:
            id: id of the task to check
        """
        assert self._run_background_tasks
        return id in self._running_tasks

    async def _handle_scheduled_tasks(self) -> None:
        """Main loop taking care of launching tasks and cleaning up old ones."""
        await self._launch_scheduled_tasks()
        await self._clean_scheduled_tasks()

    async def _launch_scheduled_tasks(self) -> None:
        """Retrieve and launch scheduled tasks that should be running at that time."""
        for task in await self.get_tasks(statuses=[TaskStatus.ACTIVE]):
            if not self.task_is_running(task.id):
                if (
                    len(self._running_tasks)
                    < TaskScheduler.MAX_CONCURRENT_RUNNING_TASKS
                ):
                    await self._launch_task(task, first_launch=False)
            else:
                if (
                    self._clock.time_msec()
                    > task.timestamp + TaskScheduler.LAST_UPDATE_BEFORE_WARNING_MS
                ):
                    logger.warn(
                        f"Task {task.id} (action {task.action}) has seen no update for more than 24h and may be stuck"
                    )
        for task in await self.get_tasks(
            statuses=[TaskStatus.SCHEDULED], max_timestamp=self._clock.time_msec()
        ):
            if (
                not self.task_is_running(task.id)
                and len(self._running_tasks)
                < TaskScheduler.MAX_CONCURRENT_RUNNING_TASKS
            ):
                await self._launch_task(task, first_launch=True)

        running_tasks_gauge.set(len(self._running_tasks))

    async def _clean_scheduled_tasks(self) -> None:
        """Clean old complete or failed jobs to avoid clutter the DB."""
        for task in await self._store.get_scheduled_tasks(
            statuses=[TaskStatus.FAILED, TaskStatus.COMPLETE]
        ):
            # FAILED and COMPLETE tasks should never be running
            assert not self.task_is_running(task.id)
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
        assert task.action in self._actions

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
