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

from typing import TYPE_CHECKING, Any, List, Optional, Tuple, cast

from synapse.storage._base import SQLBaseStore, db_to_json
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
    make_in_list_sql_clause,
)
from synapse.types import JsonDict, JsonMapping, ScheduledTask, TaskStatus
from synapse.util import json_encoder

if TYPE_CHECKING:
    from synapse.server import HomeServer

ScheduledTaskRow = Tuple[str, str, str, int, str, str, str, str]


class TaskSchedulerWorkerStore(SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

    @staticmethod
    def _convert_row_to_task(row: ScheduledTaskRow) -> ScheduledTask:
        task_id, action, status, timestamp, resource_id, params, result, error = row
        return ScheduledTask(
            id=task_id,
            action=action,
            status=TaskStatus(status),
            timestamp=timestamp,
            resource_id=resource_id,
            params=db_to_json(params) if params is not None else None,
            result=db_to_json(result) if result is not None else None,
            error=error,
        )

    async def get_scheduled_tasks(
        self,
        *,
        actions: Optional[List[str]] = None,
        resource_id: Optional[str] = None,
        statuses: Optional[List[TaskStatus]] = None,
        max_timestamp: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> List[ScheduledTask]:
        """Get a list of scheduled tasks from the DB.

        Args:
            actions: Limit the returned tasks to those specific action names
            resource_id: Limit the returned tasks to the specific resource id, if specified
            statuses: Limit the returned tasks to the specific statuses
            max_timestamp: Limit the returned tasks to the ones that have
                a timestamp inferior to the specified one
            limit: Only return `limit` number of rows if set.

        Returns: a list of `ScheduledTask`, ordered by increasing timestamps
        """

        def get_scheduled_tasks_txn(txn: LoggingTransaction) -> List[ScheduledTaskRow]:
            clauses: List[str] = []
            args: List[Any] = []
            if resource_id:
                clauses.append("resource_id = ?")
                args.append(resource_id)
            if actions is not None:
                clause, temp_args = make_in_list_sql_clause(
                    txn.database_engine, "action", actions
                )
                clauses.append(clause)
                args.extend(temp_args)
            if statuses is not None:
                clause, temp_args = make_in_list_sql_clause(
                    txn.database_engine, "status", statuses
                )
                clauses.append(clause)
                args.extend(temp_args)
            if max_timestamp is not None:
                clauses.append("timestamp <= ?")
                args.append(max_timestamp)

            sql = "SELECT * FROM scheduled_tasks"
            if clauses:
                sql = sql + " WHERE " + " AND ".join(clauses)

            sql = sql + " ORDER BY timestamp"

            if limit is not None:
                sql += " LIMIT ?"
                args.append(limit)

            txn.execute(sql, args)
            return cast(List[ScheduledTaskRow], txn.fetchall())

        rows = await self.db_pool.runInteraction(
            "get_scheduled_tasks", get_scheduled_tasks_txn
        )
        return [TaskSchedulerWorkerStore._convert_row_to_task(row) for row in rows]

    async def insert_scheduled_task(self, task: ScheduledTask) -> None:
        """Insert a specified `ScheduledTask` in the DB.

        Args:
            task: the `ScheduledTask` to insert
        """
        await self.db_pool.simple_insert(
            "scheduled_tasks",
            {
                "id": task.id,
                "action": task.action,
                "status": task.status,
                "timestamp": task.timestamp,
                "resource_id": task.resource_id,
                "params": None
                if task.params is None
                else json_encoder.encode(task.params),
                "result": None
                if task.result is None
                else json_encoder.encode(task.result),
                "error": task.error,
            },
            desc="insert_scheduled_task",
        )

    async def update_scheduled_task(
        self,
        id: str,
        timestamp: int,
        *,
        status: Optional[TaskStatus] = None,
        result: Optional[JsonMapping] = None,
        error: Optional[str] = None,
    ) -> bool:
        """Update a scheduled task in the DB with some new value(s).

        Args:
            id: id of the `ScheduledTask` to update
            timestamp: new timestamp of the task
            status: new status of the task
            result: new result of the task
            error: new error of the task

        Returns: `False` if no matching row was found, `True` otherwise
        """
        updatevalues: JsonDict = {"timestamp": timestamp}
        if status is not None:
            updatevalues["status"] = status
        if result is not None:
            updatevalues["result"] = json_encoder.encode(result)
        if error is not None:
            updatevalues["error"] = error
        nb_rows = await self.db_pool.simple_update(
            "scheduled_tasks",
            {"id": id},
            updatevalues,
            desc="update_scheduled_task",
        )
        return nb_rows > 0

    async def get_scheduled_task(self, id: str) -> Optional[ScheduledTask]:
        """Get a specific `ScheduledTask` from its id.

        Args:
            id: the id of the task to retrieve

        Returns: the task if available, `None` otherwise
        """
        row = cast(
            Optional[ScheduledTaskRow],
            await self.db_pool.simple_select_one(
                table="scheduled_tasks",
                keyvalues={"id": id},
                retcols=(
                    "id",
                    "action",
                    "status",
                    "timestamp",
                    "resource_id",
                    "params",
                    "result",
                    "error",
                ),
                allow_none=True,
                desc="get_scheduled_task",
            ),
        )

        return TaskSchedulerWorkerStore._convert_row_to_task(row) if row else None

    async def delete_scheduled_task(self, id: str) -> None:
        """Delete a specific task from its id.

        Args:
            id: the id of the task to delete
        """
        await self.db_pool.simple_delete(
            "scheduled_tasks",
            keyvalues={"id": id},
            desc="delete_scheduled_task",
        )
