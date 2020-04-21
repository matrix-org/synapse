# -*- coding: utf-8 -*-
# Copyright 2020 Matrix.org Foundation C.I.C.
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
import json
from typing import Any, Dict, Optional, Union

import synapse.util.stringutils as stringutils
from synapse.api.errors import StoreError, SynapseError
from synapse.storage._base import SQLBaseStore


class UIAuthStore(SQLBaseStore):
    """
    Manage user interactive authentication sessions.
    """

    async def create_session(
        self, clientdict: Dict[str, Any], uri: str, method: str, description: str,
    ) -> str:
        """
        Creates a new user interactive authentication session.

        The session can be used to track data across multiple requests, e.g. for
        interactive authentication.
        """
        # autogen a session ID and try to create it. We may clash, so just
        # try a few times till one goes through, giving up eventually.
        attempts = 0
        while attempts < 5:
            session_id = stringutils.random_string(24)

            try:
                await self.db.simple_insert(
                    table="ui_auth_sessions",
                    values={
                        "session_id": session_id,
                        "clientdict": json.dumps(clientdict),
                        "uri": uri,
                        "method": method,
                        "description": description,
                        "serverdict": "{}",
                        "last_used": self.hs.get_clock().time_msec(),
                    },
                )
                return session_id
            except self.db.engine.module.IntegrityError:
                attempts += 1
        raise StoreError(500, "Couldn't generate a session ID.")

    async def get_session(self, session_id: str) -> Dict[str, Any]:
        """Retrieve a UI auth session.

        Args:
            session_id: The ID of the session.
        Returns:
            defer.Deferred for a dict containing the device information.
        Raises:
            SynapseError: if the session is not found.
        """
        try:
            result = await self.db.simple_select_one(
                table="ui_auth_sessions",
                keyvalues={"session_id": session_id},
                retcols=("clientdict", "uri", "method", "description"),
                desc="get_session",
            )
        except StoreError:
            raise SynapseError(400, "Unknown session ID: %s" % session_id)

        result["clientdict"] = json.loads(result["clientdict"])

        return result

    def delete_old_sessions(self, expiration_time: int):
        """
        Remove sessions which were last used earlier than the expiration time.

        Args:
            expiration_time: The latest time that is still considered valid.
                This is an epoch time in milliseconds.

        """
        return self.db.runInteraction(
            "delete_sessions", self._delete_old_sessions, expiration_time
        )

    def _delete_old_sessions(self, txn, expiration_time: int):
        # Get the expired sessions.
        sql = "SELECT session_id FROM ui_auth_sessions WHERE last_used <= ?"
        txn.execute(sql, [expiration_time])
        session_ids = [r[0] for r in txn.fetchall()]

        # Delete the corresponding completed credentials.
        self.db.simple_delete_many_txn(
            txn,
            table="ui_auth_sessions_credentials",
            column="session_id",
            iterable=session_ids,
            keyvalues={},
        )

        # Finally, delete the sessions.
        self.db.simple_delete_many_txn(
            txn,
            table="ui_auth_sessions",
            column="session_id",
            iterable=session_ids,
            keyvalues={},
        )

    async def mark_stage_complete(
        self,
        session_id: str,
        stage_type: str,
        identity: Union[str, bool, Dict[str, Any]],
    ):
        """
        Mark a session stage as completed.

        Args:
            session_id: The ID of the corresponding session.
            stage_type: The completed stage type.
            identity: The identity authenticated by the stage.
        """
        await self.db.runInteraction(
            "mark_stage_complete",
            self._mark_stage_completed,
            session_id,
            stage_type,
            identity,
        )

    def _mark_stage_completed(
        self,
        txn,
        session_id: str,
        stage_type: str,
        identity: Union[str, bool, Dict[str, Any]],
    ):
        # Add (or update) the results of the current stage to the database.
        self.db.simple_upsert_txn(
            txn,
            table="ui_auth_sessions_credentials",
            keyvalues={"session_id": session_id, "stage_type": stage_type},
            values={"identity": json.dumps(identity)},
        )
        # Mark the session as still in use.
        self.db.simple_update_one_txn(
            txn,
            table="ui_auth_sessions",
            keyvalues={"session_id": session_id},
            updatevalues={"last_used": self.hs.get_clock().time_msec()},
        )

    async def get_completed_stages(
        self, session_id: str
    ) -> Dict[str, Union[str, bool, Dict[str, Any]]]:
        """
        Retrieve the completed stages of a UI authentication session.

        Args:
            session_id: The ID of the session.
        Returns:
            The completed stages mapped to the user which completed that stage.
        Raises:
            StoreError: if the session is not found.
        """
        results = {}
        for row in await self.db.simple_select_list(
            table="ui_auth_sessions_credentials",
            keyvalues={"session_id": session_id},
            retcols=("stage_type", "identity"),
            desc="get_completed_stages",
        ):
            results[row["stage_type"]] = json.loads(row["identity"])

        return results

    async def set_session_data(self, session_id: str, key: str, value: Any):
        """
        Store a key-value pair into the sessions data associated with this
        request. This data is stored server-side and cannot be modified by
        the client.

        Args:
            session_id: The ID of this session as returned from check_auth
            key: The key to store the data under
            value: The data to store
        """
        await self.db.runInteraction(
            "set_session_data", self._set_session_data, session_id, key, value
        )

    def _set_session_data(self, txn, session_id: str, key: str, value: Any):
        # Get the current value.
        result = self.db.simple_select_one_txn(
            txn,
            table="ui_auth_sessions",
            keyvalues={"session_id": session_id},
            retcols=("serverdict",),
        )

        # Update it and add it back to the database.
        serverdict = json.loads(result["serverdict"])
        serverdict[key] = value

        self.db.simple_update_one_txn(
            txn,
            table="ui_auth_sessions",
            keyvalues={"session_id": session_id},
            updatevalues={"serverdict": json.dumps(serverdict)},
        )

        # Mark the session as still in use.
        self.db.simple_update_one_txn(
            txn,
            table="ui_auth_sessions",
            keyvalues={"session_id": session_id},
            updatevalues={"last_used": self.hs.get_clock().time_msec()},
        )

    async def get_session_data(
        self, session_id: str, key: str, default: Optional[Any] = None
    ) -> Any:
        """
        Retrieve data stored with set_session_data

        Args:
            session_id: The ID of this session as returned from check_auth
            key: The key to store the data under
            default: Value to return if the key has not been set
        """
        result = await self.db.simple_select_one(
            table="ui_auth_sessions",
            keyvalues={"session_id": session_id},
            retcols=("serverdict",),
            desc="get_server_data",
        )

        serverdict = json.loads(result["serverdict"])

        return serverdict.get(key, default)
