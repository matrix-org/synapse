# Copyright 2017 New Vector Ltd
# Copyright 2019 Matrix.org Foundation C.I.C.
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

from typing import Dict, Iterable, Mapping, Optional, Tuple, cast

from typing_extensions import Literal, TypedDict

from synapse.api.errors import StoreError
from synapse.logging.opentracing import log_kv, trace
from synapse.storage._base import SQLBaseStore, db_to_json
from synapse.storage.database import LoggingTransaction
from synapse.types import JsonDict, JsonSerializable, StreamKeyType
from synapse.util import json_encoder


class RoomKey(TypedDict):
    """`KeyBackupData` in the Matrix spec.

    https://spec.matrix.org/v1.1/client-server-api/#get_matrixclientv3room_keyskeysroomidsessionid
    """

    first_message_index: int
    forwarded_count: int
    is_verified: bool
    session_data: JsonSerializable


class EndToEndRoomKeyStore(SQLBaseStore):
    """The store for end to end room key backups.

    See https://spec.matrix.org/v1.1/client-server-api/#server-side-key-backups

    As per the spec, backups are identified by an opaque version string. Internally,
    version identifiers are assigned using incrementing integers. Non-numeric version
    strings are treated as if they do not exist, since we would have never issued them.
    """

    async def update_e2e_room_key(
        self,
        user_id: str,
        version: str,
        room_id: str,
        session_id: str,
        room_key: RoomKey,
    ) -> None:
        """Replaces the encrypted E2E room key for a given session in a given backup

        Args:
            user_id: the user whose backup we're setting
            version: the version ID of the backup we're updating
            room_id: the ID of the room whose keys we're setting
            session_id: the session whose room_key we're setting
            room_key: the room_key being set
        Raises:
            StoreError
        """
        try:
            version_int = int(version)
        except ValueError:
            # Our versions are all ints so if we can't convert it to an integer,
            # it doesn't exist.
            raise StoreError(404, "No backup with that version exists")

        await self.db_pool.simple_update_one(
            table="e2e_room_keys",
            keyvalues={
                "user_id": user_id,
                "version": version_int,
                "room_id": room_id,
                "session_id": session_id,
            },
            updatevalues={
                "first_message_index": room_key["first_message_index"],
                "forwarded_count": room_key["forwarded_count"],
                "is_verified": room_key["is_verified"],
                "session_data": json_encoder.encode(room_key["session_data"]),
            },
            desc="update_e2e_room_key",
        )

    async def add_e2e_room_keys(
        self, user_id: str, version: str, room_keys: Iterable[Tuple[str, str, RoomKey]]
    ) -> None:
        """Bulk add room keys to a given backup.

        Args:
            user_id: the user whose backup we're adding to
            version: the version ID of the backup for the set of keys we're adding to
            room_keys: the keys to add, in the form (roomID, sessionID, keyData)
        """
        try:
            version_int = int(version)
        except ValueError:
            # Our versions are all ints so if we can't convert it to an integer,
            # it doesn't exist.
            raise StoreError(404, "No backup with that version exists")

        values = []
        for (room_id, session_id, room_key) in room_keys:
            values.append(
                (
                    user_id,
                    version_int,
                    room_id,
                    session_id,
                    room_key["first_message_index"],
                    room_key["forwarded_count"],
                    room_key["is_verified"],
                    json_encoder.encode(room_key["session_data"]),
                )
            )
            log_kv(
                {
                    "message": "Set room key",
                    "room_id": room_id,
                    "session_id": session_id,
                    StreamKeyType.ROOM: room_key,
                }
            )

        await self.db_pool.simple_insert_many(
            table="e2e_room_keys",
            keys=(
                "user_id",
                "version",
                "room_id",
                "session_id",
                "first_message_index",
                "forwarded_count",
                "is_verified",
                "session_data",
            ),
            values=values,
            desc="add_e2e_room_keys",
        )

    @trace
    async def get_e2e_room_keys(
        self,
        user_id: str,
        version: str,
        room_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Dict[
        Literal["rooms"], Dict[str, Dict[Literal["sessions"], Dict[str, RoomKey]]]
    ]:
        """Bulk get the E2E room keys for a given backup, optionally filtered to a given
        room, or a given session.

        Args:
            user_id: the user whose backup we're querying
            version: the version ID of the backup for the set of keys we're querying
            room_id: Optional. the ID of the room whose keys we're querying, if any.
                If not specified, we return the keys for all the rooms in the backup.
            session_id: Optional. the session whose room_key we're querying, if any.
                If specified, we also require the room_id to be specified.
                If not specified, we return all the keys in this version of
                the backup (or for the specified room)

        Returns:
            A dict giving the session_data and message metadata for these room keys.
            `{"rooms": {room_id: {"sessions": {session_id: room_key}}}}`
        """

        try:
            version_int = int(version)
        except ValueError:
            return {"rooms": {}}

        keyvalues = {"user_id": user_id, "version": version_int}
        if room_id:
            keyvalues["room_id"] = room_id
            if session_id:
                keyvalues["session_id"] = session_id

        rows = await self.db_pool.simple_select_list(
            table="e2e_room_keys",
            keyvalues=keyvalues,
            retcols=(
                "user_id",
                "room_id",
                "session_id",
                "first_message_index",
                "forwarded_count",
                "is_verified",
                "session_data",
            ),
            desc="get_e2e_room_keys",
        )

        sessions: Dict[
            Literal["rooms"], Dict[str, Dict[Literal["sessions"], Dict[str, RoomKey]]]
        ] = {"rooms": {}}
        for row in rows:
            room_entry = sessions["rooms"].setdefault(row["room_id"], {"sessions": {}})
            room_entry["sessions"][row["session_id"]] = {
                "first_message_index": row["first_message_index"],
                "forwarded_count": row["forwarded_count"],
                # is_verified must be returned to the client as a boolean
                "is_verified": bool(row["is_verified"]),
                "session_data": db_to_json(row["session_data"]),
            }

        return sessions

    async def get_e2e_room_keys_multi(
        self,
        user_id: str,
        version: str,
        room_keys: Mapping[str, Mapping[Literal["sessions"], Iterable[str]]],
    ) -> Dict[str, Dict[str, RoomKey]]:
        """Get multiple room keys at a time.  The difference between this function and
        get_e2e_room_keys is that this function can be used to retrieve
        multiple specific keys at a time, whereas get_e2e_room_keys is used for
        getting all the keys in a backup version, all the keys for a room, or a
        specific key.

        Args:
            user_id: the user whose backup we're querying
            version: the version ID of the backup we're querying about
            room_keys: a map from room ID -> {"sessions": [session ids]}
                indicating the session IDs that we want to query

        Returns:
           A map of room IDs to session IDs to room key
        """
        try:
            version_int = int(version)
        except ValueError:
            # Our versions are all ints so if we can't convert it to an integer,
            # it doesn't exist.
            return {}

        return await self.db_pool.runInteraction(
            "get_e2e_room_keys_multi",
            self._get_e2e_room_keys_multi_txn,
            user_id,
            version_int,
            room_keys,
        )

    @staticmethod
    def _get_e2e_room_keys_multi_txn(
        txn: LoggingTransaction,
        user_id: str,
        version: int,
        room_keys: Mapping[str, Mapping[Literal["sessions"], Iterable[str]]],
    ) -> Dict[str, Dict[str, RoomKey]]:
        if not room_keys:
            return {}

        where_clauses = []
        params = [user_id, version]
        for room_id, room in room_keys.items():
            sessions = list(room["sessions"])
            if not sessions:
                continue
            params.append(room_id)
            params.extend(sessions)
            where_clauses.append(
                "(room_id = ? AND session_id IN (%s))"
                % (",".join(["?" for _ in sessions]),)
            )

        # check if we're actually querying something
        if not where_clauses:
            return {}

        sql = """
        SELECT room_id, session_id, first_message_index, forwarded_count,
               is_verified, session_data
        FROM e2e_room_keys
        WHERE user_id = ? AND version = ? AND (%s)
        """ % (
            " OR ".join(where_clauses)
        )

        txn.execute(sql, params)

        ret: Dict[str, Dict[str, RoomKey]] = {}

        for row in txn:
            room_id = row[0]
            session_id = row[1]
            ret.setdefault(room_id, {})
            ret[room_id][session_id] = {
                "first_message_index": row[2],
                "forwarded_count": row[3],
                "is_verified": row[4],
                "session_data": db_to_json(row[5]),
            }

        return ret

    async def count_e2e_room_keys(self, user_id: str, version: str) -> int:
        """Get the number of keys in a backup version.

        Args:
            user_id: the user whose backup we're querying
            version: the version ID of the backup we're querying about
        """
        try:
            version_int = int(version)
        except ValueError:
            # Our versions are all ints so if we can't convert it to an integer,
            # it doesn't exist.
            return 0

        return await self.db_pool.simple_select_one_onecol(
            table="e2e_room_keys",
            keyvalues={"user_id": user_id, "version": version_int},
            retcol="COUNT(*)",
            desc="count_e2e_room_keys",
        )

    @trace
    async def delete_e2e_room_keys(
        self,
        user_id: str,
        version: str,
        room_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> None:
        """Bulk delete the E2E room keys for a given backup, optionally filtered to a given
        room or a given session.

        Args:
            user_id: the user whose backup we're deleting from
            version: the version ID of the backup for the set of keys we're deleting
            room_id: Optional. the ID of the room whose keys we're deleting, if any.
                If not specified, we delete the keys for all the rooms in the backup.
            session_id: Optional. the session whose room_key we're querying, if any.
                If specified, we also require the room_id to be specified.
                If not specified, we delete all the keys in this version of
                the backup (or for the specified room)
        """
        try:
            version_int = int(version)
        except ValueError:
            # Our versions are all ints so if we can't convert it to an integer,
            # it doesn't exist.
            return

        keyvalues = {"user_id": user_id, "version": version_int}
        if room_id:
            keyvalues["room_id"] = room_id
            if session_id:
                keyvalues["session_id"] = session_id

        await self.db_pool.simple_delete(
            table="e2e_room_keys", keyvalues=keyvalues, desc="delete_e2e_room_keys"
        )

    @staticmethod
    def _get_current_version(txn: LoggingTransaction, user_id: str) -> int:
        txn.execute(
            "SELECT MAX(version) FROM e2e_room_keys_versions "
            "WHERE user_id=? AND deleted=0",
            (user_id,),
        )
        # `SELECT MAX() FROM ...` will always return 1 row. The value in that row will
        # be `NULL` when there are no available versions.
        row = cast(Tuple[Optional[int]], txn.fetchone())
        if row[0] is None:
            raise StoreError(404, "No current backup version")
        return row[0]

    async def get_e2e_room_keys_version_info(
        self, user_id: str, version: Optional[str] = None
    ) -> JsonDict:
        """Get info metadata about a version of our room_keys backup.

        Args:
            user_id: the user whose backup we're querying
            version: Optional. the version ID of the backup we're querying about
                If missing, we return the information about the current version.
        Raises:
            StoreError: with code 404 if there are no e2e_room_keys_versions present
        Returns:
            A dict giving the info metadata for this backup version, with
            fields including:
                version(str)
                algorithm(str)
                auth_data(object): opaque dict supplied by the client
                etag(int): tag of the keys in the backup
        """

        def _get_e2e_room_keys_version_info_txn(txn: LoggingTransaction) -> JsonDict:
            if version is None:
                this_version = self._get_current_version(txn, user_id)
            else:
                try:
                    this_version = int(version)
                except ValueError:
                    # Our versions are all ints so if we can't convert it to an integer,
                    # it isn't there.
                    raise StoreError(404, "No backup with that version exists")

            result = self.db_pool.simple_select_one_txn(
                txn,
                table="e2e_room_keys_versions",
                keyvalues={"user_id": user_id, "version": this_version, "deleted": 0},
                retcols=("version", "algorithm", "auth_data", "etag"),
                allow_none=False,
            )
            assert result is not None  # see comment on `simple_select_one_txn`
            result["auth_data"] = db_to_json(result["auth_data"])
            result["version"] = str(result["version"])
            if result["etag"] is None:
                result["etag"] = 0
            return result

        return await self.db_pool.runInteraction(
            "get_e2e_room_keys_version_info", _get_e2e_room_keys_version_info_txn
        )

    @trace
    async def create_e2e_room_keys_version(self, user_id: str, info: JsonDict) -> str:
        """Atomically creates a new version of this user's e2e_room_keys store
        with the given version info.

        Args:
            user_id: the user whose backup we're creating a version
            info: the info about the backup version to be created

        Returns:
            The newly created version ID
        """

        def _create_e2e_room_keys_version_txn(txn: LoggingTransaction) -> str:
            txn.execute(
                "SELECT MAX(version) FROM e2e_room_keys_versions WHERE user_id=?",
                (user_id,),
            )
            current_version = cast(Tuple[Optional[int]], txn.fetchone())[0]
            if current_version is None:
                current_version = 0

            new_version = current_version + 1

            self.db_pool.simple_insert_txn(
                txn,
                table="e2e_room_keys_versions",
                values={
                    "user_id": user_id,
                    "version": new_version,
                    "algorithm": info["algorithm"],
                    "auth_data": json_encoder.encode(info["auth_data"]),
                },
            )

            return str(new_version)

        return await self.db_pool.runInteraction(
            "create_e2e_room_keys_version_txn", _create_e2e_room_keys_version_txn
        )

    @trace
    async def update_e2e_room_keys_version(
        self,
        user_id: str,
        version: str,
        info: Optional[JsonDict] = None,
        version_etag: Optional[int] = None,
    ) -> None:
        """Update a given backup version

        Args:
            user_id: the user whose backup version we're updating
            version: the version ID of the backup version we're updating
            info: the new backup version info to store. If None, then the backup
                version info is not updated.
            version_etag: etag of the keys in the backup. If None, then the etag
                is not updated.
        """
        updatevalues: Dict[str, object] = {}

        if info is not None and "auth_data" in info:
            updatevalues["auth_data"] = json_encoder.encode(info["auth_data"])
        if version_etag is not None:
            updatevalues["etag"] = version_etag

        if updatevalues:
            try:
                version_int = int(version)
            except ValueError:
                # Our versions are all ints so if we can't convert it to an integer,
                # it doesn't exist.
                raise StoreError(404, "No backup with that version exists")

            await self.db_pool.simple_update_one(
                table="e2e_room_keys_versions",
                keyvalues={"user_id": user_id, "version": version_int},
                updatevalues=updatevalues,
                desc="update_e2e_room_keys_version",
            )

    @trace
    async def delete_e2e_room_keys_version(
        self, user_id: str, version: Optional[str] = None
    ) -> None:
        """Delete a given backup version of the user's room keys.
        Doesn't delete their actual key data.

        Args:
            user_id: the user whose backup version we're deleting
            version: Optional. the version ID of the backup version we're deleting
                If missing, we delete the current backup version info.
        Raises:
            StoreError: with code 404 if there are no e2e_room_keys_versions present,
                or if the version requested doesn't exist.
        """

        def _delete_e2e_room_keys_version_txn(txn: LoggingTransaction) -> None:
            if version is None:
                this_version = self._get_current_version(txn, user_id)
            else:
                try:
                    this_version = int(version)
                except ValueError:
                    # Our versions are all ints so if we can't convert it to an integer,
                    # it isn't there.
                    raise StoreError(404, "No backup with that version exists")

            self.db_pool.simple_delete_txn(
                txn,
                table="e2e_room_keys",
                keyvalues={"user_id": user_id, "version": this_version},
            )

            self.db_pool.simple_update_one_txn(
                txn,
                table="e2e_room_keys_versions",
                keyvalues={"user_id": user_id, "version": this_version},
                updatevalues={"deleted": 1},
            )

        await self.db_pool.runInteraction(
            "delete_e2e_room_keys_version", _delete_e2e_room_keys_version_txn
        )
