# -*- coding: utf-8 -*-
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

import json

from twisted.internet import defer

from synapse.api.errors import StoreError
from synapse.logging.opentracing import log_kv, trace
from synapse.storage._base import SQLBaseStore


class EndToEndRoomKeyStore(SQLBaseStore):
    @defer.inlineCallbacks
    def update_e2e_room_key(self, user_id, version, room_id, session_id, room_key):
        """Replaces the encrypted E2E room key for a given session in a given backup

        Args:
            user_id(str): the user whose backup we're setting
            version(str): the version ID of the backup we're updating
            room_id(str): the ID of the room whose keys we're setting
            session_id(str): the session whose room_key we're setting
            room_key(dict): the room_key being set
        Raises:
            StoreError
        """

        yield self.db.simple_update_one(
            table="e2e_room_keys",
            keyvalues={
                "user_id": user_id,
                "version": version,
                "room_id": room_id,
                "session_id": session_id,
            },
            updatevalues={
                "first_message_index": room_key["first_message_index"],
                "forwarded_count": room_key["forwarded_count"],
                "is_verified": room_key["is_verified"],
                "session_data": json.dumps(room_key["session_data"]),
            },
            desc="update_e2e_room_key",
        )

    @defer.inlineCallbacks
    def add_e2e_room_keys(self, user_id, version, room_keys):
        """Bulk add room keys to a given backup.

        Args:
            user_id (str): the user whose backup we're adding to
            version (str): the version ID of the backup for the set of keys we're adding to
            room_keys (iterable[(str, str, dict)]): the keys to add, in the form
                (roomID, sessionID, keyData)
        """

        values = []
        for (room_id, session_id, room_key) in room_keys:
            values.append(
                {
                    "user_id": user_id,
                    "version": version,
                    "room_id": room_id,
                    "session_id": session_id,
                    "first_message_index": room_key["first_message_index"],
                    "forwarded_count": room_key["forwarded_count"],
                    "is_verified": room_key["is_verified"],
                    "session_data": json.dumps(room_key["session_data"]),
                }
            )
            log_kv(
                {
                    "message": "Set room key",
                    "room_id": room_id,
                    "session_id": session_id,
                    "room_key": room_key,
                }
            )

        yield self.db.simple_insert_many(
            table="e2e_room_keys", values=values, desc="add_e2e_room_keys"
        )

    @trace
    @defer.inlineCallbacks
    def get_e2e_room_keys(self, user_id, version, room_id=None, session_id=None):
        """Bulk get the E2E room keys for a given backup, optionally filtered to a given
        room, or a given session.

        Args:
            user_id (str): the user whose backup we're querying
            version (str): the version ID of the backup for the set of keys we're querying
            room_id (str): Optional. the ID of the room whose keys we're querying, if any.
                If not specified, we return the keys for all the rooms in the backup.
            session_id (str): Optional. the session whose room_key we're querying, if any.
                If specified, we also require the room_id to be specified.
                If not specified, we return all the keys in this version of
                the backup (or for the specified room)

        Returns:
            A deferred list of dicts giving the session_data and message metadata for
            these room keys.
        """

        try:
            version = int(version)
        except ValueError:
            return {"rooms": {}}

        keyvalues = {"user_id": user_id, "version": version}
        if room_id:
            keyvalues["room_id"] = room_id
            if session_id:
                keyvalues["session_id"] = session_id

        rows = yield self.db.simple_select_list(
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

        sessions = {"rooms": {}}
        for row in rows:
            room_entry = sessions["rooms"].setdefault(row["room_id"], {"sessions": {}})
            room_entry["sessions"][row["session_id"]] = {
                "first_message_index": row["first_message_index"],
                "forwarded_count": row["forwarded_count"],
                # is_verified must be returned to the client as a boolean
                "is_verified": bool(row["is_verified"]),
                "session_data": json.loads(row["session_data"]),
            }

        return sessions

    def get_e2e_room_keys_multi(self, user_id, version, room_keys):
        """Get multiple room keys at a time.  The difference between this function and
        get_e2e_room_keys is that this function can be used to retrieve
        multiple specific keys at a time, whereas get_e2e_room_keys is used for
        getting all the keys in a backup version, all the keys for a room, or a
        specific key.

        Args:
            user_id (str): the user whose backup we're querying
            version (str): the version ID of the backup we're querying about
            room_keys (dict[str, dict[str, iterable[str]]]): a map from
                room ID -> {"session": [session ids]} indicating the session IDs
                that we want to query

        Returns:
           Deferred[dict[str, dict[str, dict]]]: a map of room IDs to session IDs to room key
        """

        return self.db.runInteraction(
            "get_e2e_room_keys_multi",
            self._get_e2e_room_keys_multi_txn,
            user_id,
            version,
            room_keys,
        )

    @staticmethod
    def _get_e2e_room_keys_multi_txn(txn, user_id, version, room_keys):
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

        ret = {}

        for row in txn:
            room_id = row[0]
            session_id = row[1]
            ret.setdefault(room_id, {})
            ret[room_id][session_id] = {
                "first_message_index": row[2],
                "forwarded_count": row[3],
                "is_verified": row[4],
                "session_data": json.loads(row[5]),
            }

        return ret

    def count_e2e_room_keys(self, user_id, version):
        """Get the number of keys in a backup version.

        Args:
            user_id (str): the user whose backup we're querying
            version (str): the version ID of the backup we're querying about
        """

        return self.db.simple_select_one_onecol(
            table="e2e_room_keys",
            keyvalues={"user_id": user_id, "version": version},
            retcol="COUNT(*)",
            desc="count_e2e_room_keys",
        )

    @trace
    @defer.inlineCallbacks
    def delete_e2e_room_keys(self, user_id, version, room_id=None, session_id=None):
        """Bulk delete the E2E room keys for a given backup, optionally filtered to a given
        room or a given session.

        Args:
            user_id(str): the user whose backup we're deleting from
            version(str): the version ID of the backup for the set of keys we're deleting
            room_id(str): Optional. the ID of the room whose keys we're deleting, if any.
                If not specified, we delete the keys for all the rooms in the backup.
            session_id(str): Optional. the session whose room_key we're querying, if any.
                If specified, we also require the room_id to be specified.
                If not specified, we delete all the keys in this version of
                the backup (or for the specified room)

        Returns:
            A deferred of the deletion transaction
        """

        keyvalues = {"user_id": user_id, "version": int(version)}
        if room_id:
            keyvalues["room_id"] = room_id
            if session_id:
                keyvalues["session_id"] = session_id

        yield self.db.simple_delete(
            table="e2e_room_keys", keyvalues=keyvalues, desc="delete_e2e_room_keys"
        )

    @staticmethod
    def _get_current_version(txn, user_id):
        txn.execute(
            "SELECT MAX(version) FROM e2e_room_keys_versions "
            "WHERE user_id=? AND deleted=0",
            (user_id,),
        )
        row = txn.fetchone()
        if not row:
            raise StoreError(404, "No current backup version")
        return row[0]

    def get_e2e_room_keys_version_info(self, user_id, version=None):
        """Get info metadata about a version of our room_keys backup.

        Args:
            user_id(str): the user whose backup we're querying
            version(str): Optional. the version ID of the backup we're querying about
                If missing, we return the information about the current version.
        Raises:
            StoreError: with code 404 if there are no e2e_room_keys_versions present
        Returns:
            A deferred dict giving the info metadata for this backup version, with
            fields including:
                version(str)
                algorithm(str)
                auth_data(object): opaque dict supplied by the client
                etag(int): tag of the keys in the backup
        """

        def _get_e2e_room_keys_version_info_txn(txn):
            if version is None:
                this_version = self._get_current_version(txn, user_id)
            else:
                try:
                    this_version = int(version)
                except ValueError:
                    # Our versions are all ints so if we can't convert it to an integer,
                    # it isn't there.
                    raise StoreError(404, "No row found")

            result = self.db.simple_select_one_txn(
                txn,
                table="e2e_room_keys_versions",
                keyvalues={"user_id": user_id, "version": this_version, "deleted": 0},
                retcols=("version", "algorithm", "auth_data", "etag"),
            )
            result["auth_data"] = json.loads(result["auth_data"])
            result["version"] = str(result["version"])
            if result["etag"] is None:
                result["etag"] = 0
            return result

        return self.db.runInteraction(
            "get_e2e_room_keys_version_info", _get_e2e_room_keys_version_info_txn
        )

    @trace
    def create_e2e_room_keys_version(self, user_id, info):
        """Atomically creates a new version of this user's e2e_room_keys store
        with the given version info.

        Args:
            user_id(str): the user whose backup we're creating a version
            info(dict): the info about the backup version to be created

        Returns:
            A deferred string for the newly created version ID
        """

        def _create_e2e_room_keys_version_txn(txn):
            txn.execute(
                "SELECT MAX(version) FROM e2e_room_keys_versions WHERE user_id=?",
                (user_id,),
            )
            current_version = txn.fetchone()[0]
            if current_version is None:
                current_version = "0"

            new_version = str(int(current_version) + 1)

            self.db.simple_insert_txn(
                txn,
                table="e2e_room_keys_versions",
                values={
                    "user_id": user_id,
                    "version": new_version,
                    "algorithm": info["algorithm"],
                    "auth_data": json.dumps(info["auth_data"]),
                },
            )

            return new_version

        return self.db.runInteraction(
            "create_e2e_room_keys_version_txn", _create_e2e_room_keys_version_txn
        )

    @trace
    def update_e2e_room_keys_version(
        self, user_id, version, info=None, version_etag=None
    ):
        """Update a given backup version

        Args:
            user_id(str): the user whose backup version we're updating
            version(str): the version ID of the backup version we're updating
            info (dict): the new backup version info to store.  If None, then
                the backup version info is not updated
            version_etag (Optional[int]): etag of the keys in the backup.  If
                None, then the etag is not updated
        """
        updatevalues = {}

        if info is not None and "auth_data" in info:
            updatevalues["auth_data"] = json.dumps(info["auth_data"])
        if version_etag is not None:
            updatevalues["etag"] = version_etag

        if updatevalues:
            return self.db.simple_update(
                table="e2e_room_keys_versions",
                keyvalues={"user_id": user_id, "version": version},
                updatevalues=updatevalues,
                desc="update_e2e_room_keys_version",
            )

    @trace
    def delete_e2e_room_keys_version(self, user_id, version=None):
        """Delete a given backup version of the user's room keys.
        Doesn't delete their actual key data.

        Args:
            user_id(str): the user whose backup version we're deleting
            version(str): Optional. the version ID of the backup version we're deleting
                If missing, we delete the current backup version info.
        Raises:
            StoreError: with code 404 if there are no e2e_room_keys_versions present,
                or if the version requested doesn't exist.
        """

        def _delete_e2e_room_keys_version_txn(txn):
            if version is None:
                this_version = self._get_current_version(txn, user_id)
                if this_version is None:
                    raise StoreError(404, "No current backup version")
            else:
                this_version = version

            self.db.simple_delete_txn(
                txn,
                table="e2e_room_keys",
                keyvalues={"user_id": user_id, "version": this_version},
            )

            return self.db.simple_update_one_txn(
                txn,
                table="e2e_room_keys_versions",
                keyvalues={"user_id": user_id, "version": this_version},
                updatevalues={"deleted": 1},
            )

        return self.db.runInteraction(
            "delete_e2e_room_keys_version", _delete_e2e_room_keys_version_txn
        )
