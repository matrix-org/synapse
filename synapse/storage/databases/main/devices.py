# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd
# Copyright 2019,2020 The Matrix.org Foundation C.I.C.
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
import abc
import logging
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from synapse.api.errors import Codes, StoreError
from synapse.logging.opentracing import (
    get_active_span_text_map,
    set_tag,
    trace,
    whitelisted_homeserver,
)
from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.storage._base import SQLBaseStore, db_to_json, make_in_list_sql_clause
from synapse.storage.database import (
    DatabasePool,
    LoggingTransaction,
    make_tuple_comparison_clause,
)
from synapse.types import Collection, JsonDict, get_verify_key_from_cross_signing_key
from synapse.util import json_decoder, json_encoder
from synapse.util.caches.descriptors import cached, cachedList
from synapse.util.caches.lrucache import LruCache
from synapse.util.iterutils import batch_iter
from synapse.util.stringutils import shortstr

logger = logging.getLogger(__name__)

DROP_DEVICE_LIST_STREAMS_NON_UNIQUE_INDEXES = (
    "drop_device_list_streams_non_unique_indexes"
)

BG_UPDATE_REMOVE_DUP_OUTBOUND_POKES = "remove_dup_outbound_pokes"


class DeviceWorkerStore(SQLBaseStore):
    def __init__(self, database: DatabasePool, db_conn, hs):
        super().__init__(database, db_conn, hs)

        if hs.config.run_background_tasks:
            self._clock.looping_call(
                self._prune_old_outbound_device_pokes, 60 * 60 * 1000
            )

    async def get_device(self, user_id: str, device_id: str) -> Dict[str, Any]:
        """Retrieve a device. Only returns devices that are not marked as
        hidden.

        Args:
            user_id: The ID of the user which owns the device
            device_id: The ID of the device to retrieve
        Returns:
            A dict containing the device information
        Raises:
            StoreError: if the device is not found
        """
        return await self.db_pool.simple_select_one(
            table="devices",
            keyvalues={"user_id": user_id, "device_id": device_id, "hidden": False},
            retcols=("user_id", "device_id", "display_name"),
            desc="get_device",
        )

    async def get_devices_by_user(self, user_id: str) -> Dict[str, Dict[str, str]]:
        """Retrieve all of a user's registered devices. Only returns devices
        that are not marked as hidden.

        Args:
            user_id:
        Returns:
            A mapping from device_id to a dict containing "device_id", "user_id"
            and "display_name" for each device.
        """
        devices = await self.db_pool.simple_select_list(
            table="devices",
            keyvalues={"user_id": user_id, "hidden": False},
            retcols=("user_id", "device_id", "display_name"),
            desc="get_devices_by_user",
        )

        return {d["device_id"]: d for d in devices}

    @trace
    async def get_device_updates_by_remote(
        self, destination: str, from_stream_id: int, limit: int
    ) -> Tuple[int, List[Tuple[str, dict]]]:
        """Get a stream of device updates to send to the given remote server.

        Args:
            destination: The host the device updates are intended for
            from_stream_id: The minimum stream_id to filter updates by, exclusive
            limit: Maximum number of device updates to return

        Returns:
            A mapping from the  current stream id (ie, the stream id of the last
            update included in the response), and the list of updates, where
            each update is a pair of EDU type and EDU contents.
        """
        now_stream_id = self.get_device_stream_token()

        has_changed = self._device_list_federation_stream_cache.has_entity_changed(
            destination, int(from_stream_id)
        )
        if not has_changed:
            return now_stream_id, []

        updates = await self.db_pool.runInteraction(
            "get_device_updates_by_remote",
            self._get_device_updates_by_remote_txn,
            destination,
            from_stream_id,
            now_stream_id,
            limit,
        )

        # Return an empty list if there are no updates
        if not updates:
            return now_stream_id, []

        # get the cross-signing keys of the users in the list, so that we can
        # determine which of the device changes were cross-signing keys
        users = {r[0] for r in updates}
        master_key_by_user = {}
        self_signing_key_by_user = {}
        for user in users:
            cross_signing_key = await self.get_e2e_cross_signing_key(user, "master")
            if cross_signing_key:
                key_id, verify_key = get_verify_key_from_cross_signing_key(
                    cross_signing_key
                )
                # verify_key is a VerifyKey from signedjson, which uses
                # .version to denote the portion of the key ID after the
                # algorithm and colon, which is the device ID
                master_key_by_user[user] = {
                    "key_info": cross_signing_key,
                    "device_id": verify_key.version,
                }

            cross_signing_key = await self.get_e2e_cross_signing_key(
                user, "self_signing"
            )
            if cross_signing_key:
                key_id, verify_key = get_verify_key_from_cross_signing_key(
                    cross_signing_key
                )
                self_signing_key_by_user[user] = {
                    "key_info": cross_signing_key,
                    "device_id": verify_key.version,
                }

        # Perform the equivalent of a GROUP BY
        #
        # Iterate through the updates list and copy non-duplicate
        # (user_id, device_id) entries into a map, with the value being
        # the max stream_id across each set of duplicate entries
        #
        # maps (user_id, device_id) -> (stream_id, opentracing_context)
        #
        # opentracing_context contains the opentracing metadata for the request
        # that created the poke
        #
        # The most recent request's opentracing_context is used as the
        # context which created the Edu.

        query_map = {}
        cross_signing_keys_by_user = {}
        for user_id, device_id, update_stream_id, update_context in updates:
            if (
                user_id in master_key_by_user
                and device_id == master_key_by_user[user_id]["device_id"]
            ):
                result = cross_signing_keys_by_user.setdefault(user_id, {})
                result["master_key"] = master_key_by_user[user_id]["key_info"]
            elif (
                user_id in self_signing_key_by_user
                and device_id == self_signing_key_by_user[user_id]["device_id"]
            ):
                result = cross_signing_keys_by_user.setdefault(user_id, {})
                result["self_signing_key"] = self_signing_key_by_user[user_id][
                    "key_info"
                ]
            else:
                key = (user_id, device_id)

                previous_update_stream_id, _ = query_map.get(key, (0, None))

                if update_stream_id > previous_update_stream_id:
                    query_map[key] = (update_stream_id, update_context)

        results = await self._get_device_update_edus_by_remote(
            destination, from_stream_id, query_map
        )

        # add the updated cross-signing keys to the results list
        for user_id, result in cross_signing_keys_by_user.items():
            result["user_id"] = user_id
            # FIXME: switch to m.signing_key_update when MSC1756 is merged into the spec
            results.append(("org.matrix.signing_key_update", result))

        return now_stream_id, results

    def _get_device_updates_by_remote_txn(
        self,
        txn: LoggingTransaction,
        destination: str,
        from_stream_id: int,
        now_stream_id: int,
        limit: int,
    ):
        """Return device update information for a given remote destination

        Args:
            txn: The transaction to execute
            destination: The host the device updates are intended for
            from_stream_id: The minimum stream_id to filter updates by, exclusive
            now_stream_id: The maximum stream_id to filter updates by, inclusive
            limit: Maximum number of device updates to return

        Returns:
            List: List of device updates
        """
        # get the list of device updates that need to be sent
        sql = """
            SELECT user_id, device_id, stream_id, opentracing_context FROM device_lists_outbound_pokes
            WHERE destination = ? AND ? < stream_id AND stream_id <= ?
            ORDER BY stream_id
            LIMIT ?
        """
        txn.execute(sql, (destination, from_stream_id, now_stream_id, limit))

        return list(txn)

    async def _get_device_update_edus_by_remote(
        self,
        destination: str,
        from_stream_id: int,
        query_map: Dict[Tuple[str, str], Tuple[int, Optional[str]]],
    ) -> List[Tuple[str, dict]]:
        """Returns a list of device update EDUs as well as E2EE keys

        Args:
            destination: The host the device updates are intended for
            from_stream_id: The minimum stream_id to filter updates by, exclusive
            query_map (Dict[(str, str): (int, str|None)]): Dictionary mapping
                user_id/device_id to update stream_id and the relevant json-encoded
                opentracing context

        Returns:
            List of objects representing an device update EDU
        """
        devices = (
            await self.get_e2e_device_keys_and_signatures(
                query_map.keys(),
                include_all_devices=True,
                include_deleted_devices=True,
            )
            if query_map
            else {}
        )

        results = []
        for user_id, user_devices in devices.items():
            # The prev_id for the first row is always the last row before
            # `from_stream_id`
            prev_id = await self._get_last_device_update_for_remote_user(
                destination, user_id, from_stream_id
            )

            # make sure we go through the devices in stream order
            device_ids = sorted(
                user_devices.keys(), key=lambda i: query_map[(user_id, i)][0],
            )

            for device_id in device_ids:
                device = user_devices[device_id]
                stream_id, opentracing_context = query_map[(user_id, device_id)]
                result = {
                    "user_id": user_id,
                    "device_id": device_id,
                    "prev_id": [prev_id] if prev_id else [],
                    "stream_id": stream_id,
                    "org.matrix.opentracing_context": opentracing_context,
                }

                prev_id = stream_id

                if device is not None:
                    keys = device.keys
                    if keys:
                        result["keys"] = keys

                    device_display_name = device.display_name
                    if device_display_name:
                        result["device_display_name"] = device_display_name
                else:
                    result["deleted"] = True

                results.append(("m.device_list_update", result))

        return results

    async def _get_last_device_update_for_remote_user(
        self, destination: str, user_id: str, from_stream_id: int
    ) -> int:
        def f(txn):
            prev_sent_id_sql = """
                SELECT coalesce(max(stream_id), 0) as stream_id
                FROM device_lists_outbound_last_success
                WHERE destination = ? AND user_id = ? AND stream_id <= ?
            """
            txn.execute(prev_sent_id_sql, (destination, user_id, from_stream_id))
            rows = txn.fetchall()
            return rows[0][0]

        return await self.db_pool.runInteraction(
            "get_last_device_update_for_remote_user", f
        )

    async def mark_as_sent_devices_by_remote(
        self, destination: str, stream_id: int
    ) -> None:
        """Mark that updates have successfully been sent to the destination.
        """
        await self.db_pool.runInteraction(
            "mark_as_sent_devices_by_remote",
            self._mark_as_sent_devices_by_remote_txn,
            destination,
            stream_id,
        )

    def _mark_as_sent_devices_by_remote_txn(
        self, txn: LoggingTransaction, destination: str, stream_id: int
    ) -> None:
        # We update the device_lists_outbound_last_success with the successfully
        # poked users.
        sql = """
            SELECT user_id, coalesce(max(o.stream_id), 0)
            FROM device_lists_outbound_pokes as o
            WHERE destination = ? AND o.stream_id <= ?
            GROUP BY user_id
        """
        txn.execute(sql, (destination, stream_id))
        rows = txn.fetchall()

        self.db_pool.simple_upsert_many_txn(
            txn=txn,
            table="device_lists_outbound_last_success",
            key_names=("destination", "user_id"),
            key_values=((destination, user_id) for user_id, _ in rows),
            value_names=("stream_id",),
            value_values=((stream_id,) for _, stream_id in rows),
        )

        # Delete all sent outbound pokes
        sql = """
            DELETE FROM device_lists_outbound_pokes
            WHERE destination = ? AND stream_id <= ?
        """
        txn.execute(sql, (destination, stream_id))

    async def add_user_signature_change_to_streams(
        self, from_user_id: str, user_ids: List[str]
    ) -> int:
        """Persist that a user has made new signatures

        Args:
            from_user_id: the user who made the signatures
            user_ids: the users who were signed

        Returns:
            THe new stream ID.
        """

        async with self._device_list_id_gen.get_next() as stream_id:
            await self.db_pool.runInteraction(
                "add_user_sig_change_to_streams",
                self._add_user_signature_change_txn,
                from_user_id,
                user_ids,
                stream_id,
            )
        return stream_id

    def _add_user_signature_change_txn(
        self,
        txn: LoggingTransaction,
        from_user_id: str,
        user_ids: List[str],
        stream_id: int,
    ) -> None:
        txn.call_after(
            self._user_signature_stream_cache.entity_has_changed,
            from_user_id,
            stream_id,
        )
        self.db_pool.simple_insert_txn(
            txn,
            "user_signature_stream",
            values={
                "stream_id": stream_id,
                "from_user_id": from_user_id,
                "user_ids": json_encoder.encode(user_ids),
            },
        )

    @abc.abstractmethod
    def get_device_stream_token(self) -> int:
        """Get the current stream id from the _device_list_id_gen"""
        ...

    @trace
    async def get_user_devices_from_cache(
        self, query_list: List[Tuple[str, str]]
    ) -> Tuple[Set[str], Dict[str, Dict[str, JsonDict]]]:
        """Get the devices (and keys if any) for remote users from the cache.

        Args:
            query_list: List of (user_id, device_ids), if device_ids is
                falsey then return all device ids for that user.

        Returns:
            A tuple of (user_ids_not_in_cache, results_map), where
            user_ids_not_in_cache is a set of user_ids and results_map is a
            mapping of user_id -> device_id -> device_info.
        """
        user_ids = {user_id for user_id, _ in query_list}
        user_map = await self.get_device_list_last_stream_id_for_remotes(list(user_ids))

        # We go and check if any of the users need to have their device lists
        # resynced. If they do then we remove them from the cached list.
        users_needing_resync = await self.get_user_ids_requiring_device_list_resync(
            user_ids
        )
        user_ids_in_cache = {
            user_id for user_id, stream_id in user_map.items() if stream_id
        } - users_needing_resync
        user_ids_not_in_cache = user_ids - user_ids_in_cache

        results = {}
        for user_id, device_id in query_list:
            if user_id not in user_ids_in_cache:
                continue

            if device_id:
                device = await self._get_cached_user_device(user_id, device_id)
                results.setdefault(user_id, {})[device_id] = device
            else:
                results[user_id] = await self.get_cached_devices_for_user(user_id)

        set_tag("in_cache", results)
        set_tag("not_in_cache", user_ids_not_in_cache)

        return user_ids_not_in_cache, results

    @cached(num_args=2, tree=True)
    async def _get_cached_user_device(self, user_id: str, device_id: str) -> JsonDict:
        content = await self.db_pool.simple_select_one_onecol(
            table="device_lists_remote_cache",
            keyvalues={"user_id": user_id, "device_id": device_id},
            retcol="content",
            desc="_get_cached_user_device",
        )
        return db_to_json(content)

    @cached()
    async def get_cached_devices_for_user(self, user_id: str) -> Dict[str, JsonDict]:
        devices = await self.db_pool.simple_select_list(
            table="device_lists_remote_cache",
            keyvalues={"user_id": user_id},
            retcols=("device_id", "content"),
            desc="get_cached_devices_for_user",
        )
        return {
            device["device_id"]: db_to_json(device["content"]) for device in devices
        }

    async def get_users_whose_devices_changed(
        self, from_key: int, user_ids: Iterable[str]
    ) -> Set[str]:
        """Get set of users whose devices have changed since `from_key` that
        are in the given list of user_ids.

        Args:
            from_key: The device lists stream token
            user_ids: The user IDs to query for devices.

        Returns:
            The set of user_ids whose devices have changed since `from_key`
        """

        # Get set of users who *may* have changed. Users not in the returned
        # list have definitely not changed.
        to_check = self._device_list_stream_cache.get_entities_changed(
            user_ids, from_key
        )

        if not to_check:
            return set()

        def _get_users_whose_devices_changed_txn(txn):
            changes = set()

            sql = """
                SELECT DISTINCT user_id FROM device_lists_stream
                WHERE stream_id > ?
                AND
            """

            for chunk in batch_iter(to_check, 100):
                clause, args = make_in_list_sql_clause(
                    txn.database_engine, "user_id", chunk
                )
                txn.execute(sql + clause, (from_key,) + tuple(args))
                changes.update(user_id for user_id, in txn)

            return changes

        return await self.db_pool.runInteraction(
            "get_users_whose_devices_changed", _get_users_whose_devices_changed_txn
        )

    async def get_users_whose_signatures_changed(
        self, user_id: str, from_key: int
    ) -> Set[str]:
        """Get the users who have new cross-signing signatures made by `user_id` since
        `from_key`.

        Args:
            user_id: the user who made the signatures
            from_key: The device lists stream token

        Returns:
            A set of user IDs with updated signatures.
        """

        if self._user_signature_stream_cache.has_entity_changed(user_id, from_key):
            sql = """
                SELECT DISTINCT user_ids FROM user_signature_stream
                WHERE from_user_id = ? AND stream_id > ?
            """
            rows = await self.db_pool.execute(
                "get_users_whose_signatures_changed", None, sql, user_id, from_key
            )
            return {user for row in rows for user in db_to_json(row[0])}
        else:
            return set()

    async def get_all_device_list_changes_for_remotes(
        self, instance_name: str, last_id: int, current_id: int, limit: int
    ) -> Tuple[List[Tuple[int, tuple]], int, bool]:
        """Get updates for device lists replication stream.

        Args:
            instance_name: The writer we want to fetch updates from. Unused
                here since there is only ever one writer.
            last_id: The token to fetch updates from. Exclusive.
            current_id: The token to fetch updates up to. Inclusive.
            limit: The requested limit for the number of rows to return. The
                function may return more or fewer rows.

        Returns:
            A tuple consisting of: the updates, a token to use to fetch
            subsequent updates, and whether we returned fewer rows than exists
            between the requested tokens due to the limit.

            The token returned can be used in a subsequent call to this
            function to get further updates.

            The updates are a list of 2-tuples of stream ID and the row data
        """

        if last_id == current_id:
            return [], current_id, False

        def _get_all_device_list_changes_for_remotes(txn):
            # This query Does The Right Thing where it'll correctly apply the
            # bounds to the inner queries.
            sql = """
                SELECT stream_id, entity FROM (
                    SELECT stream_id, user_id AS entity FROM device_lists_stream
                    UNION ALL
                    SELECT stream_id, destination AS entity FROM device_lists_outbound_pokes
                ) AS e
                WHERE ? < stream_id AND stream_id <= ?
                LIMIT ?
            """

            txn.execute(sql, (last_id, current_id, limit))
            updates = [(row[0], row[1:]) for row in txn]
            limited = False
            upto_token = current_id
            if len(updates) >= limit:
                upto_token = updates[-1][0]
                limited = True

            return updates, upto_token, limited

        return await self.db_pool.runInteraction(
            "get_all_device_list_changes_for_remotes",
            _get_all_device_list_changes_for_remotes,
        )

    @cached(max_entries=10000)
    async def get_device_list_last_stream_id_for_remote(
        self, user_id: str
    ) -> Optional[Any]:
        """Get the last stream_id we got for a user. May be None if we haven't
        got any information for them.
        """
        return await self.db_pool.simple_select_one_onecol(
            table="device_lists_remote_extremeties",
            keyvalues={"user_id": user_id},
            retcol="stream_id",
            desc="get_device_list_last_stream_id_for_remote",
            allow_none=True,
        )

    @cachedList(
        cached_method_name="get_device_list_last_stream_id_for_remote",
        list_name="user_ids",
    )
    async def get_device_list_last_stream_id_for_remotes(self, user_ids: str):
        rows = await self.db_pool.simple_select_many_batch(
            table="device_lists_remote_extremeties",
            column="user_id",
            iterable=user_ids,
            retcols=("user_id", "stream_id"),
            desc="get_device_list_last_stream_id_for_remotes",
        )

        results = {user_id: None for user_id in user_ids}
        results.update({row["user_id"]: row["stream_id"] for row in rows})

        return results

    async def get_user_ids_requiring_device_list_resync(
        self, user_ids: Optional[Collection[str]] = None,
    ) -> Set[str]:
        """Given a list of remote users return the list of users that we
        should resync the device lists for. If None is given instead of a list,
        return every user that we should resync the device lists for.

        Returns:
            The IDs of users whose device lists need resync.
        """
        if user_ids:
            rows = await self.db_pool.simple_select_many_batch(
                table="device_lists_remote_resync",
                column="user_id",
                iterable=user_ids,
                retcols=("user_id",),
                desc="get_user_ids_requiring_device_list_resync_with_iterable",
            )
        else:
            rows = await self.db_pool.simple_select_list(
                table="device_lists_remote_resync",
                keyvalues=None,
                retcols=("user_id",),
                desc="get_user_ids_requiring_device_list_resync",
            )

        return {row["user_id"] for row in rows}

    async def mark_remote_user_device_cache_as_stale(self, user_id: str) -> None:
        """Records that the server has reason to believe the cache of the devices
        for the remote users is out of date.
        """
        await self.db_pool.simple_upsert(
            table="device_lists_remote_resync",
            keyvalues={"user_id": user_id},
            values={},
            insertion_values={"added_ts": self._clock.time_msec()},
            desc="make_remote_user_device_cache_as_stale",
        )

    async def mark_remote_user_device_list_as_unsubscribed(self, user_id: str) -> None:
        """Mark that we no longer track device lists for remote user.
        """

        def _mark_remote_user_device_list_as_unsubscribed_txn(txn):
            self.db_pool.simple_delete_txn(
                txn,
                table="device_lists_remote_extremeties",
                keyvalues={"user_id": user_id},
            )
            self._invalidate_cache_and_stream(
                txn, self.get_device_list_last_stream_id_for_remote, (user_id,)
            )

        await self.db_pool.runInteraction(
            "mark_remote_user_device_list_as_unsubscribed",
            _mark_remote_user_device_list_as_unsubscribed_txn,
        )

    async def get_dehydrated_device(
        self, user_id: str
    ) -> Optional[Tuple[str, JsonDict]]:
        """Retrieve the information for a dehydrated device.

        Args:
            user_id: the user whose dehydrated device we are looking for
        Returns:
            a tuple whose first item is the device ID, and the second item is
            the dehydrated device information
        """
        # FIXME: make sure device ID still exists in devices table
        row = await self.db_pool.simple_select_one(
            table="dehydrated_devices",
            keyvalues={"user_id": user_id},
            retcols=["device_id", "device_data"],
            allow_none=True,
        )
        return (
            (row["device_id"], json_decoder.decode(row["device_data"])) if row else None
        )

    def _store_dehydrated_device_txn(
        self, txn, user_id: str, device_id: str, device_data: str
    ) -> Optional[str]:
        old_device_id = self.db_pool.simple_select_one_onecol_txn(
            txn,
            table="dehydrated_devices",
            keyvalues={"user_id": user_id},
            retcol="device_id",
            allow_none=True,
        )
        self.db_pool.simple_upsert_txn(
            txn,
            table="dehydrated_devices",
            keyvalues={"user_id": user_id},
            values={"device_id": device_id, "device_data": device_data},
        )
        return old_device_id

    async def store_dehydrated_device(
        self, user_id: str, device_id: str, device_data: JsonDict
    ) -> Optional[str]:
        """Store a dehydrated device for a user.

        Args:
            user_id: the user that we are storing the device for
            device_id: the ID of the dehydrated device
            device_data: the dehydrated device information
        Returns:
            device id of the user's previous dehydrated device, if any
        """
        return await self.db_pool.runInteraction(
            "store_dehydrated_device_txn",
            self._store_dehydrated_device_txn,
            user_id,
            device_id,
            json_encoder.encode(device_data),
        )

    async def remove_dehydrated_device(self, user_id: str, device_id: str) -> bool:
        """Remove a dehydrated device.

        Args:
            user_id: the user that the dehydrated device belongs to
            device_id: the ID of the dehydrated device
        """
        count = await self.db_pool.simple_delete(
            "dehydrated_devices",
            {"user_id": user_id, "device_id": device_id},
            desc="remove_dehydrated_device",
        )
        return count >= 1

    @wrap_as_background_process("prune_old_outbound_device_pokes")
    async def _prune_old_outbound_device_pokes(
        self, prune_age: int = 24 * 60 * 60 * 1000
    ) -> None:
        """Delete old entries out of the device_lists_outbound_pokes to ensure
        that we don't fill up due to dead servers.

        Normally, we try to send device updates as a delta since a previous known point:
        this is done by setting the prev_id in the m.device_list_update EDU. However,
        for that to work, we have to have a complete record of each change to
        each device, which can add up to quite a lot of data.

        An alternative mechanism is that, if the remote server sees that it has missed
        an entry in the stream_id sequence for a given user, it will request a full
        list of that user's devices. Hence, we can reduce the amount of data we have to
        store (and transmit in some future transaction), by clearing almost everything
        for a given destination out of the database, and having the remote server
        resync.

        All we need to do is make sure we keep at least one row for each
        (user, destination) pair, to remind us to send a m.device_list_update EDU for
        that user when the destination comes back. It doesn't matter which device
        we keep.
        """
        yesterday = self._clock.time_msec() - prune_age

        def _prune_txn(txn):
            # look for (user, destination) pairs which have an update older than
            # the cutoff.
            #
            # For each pair, we also need to know the most recent stream_id, and
            # an arbitrary device_id at that stream_id.
            select_sql = """
            SELECT
                dlop1.destination,
                dlop1.user_id,
                MAX(dlop1.stream_id) AS stream_id,
                (SELECT MIN(dlop2.device_id) AS device_id FROM
                    device_lists_outbound_pokes dlop2
                    WHERE dlop2.destination = dlop1.destination AND
                      dlop2.user_id=dlop1.user_id AND
                      dlop2.stream_id=MAX(dlop1.stream_id)
                )
            FROM device_lists_outbound_pokes dlop1
                GROUP BY destination, user_id
                HAVING min(ts) < ? AND count(*) > 1
            """

            txn.execute(select_sql, (yesterday,))
            rows = txn.fetchall()

            if not rows:
                return

            logger.info(
                "Pruning old outbound device list updates for %i users/destinations: %s",
                len(rows),
                shortstr((row[0], row[1]) for row in rows),
            )

            # we want to keep the update with the highest stream_id for each user.
            #
            # there might be more than one update (with different device_ids) with the
            # same stream_id, so we also delete all but one rows with the max stream id.
            delete_sql = """
                DELETE FROM device_lists_outbound_pokes
                WHERE destination = ? AND user_id = ? AND (
                    stream_id < ? OR
                    (stream_id = ? AND device_id != ?)
                )
            """
            count = 0
            for (destination, user_id, stream_id, device_id) in rows:
                txn.execute(
                    delete_sql, (destination, user_id, stream_id, stream_id, device_id)
                )
                count += txn.rowcount

            # Since we've deleted unsent deltas, we need to remove the entry
            # of last successful sent so that the prev_ids are correctly set.
            sql = """
                DELETE FROM device_lists_outbound_last_success
                WHERE destination = ? AND user_id = ?
            """
            txn.executemany(sql, ((row[0], row[1]) for row in rows))

            logger.info("Pruned %d device list outbound pokes", count)

        await self.db_pool.runInteraction(
            "_prune_old_outbound_device_pokes", _prune_txn,
        )


class DeviceBackgroundUpdateStore(SQLBaseStore):
    def __init__(self, database: DatabasePool, db_conn, hs):
        super().__init__(database, db_conn, hs)

        self.db_pool.updates.register_background_index_update(
            "device_lists_stream_idx",
            index_name="device_lists_stream_user_id",
            table="device_lists_stream",
            columns=["user_id", "device_id"],
        )

        # create a unique index on device_lists_remote_cache
        self.db_pool.updates.register_background_index_update(
            "device_lists_remote_cache_unique_idx",
            index_name="device_lists_remote_cache_unique_id",
            table="device_lists_remote_cache",
            columns=["user_id", "device_id"],
            unique=True,
        )

        # And one on device_lists_remote_extremeties
        self.db_pool.updates.register_background_index_update(
            "device_lists_remote_extremeties_unique_idx",
            index_name="device_lists_remote_extremeties_unique_idx",
            table="device_lists_remote_extremeties",
            columns=["user_id"],
            unique=True,
        )

        # once they complete, we can remove the old non-unique indexes.
        self.db_pool.updates.register_background_update_handler(
            DROP_DEVICE_LIST_STREAMS_NON_UNIQUE_INDEXES,
            self._drop_device_list_streams_non_unique_indexes,
        )

        # clear out duplicate device list outbound pokes
        self.db_pool.updates.register_background_update_handler(
            BG_UPDATE_REMOVE_DUP_OUTBOUND_POKES, self._remove_duplicate_outbound_pokes,
        )

        # a pair of background updates that were added during the 1.14 release cycle,
        # but replaced with 58/06dlols_unique_idx.py
        self.db_pool.updates.register_noop_background_update(
            "device_lists_outbound_last_success_unique_idx",
        )
        self.db_pool.updates.register_noop_background_update(
            "drop_device_lists_outbound_last_success_non_unique_idx",
        )

    async def _drop_device_list_streams_non_unique_indexes(self, progress, batch_size):
        def f(conn):
            txn = conn.cursor()
            txn.execute("DROP INDEX IF EXISTS device_lists_remote_cache_id")
            txn.execute("DROP INDEX IF EXISTS device_lists_remote_extremeties_id")
            txn.close()

        await self.db_pool.runWithConnection(f)
        await self.db_pool.updates._end_background_update(
            DROP_DEVICE_LIST_STREAMS_NON_UNIQUE_INDEXES
        )
        return 1

    async def _remove_duplicate_outbound_pokes(self, progress, batch_size):
        # for some reason, we have accumulated duplicate entries in
        # device_lists_outbound_pokes, which makes prune_outbound_device_list_pokes less
        # efficient.
        #
        # For each duplicate, we delete all the existing rows and put one back.

        KEY_COLS = ["stream_id", "destination", "user_id", "device_id"]
        last_row = progress.get(
            "last_row",
            {"stream_id": 0, "destination": "", "user_id": "", "device_id": ""},
        )

        def _txn(txn):
            clause, args = make_tuple_comparison_clause(
                self.db_pool.engine, [(x, last_row[x]) for x in KEY_COLS]
            )
            sql = """
                SELECT stream_id, destination, user_id, device_id, MAX(ts) AS ts
                FROM device_lists_outbound_pokes
                WHERE %s
                GROUP BY %s
                HAVING count(*) > 1
                ORDER BY %s
                LIMIT ?
                """ % (
                clause,  # WHERE
                ",".join(KEY_COLS),  # GROUP BY
                ",".join(KEY_COLS),  # ORDER BY
            )
            txn.execute(sql, args + [batch_size])
            rows = self.db_pool.cursor_to_dict(txn)

            row = None
            for row in rows:
                self.db_pool.simple_delete_txn(
                    txn, "device_lists_outbound_pokes", {x: row[x] for x in KEY_COLS},
                )

                row["sent"] = False
                self.db_pool.simple_insert_txn(
                    txn, "device_lists_outbound_pokes", row,
                )

            if row:
                self.db_pool.updates._background_update_progress_txn(
                    txn, BG_UPDATE_REMOVE_DUP_OUTBOUND_POKES, {"last_row": row},
                )

            return len(rows)

        rows = await self.db_pool.runInteraction(
            BG_UPDATE_REMOVE_DUP_OUTBOUND_POKES, _txn
        )

        if not rows:
            await self.db_pool.updates._end_background_update(
                BG_UPDATE_REMOVE_DUP_OUTBOUND_POKES
            )

        return rows


class DeviceStore(DeviceWorkerStore, DeviceBackgroundUpdateStore):
    def __init__(self, database: DatabasePool, db_conn, hs):
        super().__init__(database, db_conn, hs)

        # Map of (user_id, device_id) -> bool. If there is an entry that implies
        # the device exists.
        self.device_id_exists_cache = LruCache(
            cache_name="device_id_exists", keylen=2, max_size=10000
        )

    async def store_device(
        self, user_id: str, device_id: str, initial_device_display_name: Optional[str]
    ) -> bool:
        """Ensure the given device is known; add it to the store if not

        Args:
            user_id: id of user associated with the device
            device_id: id of device
            initial_device_display_name: initial displayname of the device.
                Ignored if device exists.

        Returns:
            Whether the device was inserted or an existing device existed with that ID.

        Raises:
            StoreError: if the device is already in use
        """
        key = (user_id, device_id)
        if self.device_id_exists_cache.get(key, None):
            return False

        try:
            inserted = await self.db_pool.simple_insert(
                "devices",
                values={
                    "user_id": user_id,
                    "device_id": device_id,
                    "display_name": initial_device_display_name,
                    "hidden": False,
                },
                desc="store_device",
                or_ignore=True,
            )
            if not inserted:
                # if the device already exists, check if it's a real device, or
                # if the device ID is reserved by something else
                hidden = await self.db_pool.simple_select_one_onecol(
                    "devices",
                    keyvalues={"user_id": user_id, "device_id": device_id},
                    retcol="hidden",
                )
                if hidden:
                    raise StoreError(400, "The device ID is in use", Codes.FORBIDDEN)
            self.device_id_exists_cache.set(key, True)
            return inserted
        except StoreError:
            raise
        except Exception as e:
            logger.error(
                "store_device with device_id=%s(%r) user_id=%s(%r)"
                " display_name=%s(%r) failed: %s",
                type(device_id).__name__,
                device_id,
                type(user_id).__name__,
                user_id,
                type(initial_device_display_name).__name__,
                initial_device_display_name,
                e,
            )
            raise StoreError(500, "Problem storing device.")

    async def delete_device(self, user_id: str, device_id: str) -> None:
        """Delete a device.

        Args:
            user_id: The ID of the user which owns the device
            device_id: The ID of the device to delete
        """
        await self.db_pool.simple_delete_one(
            table="devices",
            keyvalues={"user_id": user_id, "device_id": device_id, "hidden": False},
            desc="delete_device",
        )

        self.device_id_exists_cache.invalidate((user_id, device_id))

    async def delete_devices(self, user_id: str, device_ids: List[str]) -> None:
        """Deletes several devices.

        Args:
            user_id: The ID of the user which owns the devices
            device_ids: The IDs of the devices to delete
        """
        await self.db_pool.simple_delete_many(
            table="devices",
            column="device_id",
            iterable=device_ids,
            keyvalues={"user_id": user_id, "hidden": False},
            desc="delete_devices",
        )
        for device_id in device_ids:
            self.device_id_exists_cache.invalidate((user_id, device_id))

    async def update_device(
        self, user_id: str, device_id: str, new_display_name: Optional[str] = None
    ) -> None:
        """Update a device. Only updates the device if it is not marked as
        hidden.

        Args:
            user_id: The ID of the user which owns the device
            device_id: The ID of the device to update
            new_display_name: new displayname for device; None to leave unchanged
        Raises:
            StoreError: if the device is not found
        """
        updates = {}
        if new_display_name is not None:
            updates["display_name"] = new_display_name
        if not updates:
            return None
        await self.db_pool.simple_update_one(
            table="devices",
            keyvalues={"user_id": user_id, "device_id": device_id, "hidden": False},
            updatevalues=updates,
            desc="update_device",
        )

    async def update_remote_device_list_cache_entry(
        self, user_id: str, device_id: str, content: JsonDict, stream_id: str
    ) -> None:
        """Updates a single device in the cache of a remote user's devicelist.

        Note: assumes that we are the only thread that can be updating this user's
        device list.

        Args:
            user_id: User to update device list for
            device_id: ID of decivice being updated
            content: new data on this device
            stream_id: the version of the device list
        """
        await self.db_pool.runInteraction(
            "update_remote_device_list_cache_entry",
            self._update_remote_device_list_cache_entry_txn,
            user_id,
            device_id,
            content,
            stream_id,
        )

    def _update_remote_device_list_cache_entry_txn(
        self,
        txn: LoggingTransaction,
        user_id: str,
        device_id: str,
        content: JsonDict,
        stream_id: str,
    ) -> None:
        if content.get("deleted"):
            self.db_pool.simple_delete_txn(
                txn,
                table="device_lists_remote_cache",
                keyvalues={"user_id": user_id, "device_id": device_id},
            )

            txn.call_after(self.device_id_exists_cache.invalidate, (user_id, device_id))
        else:
            self.db_pool.simple_upsert_txn(
                txn,
                table="device_lists_remote_cache",
                keyvalues={"user_id": user_id, "device_id": device_id},
                values={"content": json_encoder.encode(content)},
                # we don't need to lock, because we assume we are the only thread
                # updating this user's devices.
                lock=False,
            )

        txn.call_after(self._get_cached_user_device.invalidate, (user_id, device_id))
        txn.call_after(self.get_cached_devices_for_user.invalidate, (user_id,))
        txn.call_after(
            self.get_device_list_last_stream_id_for_remote.invalidate, (user_id,)
        )

        self.db_pool.simple_upsert_txn(
            txn,
            table="device_lists_remote_extremeties",
            keyvalues={"user_id": user_id},
            values={"stream_id": stream_id},
            # again, we can assume we are the only thread updating this user's
            # extremity.
            lock=False,
        )

    async def update_remote_device_list_cache(
        self, user_id: str, devices: List[dict], stream_id: int
    ) -> None:
        """Replace the entire cache of the remote user's devices.

        Note: assumes that we are the only thread that can be updating this user's
        device list.

        Args:
            user_id: User to update device list for
            devices: list of device objects supplied over federation
            stream_id: the version of the device list
        """
        await self.db_pool.runInteraction(
            "update_remote_device_list_cache",
            self._update_remote_device_list_cache_txn,
            user_id,
            devices,
            stream_id,
        )

    def _update_remote_device_list_cache_txn(
        self, txn: LoggingTransaction, user_id: str, devices: List[dict], stream_id: int
    ) -> None:
        self.db_pool.simple_delete_txn(
            txn, table="device_lists_remote_cache", keyvalues={"user_id": user_id}
        )

        self.db_pool.simple_insert_many_txn(
            txn,
            table="device_lists_remote_cache",
            values=[
                {
                    "user_id": user_id,
                    "device_id": content["device_id"],
                    "content": json_encoder.encode(content),
                }
                for content in devices
            ],
        )

        txn.call_after(self.get_cached_devices_for_user.invalidate, (user_id,))
        txn.call_after(self._get_cached_user_device.invalidate_many, (user_id,))
        txn.call_after(
            self.get_device_list_last_stream_id_for_remote.invalidate, (user_id,)
        )

        self.db_pool.simple_upsert_txn(
            txn,
            table="device_lists_remote_extremeties",
            keyvalues={"user_id": user_id},
            values={"stream_id": stream_id},
            # we don't need to lock, because we can assume we are the only thread
            # updating this user's extremity.
            lock=False,
        )

        # If we're replacing the remote user's device list cache presumably
        # we've done a full resync, so we remove the entry that says we need
        # to resync
        self.db_pool.simple_delete_txn(
            txn, table="device_lists_remote_resync", keyvalues={"user_id": user_id},
        )

    async def add_device_change_to_streams(
        self, user_id: str, device_ids: Collection[str], hosts: List[str]
    ):
        """Persist that a user's devices have been updated, and which hosts
        (if any) should be poked.
        """
        if not device_ids:
            return

        async with self._device_list_id_gen.get_next_mult(
            len(device_ids)
        ) as stream_ids:
            await self.db_pool.runInteraction(
                "add_device_change_to_stream",
                self._add_device_change_to_stream_txn,
                user_id,
                device_ids,
                stream_ids,
            )

        if not hosts:
            return stream_ids[-1]

        context = get_active_span_text_map()
        async with self._device_list_id_gen.get_next_mult(
            len(hosts) * len(device_ids)
        ) as stream_ids:
            await self.db_pool.runInteraction(
                "add_device_outbound_poke_to_stream",
                self._add_device_outbound_poke_to_stream_txn,
                user_id,
                device_ids,
                hosts,
                stream_ids,
                context,
            )

        return stream_ids[-1]

    def _add_device_change_to_stream_txn(
        self,
        txn: LoggingTransaction,
        user_id: str,
        device_ids: Collection[str],
        stream_ids: List[str],
    ):
        txn.call_after(
            self._device_list_stream_cache.entity_has_changed, user_id, stream_ids[-1],
        )

        min_stream_id = stream_ids[0]

        # Delete older entries in the table, as we really only care about
        # when the latest change happened.
        txn.executemany(
            """
            DELETE FROM device_lists_stream
            WHERE user_id = ? AND device_id = ? AND stream_id < ?
            """,
            [(user_id, device_id, min_stream_id) for device_id in device_ids],
        )

        self.db_pool.simple_insert_many_txn(
            txn,
            table="device_lists_stream",
            values=[
                {"stream_id": stream_id, "user_id": user_id, "device_id": device_id}
                for stream_id, device_id in zip(stream_ids, device_ids)
            ],
        )

    def _add_device_outbound_poke_to_stream_txn(
        self,
        txn: LoggingTransaction,
        user_id: str,
        device_ids: Collection[str],
        hosts: List[str],
        stream_ids: List[str],
        context: Dict[str, str],
    ):
        for host in hosts:
            txn.call_after(
                self._device_list_federation_stream_cache.entity_has_changed,
                host,
                stream_ids[-1],
            )

        now = self._clock.time_msec()
        next_stream_id = iter(stream_ids)

        self.db_pool.simple_insert_many_txn(
            txn,
            table="device_lists_outbound_pokes",
            values=[
                {
                    "destination": destination,
                    "stream_id": next(next_stream_id),
                    "user_id": user_id,
                    "device_id": device_id,
                    "sent": False,
                    "ts": now,
                    "opentracing_context": json_encoder.encode(context)
                    if whitelisted_homeserver(destination)
                    else "{}",
                }
                for destination in hosts
                for device_id in device_ids
            ],
        )
