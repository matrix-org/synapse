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
from typing import (
    TYPE_CHECKING,
    Any,
    Collection,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    cast,
)

from typing_extensions import Literal

from synapse.api.constants import EduTypes
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
    LoggingDatabaseConnection,
    LoggingTransaction,
    make_tuple_comparison_clause,
)
from synapse.storage.databases.main.end_to_end_keys import EndToEndKeyWorkerStore
from synapse.storage.databases.main.roommember import RoomMemberWorkerStore
from synapse.storage.types import Cursor
from synapse.types import JsonDict, get_verify_key_from_cross_signing_key
from synapse.util import json_decoder, json_encoder
from synapse.util.caches.descriptors import cached, cachedList
from synapse.util.caches.lrucache import LruCache
from synapse.util.caches.stream_change_cache import StreamChangeCache
from synapse.util.cancellation import cancellable
from synapse.util.iterutils import batch_iter
from synapse.util.stringutils import shortstr

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)
issue_8631_logger = logging.getLogger("synapse.8631_debug")

DROP_DEVICE_LIST_STREAMS_NON_UNIQUE_INDEXES = (
    "drop_device_list_streams_non_unique_indexes"
)

BG_UPDATE_REMOVE_DUP_OUTBOUND_POKES = "remove_dup_outbound_pokes"


class DeviceWorkerStore(RoomMemberWorkerStore, EndToEndKeyWorkerStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        # Type-ignore: _device_list_id_gen is mixed in from either DataStore (as a
        # StreamIdGenerator) or SlavedDataStore (as a SlavedIdTracker).
        device_list_max = self._device_list_id_gen.get_current_token()  # type: ignore[attr-defined]
        device_list_prefill, min_device_list_id = self.db_pool.get_cache_dict(
            db_conn,
            "device_lists_stream",
            entity_column="user_id",
            stream_column="stream_id",
            max_value=device_list_max,
            limit=10000,
        )
        self._device_list_stream_cache = StreamChangeCache(
            "DeviceListStreamChangeCache",
            min_device_list_id,
            prefilled_cache=device_list_prefill,
        )

        (
            user_signature_stream_prefill,
            user_signature_stream_list_id,
        ) = self.db_pool.get_cache_dict(
            db_conn,
            "user_signature_stream",
            entity_column="from_user_id",
            stream_column="stream_id",
            max_value=device_list_max,
            limit=1000,
        )
        self._user_signature_stream_cache = StreamChangeCache(
            "UserSignatureStreamChangeCache",
            user_signature_stream_list_id,
            prefilled_cache=user_signature_stream_prefill,
        )

        (
            device_list_federation_prefill,
            device_list_federation_list_id,
        ) = self.db_pool.get_cache_dict(
            db_conn,
            "device_lists_outbound_pokes",
            entity_column="destination",
            stream_column="stream_id",
            max_value=device_list_max,
            limit=10000,
        )
        self._device_list_federation_stream_cache = StreamChangeCache(
            "DeviceListFederationStreamChangeCache",
            device_list_federation_list_id,
            prefilled_cache=device_list_federation_prefill,
        )

        if hs.config.worker.run_background_tasks:
            self._clock.looping_call(
                self._prune_old_outbound_device_pokes, 60 * 60 * 1000
            )

    async def count_devices_by_users(self, user_ids: Optional[List[str]] = None) -> int:
        """Retrieve number of all devices of given users.
        Only returns number of devices that are not marked as hidden.

        Args:
            user_ids: The IDs of the users which owns devices
        Returns:
            Number of devices of this users.
        """

        def count_devices_by_users_txn(
            txn: LoggingTransaction, user_ids: List[str]
        ) -> int:
            sql = """
                SELECT count(*)
                FROM devices
                WHERE
                    hidden = '0' AND
            """

            clause, args = make_in_list_sql_clause(
                txn.database_engine, "user_id", user_ids
            )

            txn.execute(sql + clause, args)
            return cast(Tuple[int], txn.fetchone())[0]

        if not user_ids:
            return 0

        return await self.db_pool.runInteraction(
            "count_devices_by_users", count_devices_by_users_txn, user_ids
        )

    async def get_device(
        self, user_id: str, device_id: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a device. Only returns devices that are not marked as
        hidden.

        Args:
            user_id: The ID of the user which owns the device
            device_id: The ID of the device to retrieve
        Returns:
            A dict containing the device information, or `None` if the device does not
            exist.
        """
        return await self.db_pool.simple_select_one(
            table="devices",
            keyvalues={"user_id": user_id, "device_id": device_id, "hidden": False},
            retcols=("user_id", "device_id", "display_name"),
            desc="get_device",
            allow_none=True,
        )

    async def get_device_opt(
        self, user_id: str, device_id: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a device. Only returns devices that are not marked as
        hidden.

        Args:
            user_id: The ID of the user which owns the device
            device_id: The ID of the device to retrieve
        Returns:
            A dict containing the device information, or None if the device does not exist.
        """
        return await self.db_pool.simple_select_one(
            table="devices",
            keyvalues={"user_id": user_id, "device_id": device_id, "hidden": False},
            retcols=("user_id", "device_id", "display_name"),
            desc="get_device",
            allow_none=True,
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

    async def get_devices_by_auth_provider_session_id(
        self, auth_provider_id: str, auth_provider_session_id: str
    ) -> List[Dict[str, Any]]:
        """Retrieve the list of devices associated with a SSO IdP session ID.

        Args:
            auth_provider_id: The SSO IdP ID as defined in the server config
            auth_provider_session_id: The session ID within the IdP
        Returns:
            A list of dicts containing the device_id and the user_id of each device
        """
        return await self.db_pool.simple_select_list(
            table="device_auth_providers",
            keyvalues={
                "auth_provider_id": auth_provider_id,
                "auth_provider_session_id": auth_provider_session_id,
            },
            retcols=("user_id", "device_id"),
            desc="get_devices_by_auth_provider_session_id",
        )

    @trace
    async def get_device_updates_by_remote(
        self, destination: str, from_stream_id: int, limit: int
    ) -> Tuple[int, List[Tuple[str, JsonDict]]]:
        """Get a stream of device updates to send to the given remote server.

        Args:
            destination: The host the device updates are intended for
            from_stream_id: The minimum stream_id to filter updates by, exclusive
            limit: Maximum number of device updates to return

        Returns:
            - The current stream id (i.e. the stream id of the last update included
              in the response); and
            - The list of updates, where each update is a pair of EDU type and
              EDU contents.
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

        # We need to ensure `updates` doesn't grow too big.
        # Currently: `len(updates) <= limit`.

        # Return an empty list if there are no updates
        if not updates:
            return now_stream_id, []

        if issue_8631_logger.isEnabledFor(logging.DEBUG):
            data = {(user, device): stream_id for user, device, stream_id, _ in updates}
            issue_8631_logger.debug(
                "device updates need to be sent to %s: %s", destination, data
            )

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

        # This is the stream ID that we will return for the consumer to resume
        # following this stream later.
        last_processed_stream_id = from_stream_id

        # A map of (user ID, device ID) to (stream ID, context).
        query_map: Dict[Tuple[str, str], Tuple[int, Optional[str]]] = {}
        cross_signing_keys_by_user: Dict[str, Dict[str, object]] = {}
        for user_id, device_id, update_stream_id, update_context in updates:
            # Calculate the remaining length budget.
            # Note that, for now, each entry in `cross_signing_keys_by_user`
            # gives rise to two device updates in the result, so those cost twice
            # as much (and are the whole reason we need to separately calculate
            # the budget; we know len(updates) <= limit otherwise!)
            # N.B. len() on dicts is cheap since they store their size.
            remaining_length_budget = limit - (
                len(query_map) + 2 * len(cross_signing_keys_by_user)
            )
            assert remaining_length_budget >= 0

            is_master_key_update = (
                user_id in master_key_by_user
                and device_id == master_key_by_user[user_id]["device_id"]
            )
            is_self_signing_key_update = (
                user_id in self_signing_key_by_user
                and device_id == self_signing_key_by_user[user_id]["device_id"]
            )

            is_cross_signing_key_update = (
                is_master_key_update or is_self_signing_key_update
            )

            if (
                is_cross_signing_key_update
                and user_id not in cross_signing_keys_by_user
            ):
                # This will give rise to 2 device updates.
                # If we don't have the budget, stop here!
                if remaining_length_budget < 2:
                    break

            if is_master_key_update:
                result = cross_signing_keys_by_user.setdefault(user_id, {})
                result["master_key"] = master_key_by_user[user_id]["key_info"]
            elif is_self_signing_key_update:
                result = cross_signing_keys_by_user.setdefault(user_id, {})
                result["self_signing_key"] = self_signing_key_by_user[user_id][
                    "key_info"
                ]
            else:
                key = (user_id, device_id)

                if key not in query_map and remaining_length_budget < 1:
                    # We don't have space for a new entry
                    break

                previous_update_stream_id, _ = query_map.get(key, (0, None))

                if update_stream_id > previous_update_stream_id:
                    # FIXME If this overwrites an older update, this discards the
                    #  previous OpenTracing context.
                    #  It might make it harder to track down issues using OpenTracing.
                    #  If there's a good reason why it doesn't matter, a comment here
                    #  about that would not hurt.
                    query_map[key] = (update_stream_id, update_context)

            # As this update has been added to the response, advance the stream
            # position.
            last_processed_stream_id = update_stream_id

        # In the worst case scenario, each update is for a distinct user and is
        # added either to the query_map or to cross_signing_keys_by_user,
        # but not both:
        # len(query_map) + len(cross_signing_keys_by_user) <= len(updates) here,
        # so len(query_map) + len(cross_signing_keys_by_user) <= limit.

        results = await self._get_device_update_edus_by_remote(
            destination, from_stream_id, query_map
        )

        # len(results) <= len(query_map) here,
        # so len(results) + len(cross_signing_keys_by_user) <= limit.

        # Add the updated cross-signing keys to the results list
        for user_id, result in cross_signing_keys_by_user.items():
            result["user_id"] = user_id
            results.append((EduTypes.SIGNING_KEY_UPDATE, result))
            # also send the unstable version
            # FIXME: remove this when enough servers have upgraded
            #        and remove the length budgeting above.
            results.append(("org.matrix.signing_key_update", result))

        if issue_8631_logger.isEnabledFor(logging.DEBUG):
            for (user_id, edu) in results:
                issue_8631_logger.debug(
                    "device update to %s for %s from %s to %s: %s",
                    destination,
                    user_id,
                    from_stream_id,
                    last_processed_stream_id,
                    edu,
                )

        return last_processed_stream_id, results

    def _get_device_updates_by_remote_txn(
        self,
        txn: LoggingTransaction,
        destination: str,
        from_stream_id: int,
        now_stream_id: int,
        limit: int,
    ) -> List[Tuple[str, str, int, Optional[str]]]:
        """Return device update information for a given remote destination

        Args:
            txn: The transaction to execute
            destination: The host the device updates are intended for
            from_stream_id: The minimum stream_id to filter updates by, exclusive
            now_stream_id: The maximum stream_id to filter updates by, inclusive
            limit: Maximum number of device updates to return

        Returns:
            List: List of device update tuples:
                - user_id
                - device_id
                - stream_id
                - opentracing_context
        """
        # get the list of device updates that need to be sent
        sql = """
            SELECT user_id, device_id, stream_id, opentracing_context FROM device_lists_outbound_pokes
            WHERE destination = ? AND ? < stream_id AND stream_id <= ?
            ORDER BY stream_id
            LIMIT ?
        """
        txn.execute(sql, (destination, from_stream_id, now_stream_id, limit))

        return cast(List[Tuple[str, str, int, Optional[str]]], txn.fetchall())

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
            query_map: Dictionary mapping (user_id, device_id) to
                (update stream_id, the relevant json-encoded opentracing context)

        Returns:
            List of objects representing a device update EDU.

        Postconditions:
            The returned list has a length not exceeding that of the query_map:
                len(result) <= len(query_map)
        """
        devices = (
            await self.get_e2e_device_keys_and_signatures(
                # Because these are (user_id, device_id) tuples with all
                # device_ids not being None, the returned list's length will not
                # exceed that of query_map.
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
                user_devices.keys(),
                key=lambda i: query_map[(user_id, i)][0],
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

                results.append((EduTypes.DEVICE_LIST_UPDATE, result))

        return results

    async def _get_last_device_update_for_remote_user(
        self, destination: str, user_id: str, from_stream_id: int
    ) -> int:
        def f(txn: LoggingTransaction) -> int:
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
        """Mark that updates have successfully been sent to the destination."""
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
            key_values=[(destination, user_id) for user_id, _ in rows],
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
            The new stream ID.
        """

        # TODO: this looks like it's _writing_. Should this be on DeviceStore rather
        #  than DeviceWorkerStore?
        async with self._device_list_id_gen.get_next() as stream_id:  # type: ignore[attr-defined]
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
    @cancellable
    async def get_user_devices_from_cache(
        self, query_list: List[Tuple[str, Optional[str]]]
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

        results: Dict[str, Dict[str, JsonDict]] = {}
        for user_id, device_id in query_list:
            if user_id not in user_ids_in_cache:
                continue

            if device_id:
                device = await self._get_cached_user_device(user_id, device_id)
                results.setdefault(user_id, {})[device_id] = device
            else:
                results[user_id] = await self.get_cached_devices_for_user(user_id)

        set_tag("in_cache", str(results))
        set_tag("not_in_cache", str(user_ids_not_in_cache))

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

    def get_cached_device_list_changes(
        self,
        from_key: int,
    ) -> Optional[List[str]]:
        """Get set of users whose devices have changed since `from_key`, or None
        if that information is not in our cache.
        """

        return self._device_list_stream_cache.get_all_entities_changed(from_key)

    @cancellable
    async def get_users_whose_devices_changed(
        self,
        from_key: int,
        user_ids: Optional[Collection[str]] = None,
        to_key: Optional[int] = None,
    ) -> Set[str]:
        """Get set of users whose devices have changed since `from_key` that
        are in the given list of user_ids.

        Args:
            from_key: The minimum device lists stream token to query device list changes for,
                exclusive.
            user_ids: If provided, only check if these users have changed their device lists.
                Otherwise changes from all users are returned.
            to_key: The maximum device lists stream token to query device list changes for,
                inclusive.

        Returns:
            The set of user_ids whose devices have changed since `from_key` (exclusive)
                until `to_key` (inclusive).
        """
        # Get set of users who *may* have changed. Users not in the returned
        # list have definitely not changed.
        user_ids_to_check: Optional[Collection[str]]
        if user_ids is None:
            # Get set of all users that have had device list changes since 'from_key'
            user_ids_to_check = self._device_list_stream_cache.get_all_entities_changed(
                from_key
            )
        else:
            # The same as above, but filter results to only those users in 'user_ids'
            user_ids_to_check = self._device_list_stream_cache.get_entities_changed(
                user_ids, from_key
            )

        if not user_ids_to_check:
            return set()

        def _get_users_whose_devices_changed_txn(txn: LoggingTransaction) -> Set[str]:
            changes: Set[str] = set()

            stream_id_where_clause = "stream_id > ?"
            sql_args = [from_key]

            if to_key:
                stream_id_where_clause += " AND stream_id <= ?"
                sql_args.append(to_key)

            sql = f"""
                SELECT DISTINCT user_id FROM device_lists_stream
                WHERE {stream_id_where_clause}
                AND
            """

            # Query device changes with a batch of users at a time
            # Assertion for mypy's benefit; see also
            # https://mypy.readthedocs.io/en/stable/common_issues.html#narrowing-and-inner-functions
            assert user_ids_to_check is not None
            for chunk in batch_iter(user_ids_to_check, 100):
                clause, args = make_in_list_sql_clause(
                    txn.database_engine, "user_id", chunk
                )
                txn.execute(sql + clause, sql_args + args)
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

        def _get_all_device_list_changes_for_remotes(
            txn: Cursor,
        ) -> Tuple[List[Tuple[int, tuple]], int, bool]:
            # This query Does The Right Thing where it'll correctly apply the
            # bounds to the inner queries.
            sql = """
                SELECT stream_id, entity FROM (
                    SELECT stream_id, user_id AS entity FROM device_lists_stream
                    UNION ALL
                    SELECT stream_id, destination AS entity FROM device_lists_outbound_pokes
                ) AS e
                WHERE ? < stream_id AND stream_id <= ?
                ORDER BY stream_id ASC
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
    ) -> Optional[str]:
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
    async def get_device_list_last_stream_id_for_remotes(
        self, user_ids: Iterable[str]
    ) -> Dict[str, Optional[str]]:
        rows = await self.db_pool.simple_select_many_batch(
            table="device_lists_remote_extremeties",
            column="user_id",
            iterable=user_ids,
            retcols=("user_id", "stream_id"),
            desc="get_device_list_last_stream_id_for_remotes",
        )

        results: Dict[str, Optional[str]] = {user_id: None for user_id in user_ids}
        results.update({row["user_id"]: row["stream_id"] for row in rows})

        return results

    async def get_user_ids_requiring_device_list_resync(
        self,
        user_ids: Optional[Collection[str]] = None,
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
            desc="mark_remote_user_device_cache_as_stale",
        )

    async def mark_remote_user_device_cache_as_valid(self, user_id: str) -> None:
        # Remove the database entry that says we need to resync devices, after a resync
        await self.db_pool.simple_delete(
            table="device_lists_remote_resync",
            keyvalues={"user_id": user_id},
            desc="mark_remote_user_device_cache_as_valid",
        )

    async def handle_potentially_left_users(self, user_ids: Set[str]) -> None:
        """Given a set of remote users check if the server still shares a room with
        them. If not then mark those users' device cache as stale.
        """

        if not user_ids:
            return

        await self.db_pool.runInteraction(
            "_handle_potentially_left_users",
            self.handle_potentially_left_users_txn,
            user_ids,
        )

    def handle_potentially_left_users_txn(
        self,
        txn: LoggingTransaction,
        user_ids: Set[str],
    ) -> None:
        """Given a set of remote users check if the server still shares a room with
        them. If not then mark those users' device cache as stale.
        """

        if not user_ids:
            return

        joined_users = self.get_users_server_still_shares_room_with_txn(txn, user_ids)
        left_users = user_ids - joined_users

        for user_id in left_users:
            self.mark_remote_user_device_list_as_unsubscribed_txn(txn, user_id)

    async def mark_remote_user_device_list_as_unsubscribed(self, user_id: str) -> None:
        """Mark that we no longer track device lists for remote user."""

        await self.db_pool.runInteraction(
            "mark_remote_user_device_list_as_unsubscribed",
            self.mark_remote_user_device_list_as_unsubscribed_txn,
            user_id,
        )

    def mark_remote_user_device_list_as_unsubscribed_txn(
        self,
        txn: LoggingTransaction,
        user_id: str,
    ) -> None:
        self.db_pool.simple_delete_txn(
            txn,
            table="device_lists_remote_extremeties",
            keyvalues={"user_id": user_id},
        )
        self._invalidate_cache_and_stream(
            txn, self.get_device_list_last_stream_id_for_remote, (user_id,)
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
        self, txn: LoggingTransaction, user_id: str, device_id: str, device_data: str
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

        def _prune_txn(txn: LoggingTransaction) -> None:
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
            txn.execute_batch(sql, ((row[0], row[1]) for row in rows))

            logger.info("Pruned %d device list outbound pokes", count)

        await self.db_pool.runInteraction(
            "_prune_old_outbound_device_pokes",
            _prune_txn,
        )

    async def get_local_devices_not_accessed_since(
        self, since_ms: int
    ) -> Dict[str, List[str]]:
        """Retrieves local devices that haven't been accessed since a given date.

        Args:
            since_ms: the timestamp to select on, every device with a last access date
                from before that time is returned.

        Returns:
            A dictionary with an entry for each user with at least one device matching
            the request, which value is a list of the device ID(s) for the corresponding
            device(s).
        """

        def get_devices_not_accessed_since_txn(
            txn: LoggingTransaction,
        ) -> List[Dict[str, str]]:
            sql = """
                SELECT user_id, device_id
                FROM devices WHERE last_seen < ? AND hidden = FALSE
            """
            txn.execute(sql, (since_ms,))
            return self.db_pool.cursor_to_dict(txn)

        rows = await self.db_pool.runInteraction(
            "get_devices_not_accessed_since",
            get_devices_not_accessed_since_txn,
        )

        devices: Dict[str, List[str]] = {}
        for row in rows:
            # Remote devices are never stale from our point of view.
            if self.hs.is_mine_id(row["user_id"]):
                user_devices = devices.setdefault(row["user_id"], [])
                user_devices.append(row["device_id"])

        return devices

    @cached()
    async def _get_min_device_lists_changes_in_room(self) -> int:
        """Returns the minimum stream ID that we have entries for
        `device_lists_changes_in_room`
        """

        return await self.db_pool.simple_select_one_onecol(
            table="device_lists_changes_in_room",
            keyvalues={},
            retcol="COALESCE(MIN(stream_id), 0)",
            desc="get_min_device_lists_changes_in_room",
        )

    @cancellable
    async def get_device_list_changes_in_rooms(
        self, room_ids: Collection[str], from_id: int
    ) -> Optional[Set[str]]:
        """Return the set of users whose devices have changed in the given rooms
        since the given stream ID.

        Returns None if the given stream ID is too old.
        """

        if not room_ids:
            return set()

        min_stream_id = await self._get_min_device_lists_changes_in_room()

        if min_stream_id > from_id:
            return None

        sql = """
            SELECT DISTINCT user_id FROM device_lists_changes_in_room
            WHERE {clause} AND stream_id >= ?
        """

        def _get_device_list_changes_in_rooms_txn(
            txn: LoggingTransaction,
            clause: str,
            args: List[Any],
        ) -> Set[str]:
            txn.execute(sql.format(clause=clause), args)
            return {user_id for user_id, in txn}

        changes = set()
        for chunk in batch_iter(room_ids, 1000):
            clause, args = make_in_list_sql_clause(
                self.database_engine, "room_id", chunk
            )
            args.append(from_id)

            changes |= await self.db_pool.runInteraction(
                "get_device_list_changes_in_rooms",
                _get_device_list_changes_in_rooms_txn,
                clause,
                args,
            )

        return changes

    async def get_device_list_changes_in_room(
        self, room_id: str, min_stream_id: int
    ) -> Collection[Tuple[str, str]]:
        """Get all device list changes that happened in the room since the given
        stream ID.

        Returns:
            Collection of user ID/device ID tuples of all devices that have
            changed
        """

        sql = """
            SELECT DISTINCT user_id, device_id FROM device_lists_changes_in_room
            WHERE room_id = ? AND stream_id > ?
        """

        def get_device_list_changes_in_room_txn(
            txn: LoggingTransaction,
        ) -> Collection[Tuple[str, str]]:
            txn.execute(sql, (room_id, min_stream_id))
            return cast(Collection[Tuple[str, str]], txn.fetchall())

        return await self.db_pool.runInteraction(
            "get_device_list_changes_in_room",
            get_device_list_changes_in_room_txn,
        )


class DeviceBackgroundUpdateStore(SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
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
            BG_UPDATE_REMOVE_DUP_OUTBOUND_POKES,
            self._remove_duplicate_outbound_pokes,
        )

    async def _drop_device_list_streams_non_unique_indexes(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        def f(conn: LoggingDatabaseConnection) -> None:
            txn = conn.cursor()
            txn.execute("DROP INDEX IF EXISTS device_lists_remote_cache_id")
            txn.execute("DROP INDEX IF EXISTS device_lists_remote_extremeties_id")
            txn.close()

        await self.db_pool.runWithConnection(f)
        await self.db_pool.updates._end_background_update(
            DROP_DEVICE_LIST_STREAMS_NON_UNIQUE_INDEXES
        )
        return 1

    async def _remove_duplicate_outbound_pokes(
        self, progress: JsonDict, batch_size: int
    ) -> int:
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

        def _txn(txn: LoggingTransaction) -> int:
            clause, args = make_tuple_comparison_clause(
                [(x, last_row[x]) for x in KEY_COLS]
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
                    txn,
                    "device_lists_outbound_pokes",
                    {x: row[x] for x in KEY_COLS},
                )

                row["sent"] = False
                self.db_pool.simple_insert_txn(
                    txn,
                    "device_lists_outbound_pokes",
                    row,
                )

            if row:
                self.db_pool.updates._background_update_progress_txn(
                    txn,
                    BG_UPDATE_REMOVE_DUP_OUTBOUND_POKES,
                    {"last_row": row},
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
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        # Map of (user_id, device_id) -> bool. If there is an entry that implies
        # the device exists.
        self.device_id_exists_cache: LruCache[
            Tuple[str, str], Literal[True]
        ] = LruCache(cache_name="device_id_exists", max_size=10000)

    async def store_device(
        self,
        user_id: str,
        device_id: str,
        initial_device_display_name: Optional[str],
        auth_provider_id: Optional[str] = None,
        auth_provider_session_id: Optional[str] = None,
    ) -> bool:
        """Ensure the given device is known; add it to the store if not

        Args:
            user_id: id of user associated with the device
            device_id: id of device
            initial_device_display_name: initial displayname of the device.
                Ignored if device exists.
            auth_provider_id: The SSO IdP the user used, if any.
            auth_provider_session_id: The session ID (sid) got from a OIDC login.

        Returns:
            Whether the device was inserted or an existing device existed with that ID.

        Raises:
            StoreError: if the device is already in use
        """
        key = (user_id, device_id)
        if self.device_id_exists_cache.get(key, None):
            return False

        try:
            inserted = await self.db_pool.simple_upsert(
                "devices",
                keyvalues={
                    "user_id": user_id,
                    "device_id": device_id,
                },
                values={},
                insertion_values={
                    "display_name": initial_device_display_name,
                    "hidden": False,
                },
                desc="store_device",
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

            if auth_provider_id and auth_provider_session_id:
                await self.db_pool.simple_insert(
                    "device_auth_providers",
                    values={
                        "user_id": user_id,
                        "device_id": device_id,
                        "auth_provider_id": auth_provider_id,
                        "auth_provider_session_id": auth_provider_session_id,
                    },
                    desc="store_device_auth_provider",
                )

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

    async def delete_devices(self, user_id: str, device_ids: List[str]) -> None:
        """Deletes several devices.

        Args:
            user_id: The ID of the user which owns the devices
            device_ids: The IDs of the devices to delete
        """

        def _delete_devices_txn(txn: LoggingTransaction) -> None:
            self.db_pool.simple_delete_many_txn(
                txn,
                table="devices",
                column="device_id",
                values=device_ids,
                keyvalues={"user_id": user_id, "hidden": False},
            )

            self.db_pool.simple_delete_many_txn(
                txn,
                table="device_inbox",
                column="device_id",
                values=device_ids,
                keyvalues={"user_id": user_id},
            )

            self.db_pool.simple_delete_many_txn(
                txn,
                table="device_auth_providers",
                column="device_id",
                values=device_ids,
                keyvalues={"user_id": user_id},
            )

        await self.db_pool.runInteraction("delete_devices", _delete_devices_txn)
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
        """Delete, update or insert a cache entry for this (user, device) pair."""
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
        """Replace the list of cached devices for this user with the given list."""
        self.db_pool.simple_delete_txn(
            txn, table="device_lists_remote_cache", keyvalues={"user_id": user_id}
        )

        self.db_pool.simple_insert_many_txn(
            txn,
            table="device_lists_remote_cache",
            keys=("user_id", "device_id", "content"),
            values=[
                (user_id, content["device_id"], json_encoder.encode(content))
                for content in devices
            ],
        )

        txn.call_after(self.get_cached_devices_for_user.invalidate, (user_id,))
        txn.call_after(self._get_cached_user_device.invalidate, (user_id,))
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

    async def add_device_change_to_streams(
        self,
        user_id: str,
        device_ids: Collection[str],
        room_ids: Collection[str],
    ) -> Optional[int]:
        """Persist that a user's devices have been updated, and which hosts
        (if any) should be poked.

        Args:
            user_id: The ID of the user whose device changed.
            device_ids: The IDs of any changed devices. If empty, this function will
                return None.
            room_ids: The rooms that the user is in

        Returns:
            The maximum stream ID of device list updates that were added to the database, or
            None if no updates were added.
        """
        if not device_ids:
            return None

        context = get_active_span_text_map()

        def add_device_changes_txn(
            txn: LoggingTransaction, stream_ids: List[int]
        ) -> None:
            self._add_device_change_to_stream_txn(
                txn,
                user_id,
                device_ids,
                stream_ids,
            )

            self._add_device_outbound_room_poke_txn(
                txn,
                user_id,
                device_ids,
                room_ids,
                stream_ids,
                context,
            )

        async with self._device_list_id_gen.get_next_mult(  # type: ignore[attr-defined]
            len(device_ids)
        ) as stream_ids:
            await self.db_pool.runInteraction(
                "add_device_change_to_stream",
                add_device_changes_txn,
                stream_ids,
            )

        return stream_ids[-1]

    def _add_device_change_to_stream_txn(
        self,
        txn: LoggingTransaction,
        user_id: str,
        device_ids: Collection[str],
        stream_ids: List[int],
    ) -> None:
        txn.call_after(
            self._device_list_stream_cache.entity_has_changed,
            user_id,
            stream_ids[-1],
        )

        min_stream_id = stream_ids[0]

        # Delete older entries in the table, as we really only care about
        # when the latest change happened.
        txn.execute_batch(
            """
            DELETE FROM device_lists_stream
            WHERE user_id = ? AND device_id = ? AND stream_id < ?
            """,
            [(user_id, device_id, min_stream_id) for device_id in device_ids],
        )

        self.db_pool.simple_insert_many_txn(
            txn,
            table="device_lists_stream",
            keys=("stream_id", "user_id", "device_id"),
            values=[
                (stream_id, user_id, device_id)
                for stream_id, device_id in zip(stream_ids, device_ids)
            ],
        )

    def _add_device_outbound_poke_to_stream_txn(
        self,
        txn: LoggingTransaction,
        user_id: str,
        device_ids: Iterable[str],
        hosts: Collection[str],
        stream_ids: List[int],
        context: Optional[Dict[str, str]],
    ) -> None:
        for host in hosts:
            txn.call_after(
                self._device_list_federation_stream_cache.entity_has_changed,
                host,
                stream_ids[-1],
            )

        now = self._clock.time_msec()
        stream_id_iterator = iter(stream_ids)

        encoded_context = json_encoder.encode(context)
        self.db_pool.simple_insert_many_txn(
            txn,
            table="device_lists_outbound_pokes",
            keys=(
                "destination",
                "stream_id",
                "user_id",
                "device_id",
                "sent",
                "ts",
                "opentracing_context",
            ),
            values=[
                (
                    destination,
                    next(stream_id_iterator),
                    user_id,
                    device_id,
                    not self.hs.is_mine_id(
                        user_id
                    ),  # We only need to send out update for *our* users
                    now,
                    encoded_context if whitelisted_homeserver(destination) else "{}",
                )
                for destination in hosts
                for device_id in device_ids
            ],
        )

    def _add_device_outbound_room_poke_txn(
        self,
        txn: LoggingTransaction,
        user_id: str,
        device_ids: Iterable[str],
        room_ids: Collection[str],
        stream_ids: List[int],
        context: Dict[str, str],
    ) -> None:
        """Record the user in the room has updated their device."""

        encoded_context = json_encoder.encode(context)

        # The `device_lists_changes_in_room.stream_id` column matches the
        # corresponding `stream_id` of the update in the `device_lists_stream`
        # table, i.e. all rows persisted for the same device update will have
        # the same `stream_id` (but different room IDs).
        self.db_pool.simple_insert_many_txn(
            txn,
            table="device_lists_changes_in_room",
            keys=(
                "user_id",
                "device_id",
                "room_id",
                "stream_id",
                "converted_to_destinations",
                "opentracing_context",
            ),
            values=[
                (
                    user_id,
                    device_id,
                    room_id,
                    stream_id,
                    # We only need to calculate outbound pokes for local users
                    not self.hs.is_mine_id(user_id),
                    encoded_context,
                )
                for room_id in room_ids
                for device_id, stream_id in zip(device_ids, stream_ids)
            ],
        )

    async def get_uncoverted_outbound_room_pokes(
        self, limit: int = 10
    ) -> List[Tuple[str, str, str, int, Optional[Dict[str, str]]]]:
        """Get device list changes by room that have not yet been handled and
        written to `device_lists_outbound_pokes`.

        Returns:
            A list of user ID, device ID, room ID, stream ID and optional opentracing context.
        """

        sql = """
            SELECT user_id, device_id, room_id, stream_id, opentracing_context
            FROM device_lists_changes_in_room
            WHERE NOT converted_to_destinations
            ORDER BY stream_id
            LIMIT ?
        """

        def get_uncoverted_outbound_room_pokes_txn(
            txn: LoggingTransaction,
        ) -> List[Tuple[str, str, str, int, Optional[Dict[str, str]]]]:
            txn.execute(sql, (limit,))

            return [
                (
                    user_id,
                    device_id,
                    room_id,
                    stream_id,
                    db_to_json(opentracing_context),
                )
                for user_id, device_id, room_id, stream_id, opentracing_context in txn
            ]

        return await self.db_pool.runInteraction(
            "get_uncoverted_outbound_room_pokes", get_uncoverted_outbound_room_pokes_txn
        )

    async def add_device_list_outbound_pokes(
        self,
        user_id: str,
        device_id: str,
        room_id: str,
        stream_id: Optional[int],
        hosts: Collection[str],
        context: Optional[Dict[str, str]],
    ) -> None:
        """Queue the device update to be sent to the given set of hosts,
        calculated from the room ID.

        Marks the associated row in `device_lists_changes_in_room` as handled,
        if `stream_id` is provided.
        """

        def add_device_list_outbound_pokes_txn(
            txn: LoggingTransaction, stream_ids: List[int]
        ) -> None:
            if hosts:
                self._add_device_outbound_poke_to_stream_txn(
                    txn,
                    user_id=user_id,
                    device_ids=[device_id],
                    hosts=hosts,
                    stream_ids=stream_ids,
                    context=context,
                )

            if stream_id:
                self.db_pool.simple_update_txn(
                    txn,
                    table="device_lists_changes_in_room",
                    keyvalues={
                        "user_id": user_id,
                        "device_id": device_id,
                        "stream_id": stream_id,
                        "room_id": room_id,
                    },
                    updatevalues={"converted_to_destinations": True},
                )

        if not hosts:
            # If there are no hosts then we don't try and generate stream IDs.
            return await self.db_pool.runInteraction(
                "add_device_list_outbound_pokes",
                add_device_list_outbound_pokes_txn,
                [],
            )

        async with self._device_list_id_gen.get_next_mult(len(hosts)) as stream_ids:  # type: ignore[attr-defined]
            return await self.db_pool.runInteraction(
                "add_device_list_outbound_pokes",
                add_device_list_outbound_pokes_txn,
                stream_ids,
            )

    async def add_remote_device_list_to_pending(
        self, user_id: str, device_id: str
    ) -> None:
        """Add a device list update to the table tracking remote device list
        updates during partial joins.
        """

        async with self._device_list_id_gen.get_next() as stream_id:  # type: ignore[attr-defined]
            await self.db_pool.simple_upsert(
                table="device_lists_remote_pending",
                keyvalues={
                    "user_id": user_id,
                    "device_id": device_id,
                },
                values={"stream_id": stream_id},
                desc="add_remote_device_list_to_pending",
            )

    async def get_pending_remote_device_list_updates_for_room(
        self, room_id: str
    ) -> Collection[Tuple[str, str]]:
        """Get the set of remote device list updates from the pending table for
        the room.
        """

        min_device_stream_id = await self.db_pool.simple_select_one_onecol(
            table="partial_state_rooms",
            keyvalues={
                "room_id": room_id,
            },
            retcol="device_lists_stream_id",
            desc="get_pending_remote_device_list_updates_for_room_device",
        )

        sql = """
            SELECT user_id, device_id FROM device_lists_remote_pending AS d
            INNER JOIN current_state_events AS c ON
                type = 'm.room.member'
                AND state_key = user_id
                AND membership = 'join'
            WHERE
                room_id = ? AND stream_id > ?
        """

        def get_pending_remote_device_list_updates_for_room_txn(
            txn: LoggingTransaction,
        ) -> Collection[Tuple[str, str]]:
            txn.execute(sql, (room_id, min_device_stream_id))
            return cast(Collection[Tuple[str, str]], txn.fetchall())

        return await self.db_pool.runInteraction(
            "get_pending_remote_device_list_updates_for_room",
            get_pending_remote_device_list_updates_for_room_txn,
        )
