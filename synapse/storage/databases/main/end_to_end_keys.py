# Copyright 2015, 2016 OpenMarket Ltd
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
from typing import (
    TYPE_CHECKING,
    Collection,
    Dict,
    Iterable,
    List,
    Optional,
    Tuple,
    Union,
    cast,
    overload,
)

import attr
from canonicaljson import encode_canonical_json
from typing_extensions import Literal

from synapse.api.constants import DeviceKeyAlgorithms
from synapse.appservice import (
    TransactionOneTimeKeyCounts,
    TransactionUnusedFallbackKeys,
)
from synapse.logging.opentracing import log_kv, set_tag, trace
from synapse.storage._base import SQLBaseStore, db_to_json
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
    make_in_list_sql_clause,
    make_tuple_in_list_sql_clause,
)
from synapse.storage.databases.main.cache import CacheInvalidationWorkerStore
from synapse.storage.engines import PostgresEngine
from synapse.storage.util.id_generators import StreamIdGenerator
from synapse.types import JsonDict
from synapse.util import json_encoder
from synapse.util.caches.descriptors import cached, cachedList
from synapse.util.cancellation import cancellable
from synapse.util.iterutils import batch_iter

if TYPE_CHECKING:
    from synapse.handlers.e2e_keys import SignatureListItem
    from synapse.server import HomeServer


@attr.s(slots=True, auto_attribs=True)
class DeviceKeyLookupResult:
    """The type returned by get_e2e_device_keys_and_signatures"""

    display_name: Optional[str]

    # the key data from e2e_device_keys_json. Typically includes fields like
    # "algorithm", "keys" (including the curve25519 identity key and the ed25519 signing
    # key) and "signatures" (a map from (user id) to (key id/device_id) to signature.)
    keys: Optional[JsonDict]


class EndToEndKeyBackgroundStore(SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        self.db_pool.updates.register_background_index_update(
            "e2e_cross_signing_keys_idx",
            index_name="e2e_cross_signing_keys_stream_idx",
            table="e2e_cross_signing_keys",
            columns=["stream_id"],
            unique=True,
        )


class EndToEndKeyWorkerStore(EndToEndKeyBackgroundStore, CacheInvalidationWorkerStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        self._allow_device_name_lookup_over_federation = (
            self.hs.config.federation.allow_device_name_lookup_over_federation
        )

    async def get_e2e_device_keys_for_federation_query(
        self, user_id: str
    ) -> Tuple[int, List[JsonDict]]:
        """Get all devices (with any device keys) for a user

        Returns:
            (stream_id, devices)
        """
        now_stream_id = self.get_device_stream_token()

        devices = await self.get_e2e_device_keys_and_signatures([(user_id, None)])

        if devices:
            user_devices = devices[user_id]
            results = []
            for device_id, device in user_devices.items():
                result: JsonDict = {"device_id": device_id}

                keys = device.keys
                if keys:
                    result["keys"] = keys

                device_display_name = None
                if self._allow_device_name_lookup_over_federation:
                    device_display_name = device.display_name
                if device_display_name:
                    result["device_display_name"] = device_display_name

                results.append(result)

            return now_stream_id, results

        return now_stream_id, []

    @trace
    @cancellable
    async def get_e2e_device_keys_for_cs_api(
        self, query_list: List[Tuple[str, Optional[str]]]
    ) -> Dict[str, Dict[str, JsonDict]]:
        """Fetch a list of device keys, formatted suitably for the C/S API.
        Args:
            query_list(list): List of pairs of user_ids and device_ids.
        Returns:
            Dict mapping from user-id to dict mapping from device_id to
            key data.  The key data will be a dict in the same format as the
            DeviceKeys type returned by POST /_matrix/client/r0/keys/query.
        """
        set_tag("query_list", str(query_list))
        if not query_list:
            return {}

        results = await self.get_e2e_device_keys_and_signatures(query_list)

        # Build the result structure, un-jsonify the results, and add the
        # "unsigned" section
        rv: Dict[str, Dict[str, JsonDict]] = {}
        for user_id, device_keys in results.items():
            rv[user_id] = {}
            for device_id, device_info in device_keys.items():
                r = device_info.keys
                if r is None:
                    continue

                r["unsigned"] = {}
                display_name = device_info.display_name
                if display_name is not None:
                    r["unsigned"]["device_display_name"] = display_name
                rv[user_id][device_id] = r

        return rv

    @overload
    async def get_e2e_device_keys_and_signatures(
        self,
        query_list: Collection[Tuple[str, Optional[str]]],
        include_all_devices: Literal[False] = False,
    ) -> Dict[str, Dict[str, DeviceKeyLookupResult]]:
        ...

    @overload
    async def get_e2e_device_keys_and_signatures(
        self,
        query_list: Collection[Tuple[str, Optional[str]]],
        include_all_devices: bool = False,
        include_deleted_devices: Literal[False] = False,
    ) -> Dict[str, Dict[str, DeviceKeyLookupResult]]:
        ...

    @overload
    async def get_e2e_device_keys_and_signatures(
        self,
        query_list: Collection[Tuple[str, Optional[str]]],
        include_all_devices: Literal[True],
        include_deleted_devices: Literal[True],
    ) -> Dict[str, Dict[str, Optional[DeviceKeyLookupResult]]]:
        ...

    @trace
    @cancellable
    async def get_e2e_device_keys_and_signatures(
        self,
        query_list: Collection[Tuple[str, Optional[str]]],
        include_all_devices: bool = False,
        include_deleted_devices: bool = False,
    ) -> Union[
        Dict[str, Dict[str, DeviceKeyLookupResult]],
        Dict[str, Dict[str, Optional[DeviceKeyLookupResult]]],
    ]:
        """Fetch a list of device keys

        Any cross-signatures made on the keys by the owner of the device are also
        included.

        The cross-signatures are added to the `signatures` field within the `keys`
        object in the response.

        Args:
            query_list: List of pairs of user_ids and device_ids. Device id can be None
                to indicate "all devices for this user"

            include_all_devices: whether to return devices without device keys

            include_deleted_devices: whether to include null entries for
                devices which no longer exist (but were in the query_list).
                This option only takes effect if include_all_devices is true.

        Returns:
            Dict mapping from user-id to dict mapping from device_id to
            key data.
        """
        set_tag("include_all_devices", include_all_devices)
        set_tag("include_deleted_devices", include_deleted_devices)

        result = await self.db_pool.runInteraction(
            "get_e2e_device_keys",
            self._get_e2e_device_keys_txn,
            query_list,
            include_all_devices,
            include_deleted_devices,
        )

        # get the (user_id, device_id) tuples to look up cross-signatures for
        signature_query = (
            (user_id, device_id)
            for user_id, dev in result.items()
            for device_id, d in dev.items()
            if d is not None and d.keys is not None
        )

        for batch in batch_iter(signature_query, 50):
            cross_sigs_result = await self.db_pool.runInteraction(
                "get_e2e_cross_signing_signatures",
                self._get_e2e_cross_signing_signatures_for_devices_txn,
                batch,
            )

            # add each cross-signing signature to the correct device in the result dict.
            for (user_id, key_id, device_id, signature) in cross_sigs_result:
                target_device_result = result[user_id][device_id]
                # We've only looked up cross-signatures for non-deleted devices with key
                # data.
                assert target_device_result is not None
                assert target_device_result.keys is not None
                target_device_signatures = target_device_result.keys.setdefault(
                    "signatures", {}
                )
                signing_user_signatures = target_device_signatures.setdefault(
                    user_id, {}
                )
                signing_user_signatures[key_id] = signature

        log_kv(result)
        return result

    def _get_e2e_device_keys_txn(
        self,
        txn: LoggingTransaction,
        query_list: Collection[Tuple[str, Optional[str]]],
        include_all_devices: bool = False,
        include_deleted_devices: bool = False,
    ) -> Dict[str, Dict[str, Optional[DeviceKeyLookupResult]]]:
        """Get information on devices from the database

        The results include the device's keys and self-signatures, but *not* any
        cross-signing signatures which have been added subsequently (for which, see
        get_e2e_device_keys_and_signatures)
        """
        query_clauses: List[str] = []
        query_params_list: List[List[object]] = []

        if include_all_devices is False:
            include_deleted_devices = False

        if include_deleted_devices:
            deleted_devices = set(query_list)

        # Split the query list into queries for users and queries for particular
        # devices.
        user_list = []
        user_device_list = []
        for (user_id, device_id) in query_list:
            if device_id is None:
                user_list.append(user_id)
            else:
                user_device_list.append((user_id, device_id))

        if user_list:
            user_id_in_list_clause, user_args = make_in_list_sql_clause(
                txn.database_engine, "user_id", user_list
            )
            query_clauses.append(user_id_in_list_clause)
            query_params_list.append(user_args)

        if user_device_list:
            # Divide the device queries into batches, to avoid excessively large
            # queries.
            for user_device_batch in batch_iter(user_device_list, 1024):
                (
                    user_device_id_in_list_clause,
                    user_device_args,
                ) = make_tuple_in_list_sql_clause(
                    txn.database_engine, ("user_id", "device_id"), user_device_batch
                )
                query_clauses.append(user_device_id_in_list_clause)
                query_params_list.append(user_device_args)

        result: Dict[str, Dict[str, Optional[DeviceKeyLookupResult]]] = {}
        for query_clause, query_params in zip(query_clauses, query_params_list):
            sql = (
                "SELECT user_id, device_id, "
                "    d.display_name, "
                "    k.key_json"
                " FROM devices d"
                "    %s JOIN e2e_device_keys_json k USING (user_id, device_id)"
                " WHERE %s AND NOT d.hidden"
            ) % (
                "LEFT" if include_all_devices else "INNER",
                query_clause,
            )

            txn.execute(sql, query_params)

            for (user_id, device_id, display_name, key_json) in txn:
                assert device_id is not None
                if include_deleted_devices:
                    deleted_devices.remove((user_id, device_id))
                result.setdefault(user_id, {})[device_id] = DeviceKeyLookupResult(
                    display_name, db_to_json(key_json) if key_json else None
                )

        if include_deleted_devices:
            for user_id, device_id in deleted_devices:
                if device_id is None:
                    continue
                result.setdefault(user_id, {})[device_id] = None

        return result

    def _get_e2e_cross_signing_signatures_for_devices_txn(
        self, txn: LoggingTransaction, device_query: Iterable[Tuple[str, str]]
    ) -> List[Tuple[str, str, str, str]]:
        """Get cross-signing signatures for a given list of devices

        Returns signatures made by the owners of the devices.

        Returns: a list of results; each entry in the list is a tuple of
            (user_id, key_id, target_device_id, signature).
        """
        signature_query_clauses = []
        signature_query_params = []

        for (user_id, device_id) in device_query:
            signature_query_clauses.append(
                "target_user_id = ? AND target_device_id = ? AND user_id = ?"
            )
            signature_query_params.extend([user_id, device_id, user_id])

        signature_sql = """
            SELECT user_id, key_id, target_device_id, signature
            FROM e2e_cross_signing_signatures WHERE %s
            """ % (
            " OR ".join("(" + q + ")" for q in signature_query_clauses)
        )

        txn.execute(signature_sql, signature_query_params)
        return cast(
            List[
                Tuple[
                    str,
                    str,
                    str,
                    str,
                ]
            ],
            txn.fetchall(),
        )

    async def get_e2e_one_time_keys(
        self, user_id: str, device_id: str, key_ids: List[str]
    ) -> Dict[Tuple[str, str], str]:
        """Retrieve a number of one-time keys for a user

        Args:
            user_id(str): id of user to get keys for
            device_id(str): id of device to get keys for
            key_ids(list[str]): list of key ids (excluding algorithm) to
                retrieve

        Returns:
            A map from (algorithm, key_id) to json string for key
        """

        rows = await self.db_pool.simple_select_many_batch(
            table="e2e_one_time_keys_json",
            column="key_id",
            iterable=key_ids,
            retcols=("algorithm", "key_id", "key_json"),
            keyvalues={"user_id": user_id, "device_id": device_id},
            desc="add_e2e_one_time_keys_check",
        )
        result = {(row["algorithm"], row["key_id"]): row["key_json"] for row in rows}
        log_kv({"message": "Fetched one time keys for user", "one_time_keys": result})
        return result

    async def add_e2e_one_time_keys(
        self,
        user_id: str,
        device_id: str,
        time_now: int,
        new_keys: Iterable[Tuple[str, str, str]],
    ) -> None:
        """Insert some new one time keys for a device. Errors if any of the
        keys already exist.

        Args:
            user_id: id of user to get keys for
            device_id: id of device to get keys for
            time_now: insertion time to record (ms since epoch)
            new_keys: keys to add - each a tuple of (algorithm, key_id, key json)
        """

        def _add_e2e_one_time_keys(txn: LoggingTransaction) -> None:
            set_tag("user_id", user_id)
            set_tag("device_id", device_id)
            set_tag("new_keys", str(new_keys))
            # We are protected from race between lookup and insertion due to
            # a unique constraint. If there is a race of two calls to
            # `add_e2e_one_time_keys` then they'll conflict and we will only
            # insert one set.
            self.db_pool.simple_insert_many_txn(
                txn,
                table="e2e_one_time_keys_json",
                keys=(
                    "user_id",
                    "device_id",
                    "algorithm",
                    "key_id",
                    "ts_added_ms",
                    "key_json",
                ),
                values=[
                    (user_id, device_id, algorithm, key_id, time_now, json_bytes)
                    for algorithm, key_id, json_bytes in new_keys
                ],
            )
            self._invalidate_cache_and_stream(
                txn, self.count_e2e_one_time_keys, (user_id, device_id)
            )

        await self.db_pool.runInteraction(
            "add_e2e_one_time_keys_insert", _add_e2e_one_time_keys
        )

    @cached(max_entries=10000)
    async def count_e2e_one_time_keys(
        self, user_id: str, device_id: str
    ) -> Dict[str, int]:
        """Count the number of one time keys the server has for a device
        Returns:
            A mapping from algorithm to number of keys for that algorithm.
        """

        def _count_e2e_one_time_keys(txn: LoggingTransaction) -> Dict[str, int]:
            sql = (
                "SELECT algorithm, COUNT(key_id) FROM e2e_one_time_keys_json"
                " WHERE user_id = ? AND device_id = ?"
                " GROUP BY algorithm"
            )
            txn.execute(sql, (user_id, device_id))

            # Initially set the key count to 0. This ensures that the client will always
            # receive *some count*, even if it's 0.
            result = {DeviceKeyAlgorithms.SIGNED_CURVE25519: 0}

            # Override entries with the count of any keys we pulled from the database
            for algorithm, key_count in txn:
                result[algorithm] = key_count

            return result

        return await self.db_pool.runInteraction(
            "count_e2e_one_time_keys", _count_e2e_one_time_keys
        )

    async def count_bulk_e2e_one_time_keys_for_as(
        self, user_ids: Collection[str]
    ) -> TransactionOneTimeKeyCounts:
        """
        Counts, in bulk, the one-time keys for all the users specified.
        Intended to be used by application services for populating OTK counts in
        transactions.

        Return structure is of the shape:
          user_id -> device_id -> algorithm -> count
          Empty algorithm -> count dicts are created if needed to represent a
          lack of unused one-time keys.
        """

        def _count_bulk_e2e_one_time_keys_txn(
            txn: LoggingTransaction,
        ) -> TransactionOneTimeKeyCounts:
            user_in_where_clause, user_parameters = make_in_list_sql_clause(
                self.database_engine, "user_id", user_ids
            )
            sql = f"""
                SELECT user_id, device_id, algorithm, COUNT(key_id)
                FROM devices
                LEFT JOIN e2e_one_time_keys_json USING (user_id, device_id)
                WHERE {user_in_where_clause}
                GROUP BY user_id, device_id, algorithm
            """
            txn.execute(sql, user_parameters)

            result: TransactionOneTimeKeyCounts = {}

            for user_id, device_id, algorithm, count in txn:
                # We deliberately construct empty dictionaries for
                # users and devices without any unused one-time keys.
                # We *could* omit these empty dicts if there have been no
                # changes since the last transaction, but we currently don't
                # do any change tracking!
                device_count_by_algo = result.setdefault(user_id, {}).setdefault(
                    device_id, {}
                )
                if algorithm is not None:
                    # algorithm will be None if this device has no keys.
                    device_count_by_algo[algorithm] = count

            return result

        return await self.db_pool.runInteraction(
            "count_bulk_e2e_one_time_keys", _count_bulk_e2e_one_time_keys_txn
        )

    async def get_e2e_bulk_unused_fallback_key_types(
        self, user_ids: Collection[str]
    ) -> TransactionUnusedFallbackKeys:
        """
        Finds, in bulk, the types of unused fallback keys for all the users specified.
        Intended to be used by application services for populating unused fallback
        keys in transactions.

        Return structure is of the shape:
          user_id -> device_id -> algorithms
          Empty lists are created for devices if there are no unused fallback
          keys. This matches the response structure of MSC3202.
        """
        if len(user_ids) == 0:
            return {}

        def _get_bulk_e2e_unused_fallback_keys_txn(
            txn: LoggingTransaction,
        ) -> TransactionUnusedFallbackKeys:
            user_in_where_clause, user_parameters = make_in_list_sql_clause(
                self.database_engine, "devices.user_id", user_ids
            )
            # We can't use USING here because we require the `.used` condition
            # to be part of the JOIN condition so that we generate empty lists
            # when all keys are used (as opposed to just when there are no keys at all).
            sql = f"""
                SELECT devices.user_id, devices.device_id, algorithm
                FROM devices
                LEFT JOIN e2e_fallback_keys_json AS fallback_keys
                    ON devices.user_id = fallback_keys.user_id
                    AND devices.device_id = fallback_keys.device_id
                    AND NOT fallback_keys.used
                WHERE
                    {user_in_where_clause}
            """
            txn.execute(sql, user_parameters)

            result: TransactionUnusedFallbackKeys = {}

            for user_id, device_id, algorithm in txn:
                # We deliberately construct empty dictionaries and lists for
                # users and devices without any unused fallback keys.
                # We *could* omit these empty dicts if there have been no
                # changes since the last transaction, but we currently don't
                # do any change tracking!
                device_unused_keys = result.setdefault(user_id, {}).setdefault(
                    device_id, []
                )
                if algorithm is not None:
                    # algorithm will be None if this device has no keys.
                    device_unused_keys.append(algorithm)

            return result

        return await self.db_pool.runInteraction(
            "_get_bulk_e2e_unused_fallback_keys", _get_bulk_e2e_unused_fallback_keys_txn
        )

    async def set_e2e_fallback_keys(
        self, user_id: str, device_id: str, fallback_keys: JsonDict
    ) -> None:
        """Set the user's e2e fallback keys.

        Args:
            user_id: the user whose keys are being set
            device_id: the device whose keys are being set
            fallback_keys: the keys to set.  This is a map from key ID (which is
                of the form "algorithm:id") to key data.
        """
        await self.db_pool.runInteraction(
            "set_e2e_fallback_keys_txn",
            self._set_e2e_fallback_keys_txn,
            user_id,
            device_id,
            fallback_keys,
        )

        await self.invalidate_cache_and_stream(
            "get_e2e_unused_fallback_key_types", (user_id, device_id)
        )

    def _set_e2e_fallback_keys_txn(
        self,
        txn: LoggingTransaction,
        user_id: str,
        device_id: str,
        fallback_keys: JsonDict,
    ) -> None:
        # fallback_keys will usually only have one item in it, so using a for
        # loop (as opposed to calling simple_upsert_many_txn) won't be too bad
        # FIXME: make sure that only one key per algorithm is uploaded
        for key_id, fallback_key in fallback_keys.items():
            algorithm, key_id = key_id.split(":", 1)
            old_key_json = self.db_pool.simple_select_one_onecol_txn(
                txn,
                table="e2e_fallback_keys_json",
                keyvalues={
                    "user_id": user_id,
                    "device_id": device_id,
                    "algorithm": algorithm,
                },
                retcol="key_json",
                allow_none=True,
            )

            new_key_json = encode_canonical_json(fallback_key).decode("utf-8")

            # If the uploaded key is the same as the current fallback key,
            # don't do anything.  This prevents marking the key as unused if it
            # was already used.
            if old_key_json != new_key_json:
                self.db_pool.simple_upsert_txn(
                    txn,
                    table="e2e_fallback_keys_json",
                    keyvalues={
                        "user_id": user_id,
                        "device_id": device_id,
                        "algorithm": algorithm,
                    },
                    values={
                        "key_id": key_id,
                        "key_json": json_encoder.encode(fallback_key),
                        "used": False,
                    },
                )

    @cached(max_entries=10000)
    async def get_e2e_unused_fallback_key_types(
        self, user_id: str, device_id: str
    ) -> List[str]:
        """Returns the fallback key types that have an unused key.

        Args:
            user_id: the user whose keys are being queried
            device_id: the device whose keys are being queried

        Returns:
            a list of key types
        """
        return await self.db_pool.simple_select_onecol(
            "e2e_fallback_keys_json",
            keyvalues={"user_id": user_id, "device_id": device_id, "used": False},
            retcol="algorithm",
            desc="get_e2e_unused_fallback_key_types",
        )

    async def get_e2e_cross_signing_key(
        self, user_id: str, key_type: str, from_user_id: Optional[str] = None
    ) -> Optional[JsonDict]:
        """Returns a user's cross-signing key.

        Args:
            user_id: the user whose key is being requested
            key_type: the type of key that is being requested: either 'master'
                for a master key, 'self_signing' for a self-signing key, or
                'user_signing' for a user-signing key
            from_user_id: if specified, signatures made by this user on
                the self-signing key will be included in the result

        Returns:
            dict of the key data or None if not found
        """
        res = await self.get_e2e_cross_signing_keys_bulk([user_id], from_user_id)
        user_keys = res.get(user_id)
        if not user_keys:
            return None
        return user_keys.get(key_type)

    @cached(num_args=1)
    def _get_bare_e2e_cross_signing_keys(self, user_id: str) -> Dict[str, JsonDict]:
        """Dummy function.  Only used to make a cache for
        _get_bare_e2e_cross_signing_keys_bulk.
        """
        raise NotImplementedError()

    @cachedList(
        cached_method_name="_get_bare_e2e_cross_signing_keys",
        list_name="user_ids",
        num_args=1,
    )
    async def _get_bare_e2e_cross_signing_keys_bulk(
        self, user_ids: Iterable[str]
    ) -> Dict[str, Optional[Dict[str, JsonDict]]]:
        """Returns the cross-signing keys for a set of users.  The output of this
        function should be passed to _get_e2e_cross_signing_signatures_txn if
        the signatures for the calling user need to be fetched.

        Args:
            user_ids: the users whose keys are being requested

        Returns:
            A mapping from user ID to key type to key data. If a user's cross-signing
            keys were not found, either their user ID will not be in the dict, or
            their user ID will map to None.

        """
        result = await self.db_pool.runInteraction(
            "get_bare_e2e_cross_signing_keys_bulk",
            self._get_bare_e2e_cross_signing_keys_bulk_txn,
            user_ids,
        )

        # The `Optional` comes from the `@cachedList` decorator.
        return cast(Dict[str, Optional[Dict[str, JsonDict]]], result)

    def _get_bare_e2e_cross_signing_keys_bulk_txn(
        self,
        txn: LoggingTransaction,
        user_ids: Iterable[str],
    ) -> Dict[str, Dict[str, JsonDict]]:
        """Returns the cross-signing keys for a set of users.  The output of this
        function should be passed to _get_e2e_cross_signing_signatures_txn if
        the signatures for the calling user need to be fetched.

        Args:
            txn: db connection
            user_ids: the users whose keys are being requested

        Returns:
            Mapping from user ID to key type to key data.
            If a user's cross-signing keys were not found, their user ID will not be in
            the dict.

        """
        result: Dict[str, Dict[str, JsonDict]] = {}

        for user_chunk in batch_iter(user_ids, 100):
            clause, params = make_in_list_sql_clause(
                txn.database_engine, "user_id", user_chunk
            )

            # Fetch the latest key for each type per user.
            if isinstance(self.database_engine, PostgresEngine):
                # The `DISTINCT ON` clause will pick the *first* row it
                # encounters, so ordering by stream ID desc will ensure we get
                # the latest key.
                sql = """
                    SELECT DISTINCT ON (user_id, keytype) user_id, keytype, keydata, stream_id
                        FROM e2e_cross_signing_keys
                        WHERE %(clause)s
                        ORDER BY user_id, keytype, stream_id DESC
                """ % {
                    "clause": clause
                }
            else:
                # SQLite has special handling for bare columns when using
                # MIN/MAX with a `GROUP BY` clause where it picks the value from
                # a row that matches the MIN/MAX.
                sql = """
                    SELECT user_id, keytype, keydata, MAX(stream_id)
                        FROM e2e_cross_signing_keys
                        WHERE %(clause)s
                        GROUP BY user_id, keytype
                """ % {
                    "clause": clause
                }

            txn.execute(sql, params)
            rows = self.db_pool.cursor_to_dict(txn)

            for row in rows:
                user_id = row["user_id"]
                key_type = row["keytype"]
                key = db_to_json(row["keydata"])
                user_keys = result.setdefault(user_id, {})
                user_keys[key_type] = key

        return result

    def _get_e2e_cross_signing_signatures_txn(
        self,
        txn: LoggingTransaction,
        keys: Dict[str, Optional[Dict[str, JsonDict]]],
        from_user_id: str,
    ) -> Dict[str, Optional[Dict[str, JsonDict]]]:
        """Returns the cross-signing signatures made by a user on a set of keys.

        Args:
            txn: db connection
            keys: a map of user ID to key type to key data.
                This dict will be modified to add signatures.
            from_user_id: fetch the signatures made by this user

        Returns:
            Mapping from user ID to key type to key data.
            The return value will be the same as the keys argument, with the
            modifications included.
        """

        # find out what cross-signing keys (a.k.a. devices) we need to get
        # signatures for.  This is a map of (user_id, device_id) to key type
        # (device_id is the key's public part).
        devices: Dict[Tuple[str, str], str] = {}

        for user_id, user_keys in keys.items():
            if user_keys is None:
                continue
            for key_type, key in user_keys.items():
                device_id = None
                for k in key["keys"].values():
                    device_id = k
                # `key` ought to be a `CrossSigningKey`, whose .keys property is a
                # dictionary with a single entry:
                #     "algorithm:base64_public_key": "base64_public_key"
                # See https://spec.matrix.org/v1.1/client-server-api/#cross-signing
                assert isinstance(device_id, str)
                devices[(user_id, device_id)] = key_type

        for batch in batch_iter(devices.keys(), size=100):
            sql = """
                SELECT target_user_id, target_device_id, key_id, signature
                  FROM e2e_cross_signing_signatures
                 WHERE user_id = ?
                   AND (%s)
            """ % (
                " OR ".join(
                    "(target_user_id = ? AND target_device_id = ?)" for _ in batch
                )
            )
            query_params = [from_user_id]
            for item in batch:
                # item is a (user_id, device_id) tuple
                query_params.extend(item)

            txn.execute(sql, query_params)
            rows = self.db_pool.cursor_to_dict(txn)

            # and add the signatures to the appropriate keys
            for row in rows:
                key_id: str = row["key_id"]
                target_user_id: str = row["target_user_id"]
                target_device_id: str = row["target_device_id"]
                key_type = devices[(target_user_id, target_device_id)]
                # We need to copy everything, because the result may have come
                # from the cache.  dict.copy only does a shallow copy, so we
                # need to recursively copy the dicts that will be modified.
                user_keys = keys[target_user_id]
                # `user_keys` cannot be `None` because we only fetched signatures for
                # users with keys
                assert user_keys is not None
                user_keys = keys[target_user_id] = user_keys.copy()

                target_user_key = user_keys[key_type] = user_keys[key_type].copy()
                if "signatures" in target_user_key:
                    signatures = target_user_key["signatures"] = target_user_key[
                        "signatures"
                    ].copy()
                    if from_user_id in signatures:
                        user_sigs = signatures[from_user_id] = signatures[from_user_id]
                        user_sigs[key_id] = row["signature"]
                    else:
                        signatures[from_user_id] = {key_id: row["signature"]}
                else:
                    target_user_key["signatures"] = {
                        from_user_id: {key_id: row["signature"]}
                    }

        return keys

    @cancellable
    async def get_e2e_cross_signing_keys_bulk(
        self, user_ids: List[str], from_user_id: Optional[str] = None
    ) -> Dict[str, Optional[Dict[str, JsonDict]]]:
        """Returns the cross-signing keys for a set of users.

        Args:
            user_ids: the users whose keys are being requested
            from_user_id: if specified, signatures made by this user on
                the self-signing keys will be included in the result

        Returns:
            A map of user ID to key type to key data.  If a user's cross-signing
            keys were not found, either their user ID will not be in the dict,
            or their user ID will map to None.
        """
        result = await self._get_bare_e2e_cross_signing_keys_bulk(user_ids)

        if from_user_id:
            result = await self.db_pool.runInteraction(
                "get_e2e_cross_signing_signatures",
                self._get_e2e_cross_signing_signatures_txn,
                result,
                from_user_id,
            )

        return result

    async def get_all_user_signature_changes_for_remotes(
        self, instance_name: str, last_id: int, current_id: int, limit: int
    ) -> Tuple[List[Tuple[int, tuple]], int, bool]:
        """Get updates for groups replication stream.

        Note that the user signature stream represents when a user signs their
        device with their user-signing key, which is not published to other
        users or servers, so no `destination` is needed in the returned
        list. However, this is needed to poke workers.

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
            function to get further updatees.

            The updates are a list of 2-tuples of stream ID and the row data
        """

        if last_id == current_id:
            return [], current_id, False

        def _get_all_user_signature_changes_for_remotes_txn(
            txn: LoggingTransaction,
        ) -> Tuple[List[Tuple[int, tuple]], int, bool]:
            sql = """
                SELECT stream_id, from_user_id AS user_id
                FROM user_signature_stream
                WHERE ? < stream_id AND stream_id <= ?
                ORDER BY stream_id ASC
                LIMIT ?
            """
            txn.execute(sql, (last_id, current_id, limit))

            updates = [(row[0], (row[1:])) for row in txn]

            limited = False
            upto_token = current_id
            if len(updates) >= limit:
                upto_token = updates[-1][0]
                limited = True

            return updates, upto_token, limited

        return await self.db_pool.runInteraction(
            "get_all_user_signature_changes_for_remotes",
            _get_all_user_signature_changes_for_remotes_txn,
        )

    @abc.abstractmethod
    def get_device_stream_token(self) -> int:
        """Get the current stream id from the _device_list_id_gen"""
        ...

    async def claim_e2e_one_time_keys(
        self, query_list: Iterable[Tuple[str, str, str]]
    ) -> Dict[str, Dict[str, Dict[str, str]]]:
        """Take a list of one time keys out of the database.

        Args:
            query_list: An iterable of tuples of (user ID, device ID, algorithm).

        Returns:
            A map of user ID -> a map device ID -> a map of key ID -> JSON bytes.
        """

        @trace
        def _claim_e2e_one_time_key_simple(
            txn: LoggingTransaction, user_id: str, device_id: str, algorithm: str
        ) -> Optional[Tuple[str, str]]:
            """Claim OTK for device for DBs that don't support RETURNING.

            Returns:
                A tuple of key name (algorithm + key ID) and key JSON, if an
                OTK was found.
            """

            sql = """
                SELECT key_id, key_json FROM e2e_one_time_keys_json
                WHERE user_id = ? AND device_id = ? AND algorithm = ?
                LIMIT 1
            """

            txn.execute(sql, (user_id, device_id, algorithm))
            otk_row = txn.fetchone()
            if otk_row is None:
                return None

            key_id, key_json = otk_row

            self.db_pool.simple_delete_one_txn(
                txn,
                table="e2e_one_time_keys_json",
                keyvalues={
                    "user_id": user_id,
                    "device_id": device_id,
                    "algorithm": algorithm,
                    "key_id": key_id,
                },
            )
            self._invalidate_cache_and_stream(
                txn, self.count_e2e_one_time_keys, (user_id, device_id)
            )

            return f"{algorithm}:{key_id}", key_json

        @trace
        def _claim_e2e_one_time_key_returning(
            txn: LoggingTransaction, user_id: str, device_id: str, algorithm: str
        ) -> Optional[Tuple[str, str]]:
            """Claim OTK for device for DBs that support RETURNING.

            Returns:
                A tuple of key name (algorithm + key ID) and key JSON, if an
                OTK was found.
            """

            # We can use RETURNING to do the fetch and DELETE in once step.
            sql = """
                DELETE FROM e2e_one_time_keys_json
                WHERE user_id = ? AND device_id = ? AND algorithm = ?
                    AND key_id IN (
                        SELECT key_id FROM e2e_one_time_keys_json
                        WHERE user_id = ? AND device_id = ? AND algorithm = ?
                        LIMIT 1
                    )
                RETURNING key_id, key_json
            """

            txn.execute(
                sql, (user_id, device_id, algorithm, user_id, device_id, algorithm)
            )
            otk_row = txn.fetchone()
            if otk_row is None:
                return None

            self._invalidate_cache_and_stream(
                txn, self.count_e2e_one_time_keys, (user_id, device_id)
            )

            key_id, key_json = otk_row
            return f"{algorithm}:{key_id}", key_json

        results: Dict[str, Dict[str, Dict[str, str]]] = {}
        for user_id, device_id, algorithm in query_list:
            if self.database_engine.supports_returning:
                # If we support RETURNING clause we can use a single query that
                # allows us to use autocommit mode.
                _claim_e2e_one_time_key = _claim_e2e_one_time_key_returning
                db_autocommit = True
            else:
                _claim_e2e_one_time_key = _claim_e2e_one_time_key_simple
                db_autocommit = False

            claim_row = await self.db_pool.runInteraction(
                "claim_e2e_one_time_keys",
                _claim_e2e_one_time_key,
                user_id,
                device_id,
                algorithm,
                db_autocommit=db_autocommit,
            )
            if claim_row:
                device_results = results.setdefault(user_id, {}).setdefault(
                    device_id, {}
                )
                device_results[claim_row[0]] = claim_row[1]
                continue

            # No one-time key available, so see if there's a fallback
            # key
            row = await self.db_pool.simple_select_one(
                table="e2e_fallback_keys_json",
                keyvalues={
                    "user_id": user_id,
                    "device_id": device_id,
                    "algorithm": algorithm,
                },
                retcols=("key_id", "key_json", "used"),
                desc="_get_fallback_key",
                allow_none=True,
            )
            if row is None:
                continue

            key_id = row["key_id"]
            key_json = row["key_json"]
            used = row["used"]

            # Mark fallback key as used if not already.
            if not used:
                await self.db_pool.simple_update_one(
                    table="e2e_fallback_keys_json",
                    keyvalues={
                        "user_id": user_id,
                        "device_id": device_id,
                        "algorithm": algorithm,
                        "key_id": key_id,
                    },
                    updatevalues={"used": True},
                    desc="_get_fallback_key_set_used",
                )
                await self.invalidate_cache_and_stream(
                    "get_e2e_unused_fallback_key_types", (user_id, device_id)
                )

            device_results = results.setdefault(user_id, {}).setdefault(device_id, {})
            device_results[f"{algorithm}:{key_id}"] = key_json

        return results


class EndToEndKeyStore(EndToEndKeyWorkerStore, SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        self._cross_signing_id_gen = StreamIdGenerator(
            db_conn, "e2e_cross_signing_keys", "stream_id"
        )

    async def set_e2e_device_keys(
        self, user_id: str, device_id: str, time_now: int, device_keys: JsonDict
    ) -> bool:
        """Stores device keys for a device. Returns whether there was a change
        or the keys were already in the database.
        """

        def _set_e2e_device_keys_txn(txn: LoggingTransaction) -> bool:
            set_tag("user_id", user_id)
            set_tag("device_id", device_id)
            set_tag("time_now", time_now)
            set_tag("device_keys", str(device_keys))

            old_key_json = self.db_pool.simple_select_one_onecol_txn(
                txn,
                table="e2e_device_keys_json",
                keyvalues={"user_id": user_id, "device_id": device_id},
                retcol="key_json",
                allow_none=True,
            )

            # In py3 we need old_key_json to match new_key_json type. The DB
            # returns unicode while encode_canonical_json returns bytes.
            new_key_json = encode_canonical_json(device_keys).decode("utf-8")

            if old_key_json == new_key_json:
                log_kv({"Message": "Device key already stored."})
                return False

            self.db_pool.simple_upsert_txn(
                txn,
                table="e2e_device_keys_json",
                keyvalues={"user_id": user_id, "device_id": device_id},
                values={"ts_added_ms": time_now, "key_json": new_key_json},
            )
            log_kv({"message": "Device keys stored."})
            return True

        return await self.db_pool.runInteraction(
            "set_e2e_device_keys", _set_e2e_device_keys_txn
        )

    async def delete_e2e_keys_by_device(self, user_id: str, device_id: str) -> None:
        def delete_e2e_keys_by_device_txn(txn: LoggingTransaction) -> None:
            log_kv(
                {
                    "message": "Deleting keys for device",
                    "device_id": device_id,
                    "user_id": user_id,
                }
            )
            self.db_pool.simple_delete_txn(
                txn,
                table="e2e_device_keys_json",
                keyvalues={"user_id": user_id, "device_id": device_id},
            )
            self.db_pool.simple_delete_txn(
                txn,
                table="e2e_one_time_keys_json",
                keyvalues={"user_id": user_id, "device_id": device_id},
            )
            self._invalidate_cache_and_stream(
                txn, self.count_e2e_one_time_keys, (user_id, device_id)
            )
            self.db_pool.simple_delete_txn(
                txn,
                table="dehydrated_devices",
                keyvalues={"user_id": user_id, "device_id": device_id},
            )
            self.db_pool.simple_delete_txn(
                txn,
                table="e2e_fallback_keys_json",
                keyvalues={"user_id": user_id, "device_id": device_id},
            )
            self._invalidate_cache_and_stream(
                txn, self.get_e2e_unused_fallback_key_types, (user_id, device_id)
            )

        await self.db_pool.runInteraction(
            "delete_e2e_keys_by_device", delete_e2e_keys_by_device_txn
        )

    def _set_e2e_cross_signing_key_txn(
        self,
        txn: LoggingTransaction,
        user_id: str,
        key_type: str,
        key: JsonDict,
        stream_id: int,
    ) -> None:
        """Set a user's cross-signing key.

        Args:
            txn: db connection
            user_id: the user to set the signing key for
            key_type: the type of key that is being set: either 'master'
                for a master key, 'self_signing' for a self-signing key, or
                'user_signing' for a user-signing key
            key: the key data
            stream_id
        """
        # the 'key' dict will look something like:
        # {
        #   "user_id": "@alice:example.com",
        #   "usage": ["self_signing"],
        #   "keys": {
        #     "ed25519:base64+self+signing+public+key": "base64+self+signing+public+key",
        #   },
        #   "signatures": {
        #     "@alice:example.com": {
        #       "ed25519:base64+master+public+key": "base64+signature"
        #     }
        #   }
        # }
        # The "keys" property must only have one entry, which will be the public
        # key, so we just grab the first value in there
        pubkey = next(iter(key["keys"].values()))

        # The cross-signing keys need to occupy the same namespace as devices,
        # since signatures are identified by device ID.  So add an entry to the
        # device table to make sure that we don't have a collision with device
        # IDs.
        # We only need to do this for local users, since remote servers should be
        # responsible for checking this for their own users.
        if self.hs.is_mine_id(user_id):
            self.db_pool.simple_insert_txn(
                txn,
                "devices",
                values={
                    "user_id": user_id,
                    "device_id": pubkey,
                    "display_name": key_type + " signing key",
                    "hidden": True,
                },
            )

        # and finally, store the key itself
        self.db_pool.simple_insert_txn(
            txn,
            "e2e_cross_signing_keys",
            values={
                "user_id": user_id,
                "keytype": key_type,
                "keydata": json_encoder.encode(key),
                "stream_id": stream_id,
            },
        )

        self._invalidate_cache_and_stream(
            txn, self._get_bare_e2e_cross_signing_keys, (user_id,)
        )

    async def set_e2e_cross_signing_key(
        self, user_id: str, key_type: str, key: JsonDict
    ) -> None:
        """Set a user's cross-signing key.

        Args:
            user_id: the user to set the user-signing key for
            key_type: the type of cross-signing key to set
            key: the key data
        """

        async with self._cross_signing_id_gen.get_next() as stream_id:
            return await self.db_pool.runInteraction(
                "add_e2e_cross_signing_key",
                self._set_e2e_cross_signing_key_txn,
                user_id,
                key_type,
                key,
                stream_id,
            )

    async def store_e2e_cross_signing_signatures(
        self, user_id: str, signatures: "Iterable[SignatureListItem]"
    ) -> None:
        """Stores cross-signing signatures.

        Args:
            user_id: the user who made the signatures
            signatures: signatures to add
        """
        await self.db_pool.simple_insert_many(
            "e2e_cross_signing_signatures",
            keys=(
                "user_id",
                "key_id",
                "target_user_id",
                "target_device_id",
                "signature",
            ),
            values=[
                (
                    user_id,
                    item.signing_key_id,
                    item.target_user_id,
                    item.target_device_id,
                    item.signature,
                )
                for item in signatures
            ],
            desc="add_e2e_signing_key",
        )
