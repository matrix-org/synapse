# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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
import ujson as json

from twisted.internet import defer

from synapse.api.errors import StoreError
from ._base import SQLBaseStore

logger = logging.getLogger(__name__)


class DeviceStore(SQLBaseStore):
    def __init__(self, hs):
        super(DeviceStore, self).__init__(hs)

        self._clock.looping_call(
            self._prune_old_outbound_device_pokes, 60 * 60 * 1000
        )

    @defer.inlineCallbacks
    def store_device(self, user_id, device_id,
                     initial_device_display_name):
        """Ensure the given device is known; add it to the store if not

        Args:
            user_id (str): id of user associated with the device
            device_id (str): id of device
            initial_device_display_name (str): initial displayname of the
               device. Ignored if device exists.
        Returns:
            defer.Deferred: boolean whether the device was inserted or an
                existing device existed with that ID.
        """
        try:
            inserted = yield self._simple_insert(
                "devices",
                values={
                    "user_id": user_id,
                    "device_id": device_id,
                    "display_name": initial_device_display_name
                },
                desc="store_device",
                or_ignore=True,
            )
            defer.returnValue(inserted)
        except Exception as e:
            logger.error("store_device with device_id=%s(%r) user_id=%s(%r)"
                         " display_name=%s(%r) failed: %s",
                         type(device_id).__name__, device_id,
                         type(user_id).__name__, user_id,
                         type(initial_device_display_name).__name__,
                         initial_device_display_name, e)
            raise StoreError(500, "Problem storing device.")

    def get_device(self, user_id, device_id):
        """Retrieve a device.

        Args:
            user_id (str): The ID of the user which owns the device
            device_id (str): The ID of the device to retrieve
        Returns:
            defer.Deferred for a dict containing the device information
        Raises:
            StoreError: if the device is not found
        """
        return self._simple_select_one(
            table="devices",
            keyvalues={"user_id": user_id, "device_id": device_id},
            retcols=("user_id", "device_id", "display_name"),
            desc="get_device",
        )

    def delete_device(self, user_id, device_id):
        """Delete a device.

        Args:
            user_id (str): The ID of the user which owns the device
            device_id (str): The ID of the device to delete
        Returns:
            defer.Deferred
        """
        return self._simple_delete_one(
            table="devices",
            keyvalues={"user_id": user_id, "device_id": device_id},
            desc="delete_device",
        )

    def update_device(self, user_id, device_id, new_display_name=None):
        """Update a device.

        Args:
            user_id (str): The ID of the user which owns the device
            device_id (str): The ID of the device to update
            new_display_name (str|None): new displayname for device; None
               to leave unchanged
        Raises:
            StoreError: if the device is not found
        Returns:
            defer.Deferred
        """
        updates = {}
        if new_display_name is not None:
            updates["display_name"] = new_display_name
        if not updates:
            return defer.succeed(None)
        return self._simple_update_one(
            table="devices",
            keyvalues={"user_id": user_id, "device_id": device_id},
            updatevalues=updates,
            desc="update_device",
        )

    @defer.inlineCallbacks
    def get_devices_by_user(self, user_id):
        """Retrieve all of a user's registered devices.

        Args:
            user_id (str):
        Returns:
            defer.Deferred: resolves to a dict from device_id to a dict
            containing "device_id", "user_id" and "display_name" for each
            device.
        """
        devices = yield self._simple_select_list(
            table="devices",
            keyvalues={"user_id": user_id},
            retcols=("user_id", "device_id", "display_name"),
            desc="get_devices_by_user"
        )

        defer.returnValue({d["device_id"]: d for d in devices})

    def get_device_list_last_stream_id_for_remote(self, user_id):
        """Get the last stream_id we got for a user. May be None if we haven't
        got any information for them.
        """
        return self._simple_select_one_onecol(
            table="device_lists_remote_extremeties",
            keyvalues={"user_id": user_id},
            retcol="stream_id",
            desc="get_device_list_remote_extremity",
            allow_none=True,
        )

    def mark_remote_user_device_list_as_unsubscribed(self, user_id):
        """Mark that we no longer track device lists for remote user.
        """
        return self._simple_delete(
            table="device_lists_remote_extremeties",
            keyvalues={
                "user_id": user_id,
            },
            desc="mark_remote_user_device_list_as_unsubscribed",
        )

    def update_remote_device_list_cache_entry(self, user_id, device_id, content,
                                              stream_id):
        """Updates a single user's device in the cache.
        """
        return self.runInteraction(
            "update_remote_device_list_cache_entry",
            self._update_remote_device_list_cache_entry_txn,
            user_id, device_id, content, stream_id,
        )

    def _update_remote_device_list_cache_entry_txn(self, txn, user_id, device_id,
                                                   content, stream_id):
        self._simple_upsert_txn(
            txn,
            table="device_lists_remote_cache",
            keyvalues={
                "user_id": user_id,
                "device_id": device_id,
            },
            values={
                "content": json.dumps(content),
            }
        )

        self._simple_upsert_txn(
            txn,
            table="device_lists_remote_extremeties",
            keyvalues={
                "user_id": user_id,
            },
            values={
                "stream_id": stream_id,
            }
        )

    def update_remote_device_list_cache(self, user_id, devices, stream_id):
        """Replace the cache of the remote user's devices.
        """
        return self.runInteraction(
            "update_remote_device_list_cache",
            self._update_remote_device_list_cache_txn,
            user_id, devices, stream_id,
        )

    def _update_remote_device_list_cache_txn(self, txn, user_id, devices,
                                             stream_id):
        self._simple_delete_txn(
            txn,
            table="device_lists_remote_cache",
            keyvalues={
                "user_id": user_id,
            },
        )

        self._simple_insert_many_txn(
            txn,
            table="device_lists_remote_cache",
            values=[
                {
                    "user_id": user_id,
                    "device_id": content["device_id"],
                    "content": json.dumps(content),
                }
                for content in devices
            ]
        )

        self._simple_upsert_txn(
            txn,
            table="device_lists_remote_extremeties",
            keyvalues={
                "user_id": user_id,
            },
            values={
                "stream_id": stream_id,
            }
        )

    def get_devices_by_remote(self, destination, from_stream_id):
        """Get stream of updates to send to remote servers

        Returns:
            (now_stream_id, [ { updates }, .. ])
        """
        now_stream_id = self._device_list_id_gen.get_current_token()

        has_changed = self._device_list_federation_stream_cache.has_entity_changed(
            destination, int(from_stream_id)
        )
        if not has_changed:
            return (now_stream_id, [])

        return self.runInteraction(
            "get_devices_by_remote", self._get_devices_by_remote_txn,
            destination, from_stream_id, now_stream_id,
        )

    def _get_devices_by_remote_txn(self, txn, destination, from_stream_id,
                                   now_stream_id):
        sql = """
            SELECT user_id, device_id, max(stream_id) FROM device_lists_outbound_pokes
            WHERE destination = ? AND ? < stream_id AND stream_id <= ? AND sent = ?
            GROUP BY user_id, device_id
        """
        txn.execute(
            sql, (destination, from_stream_id, now_stream_id, False)
        )
        rows = txn.fetchall()

        if not rows:
            return (now_stream_id, [])

        # maps (user_id, device_id) -> stream_id
        query_map = {(r[0], r[1]): r[2] for r in rows}
        devices = self._get_e2e_device_keys_txn(
            txn, query_map.keys(), include_all_devices=True
        )

        prev_sent_id_sql = """
            SELECT coalesce(max(stream_id), 0) as stream_id
            FROM device_lists_outbound_pokes
            WHERE destination = ? AND user_id = ? AND stream_id <= ?
        """

        results = []
        for user_id, user_devices in devices.iteritems():
            # The prev_id for the first row is always the last row before
            # `from_stream_id`
            txn.execute(prev_sent_id_sql, (destination, user_id, from_stream_id))
            rows = txn.fetchall()
            prev_id = rows[0][0]
            for device_id, device in user_devices.iteritems():
                stream_id = query_map[(user_id, device_id)]
                result = {
                    "user_id": user_id,
                    "device_id": device_id,
                    "prev_id": [prev_id] if prev_id else [],
                    "stream_id": stream_id,
                }

                prev_id = stream_id

                key_json = device.get("key_json", None)
                if key_json:
                    result["keys"] = json.loads(key_json)
                device_display_name = device.get("device_display_name", None)
                if device_display_name:
                    result["device_display_name"] = device_display_name

                results.append(result)

        return (now_stream_id, results)

    def get_user_devices_from_cache(self, query_list):
        """Get the devices (and keys if any) for remote users from the cache.

        Args:
            query_list(list): List of (user_id, device_ids), if device_ids is
                falsey then return all device ids for that user.

        Returns:
            (user_ids_not_in_cache, results_map), where user_ids_not_in_cache is
            a set of user_ids and results_map is a mapping of
            user_id -> device_id -> device_info
        """
        return self.runInteraction(
            "get_user_devices_from_cache", self._get_user_devices_from_cache_txn,
            query_list,
        )

    def _get_user_devices_from_cache_txn(self, txn, query_list):
        user_ids = {user_id for user_id, _ in query_list}

        user_ids_in_cache = set()
        for user_id in user_ids:
            stream_ids = self._simple_select_onecol_txn(
                txn,
                table="device_lists_remote_extremeties",
                keyvalues={
                    "user_id": user_id,
                },
                retcol="stream_id",
            )
            if stream_ids:
                user_ids_in_cache.add(user_id)

        user_ids_not_in_cache = user_ids - user_ids_in_cache

        results = {}
        for user_id, device_id in query_list:
            if user_id not in user_ids_in_cache:
                continue

            if device_id:
                content = self._simple_select_one_onecol_txn(
                    txn,
                    table="device_lists_remote_cache",
                    keyvalues={
                        "user_id": user_id,
                        "device_id": device_id,
                    },
                    retcol="content",
                )
                results.setdefault(user_id, {})[device_id] = json.loads(content)
            else:
                devices = self._simple_select_list_txn(
                    txn,
                    table="device_lists_remote_cache",
                    keyvalues={
                        "user_id": user_id,
                    },
                    retcols=("device_id", "content"),
                )
                results[user_id] = {
                    device["device_id"]: json.loads(device["content"])
                    for device in devices
                }
                user_ids_in_cache.discard(user_id)

        return user_ids_not_in_cache, results

    def get_devices_with_keys_by_user(self, user_id):
        """Get all devices (with any device keys) for a user

        Returns:
            (stream_id, devices)
        """
        return self.runInteraction(
            "get_devices_with_keys_by_user",
            self._get_devices_with_keys_by_user_txn, user_id,
        )

    def _get_devices_with_keys_by_user_txn(self, txn, user_id):
        now_stream_id = self._device_list_id_gen.get_current_token()

        devices = self._get_e2e_device_keys_txn(
            txn, [(user_id, None)], include_all_devices=True
        )

        if devices:
            user_devices = devices[user_id]
            results = []
            for device_id, device in user_devices.iteritems():
                result = {
                    "device_id": device_id,
                }

                key_json = device.get("key_json", None)
                if key_json:
                    result["keys"] = json.loads(key_json)
                device_display_name = device.get("device_display_name", None)
                if device_display_name:
                    result["device_display_name"] = device_display_name

                results.append(result)

            return now_stream_id, results

        return now_stream_id, []

    def mark_as_sent_devices_by_remote(self, destination, stream_id):
        """Mark that updates have successfully been sent to the destination.
        """
        return self.runInteraction(
            "mark_as_sent_devices_by_remote", self._mark_as_sent_devices_by_remote_txn,
            destination, stream_id,
        )

    def _mark_as_sent_devices_by_remote_txn(self, txn, destination, stream_id):
        # First we DELETE all rows such that only the latest row for each
        # (destination, user_id is left. We do this by selecting first and
        # deleting.
        sql = """
            SELECT user_id, coalesce(max(stream_id), 0) FROM device_lists_outbound_pokes
            WHERE destination = ? AND stream_id <= ?
            GROUP BY user_id
            HAVING count(*) > 1
        """
        txn.execute(sql, (destination, stream_id,))
        rows = txn.fetchall()

        sql = """
            DELETE FROM device_lists_outbound_pokes
            WHERE destination = ? AND user_id = ? AND stream_id < ?
        """
        txn.executemany(
            sql, ((destination, row[0], row[1],) for row in rows)
        )

        # Mark everything that is left as sent
        sql = """
            UPDATE device_lists_outbound_pokes SET sent = ?
            WHERE destination = ? AND stream_id <= ?
        """
        txn.execute(sql, (True, destination, stream_id,))

    @defer.inlineCallbacks
    def get_user_whose_devices_changed(self, from_key):
        """Get set of users whose devices have changed since `from_key`.
        """
        from_key = int(from_key)
        changed = self._device_list_stream_cache.get_all_entities_changed(from_key)
        if changed is not None:
            defer.returnValue(set(changed))

        sql = """
            SELECT user_id FROM device_lists_stream WHERE stream_id > ?
        """
        rows = yield self._execute("get_user_whose_devices_changed", None, sql, from_key)
        defer.returnValue(set(row[0] for row in rows))

    def get_all_device_list_changes_for_remotes(self, from_key):
        """Return a list of `(stream_id, user_id, destination)` which is the
        combined list of changes to devices, and which destinations need to be
        poked. `destination` may be None if no destinations need to be poked.
        """
        sql = """
            SELECT stream_id, user_id, destination FROM device_lists_stream
            LEFT JOIN device_lists_outbound_pokes USING (stream_id, user_id, device_id)
            WHERE stream_id > ?
        """
        return self._execute(
            "get_users_and_hosts_device_list", None,
            sql, from_key,
        )

    @defer.inlineCallbacks
    def add_device_change_to_streams(self, user_id, device_ids, hosts):
        """Persist that a user's devices have been updated, and which hosts
        (if any) should be poked.
        """
        with self._device_list_id_gen.get_next() as stream_id:
            yield self.runInteraction(
                "add_device_change_to_streams", self._add_device_change_txn,
                user_id, device_ids, hosts, stream_id,
            )
        defer.returnValue(stream_id)

    def _add_device_change_txn(self, txn, user_id, device_ids, hosts, stream_id):
        now = self._clock.time_msec()

        txn.call_after(
            self._device_list_stream_cache.entity_has_changed,
            user_id, stream_id,
        )
        for host in hosts:
            txn.call_after(
                self._device_list_federation_stream_cache.entity_has_changed,
                host, stream_id,
            )

        self._simple_insert_many_txn(
            txn,
            table="device_lists_stream",
            values=[
                {
                    "stream_id": stream_id,
                    "user_id": user_id,
                    "device_id": device_id,
                }
                for device_id in device_ids
            ]
        )

        self._simple_insert_many_txn(
            txn,
            table="device_lists_outbound_pokes",
            values=[
                {
                    "destination": destination,
                    "stream_id": stream_id,
                    "user_id": user_id,
                    "device_id": device_id,
                    "sent": False,
                    "ts": now,
                }
                for destination in hosts
                for device_id in device_ids
            ]
        )

    def get_device_stream_token(self):
        return self._device_list_id_gen.get_current_token()

    def _prune_old_outbound_device_pokes(self):
        """Delete old entries out of the device_lists_outbound_pokes to ensure
        that we don't fill up due to dead servers. We keep one entry per
        (destination, user_id) tuple to ensure that the prev_ids remain correct
        if the server does come back.
        """
        yesterday = self._clock.time_msec() - 24 * 60 * 60 * 1000

        def _prune_txn(txn):
            select_sql = """
                SELECT destination, user_id, max(stream_id) as stream_id
                FROM device_lists_outbound_pokes
                GROUP BY destination, user_id
                HAVING min(ts) < ? AND count(*) > 1
            """

            txn.execute(select_sql, (yesterday,))
            rows = txn.fetchall()

            if not rows:
                return

            delete_sql = """
                DELETE FROM device_lists_outbound_pokes
                WHERE ts < ? AND destination = ? AND user_id = ? AND stream_id < ?
            """

            txn.executemany(
                delete_sql,
                (
                    (yesterday, row[0], row[1], row[2])
                    for row in rows
                )
            )

            logger.info("Pruned %d device list outbound pokes", txn.rowcount)

        return self.runInteraction(
            "_prune_old_outbound_device_pokes", _prune_txn
        )
