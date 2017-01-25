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
    @defer.inlineCallbacks
    def store_device(self, user_id, device_id,
                     initial_device_display_name,
                     ignore_if_known=True):
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

    def get_devices_by_remote(self, destination, from_stream_id):
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
            WHERE destination = ? AND stream_id > ? AND stream_id <= ? AND sent = ?
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
            WHERE destination = ? AND user_id = ? AND sent = ?
        """

        results = []
        for user_id, user_devices in devices.iteritems():
            txn.execute(prev_sent_id_sql, (destination, user_id, True))
            rows = txn.fetchall()
            prev_id = rows[0][0]
            for device_id, result in user_devices.iteritems():
                stream_id = query_map[(user_id, device_id)]
                result = {
                    "user_id": user_id,
                    "device_id": device_id,
                    "prev_id": [prev_id] if prev_id else [],
                    "stream_id": stream_id,
                }

                prev_id = stream_id

                key_json = result.get("key_json", None)
                if key_json:
                    result["keys"] = json.loads(key_json)
                device_display_name = result.get("device_display_name", None)
                if device_display_name:
                    result["device_display_name"] = device_display_name

                results.append(result)

        return (now_stream_id, results)

    def mark_as_sent_devices_by_remote(self, destination, stream_id):
        return self.runInteraction(
            "mark_as_sent_devices_by_remote", self._mark_as_sent_devices_by_remote_txn,
            destination, stream_id,
        )

    def _mark_as_sent_devices_by_remote_txn(self, txn, destination, stream_id):
        sql = """
            DELETE FROM device_lists_outbound_pokes
            WHERE destination = ? AND stream_id < (
                SELECT coalesce(max(stream_id), 0) FROM device_lists_outbound_pokes
                WHERE destination = ? AND stream_id <= ?
            )
        """
        txn.execute(sql, (destination, destination, stream_id,))

        sql = """
            UPDATE device_lists_outbound_pokes SET sent = ?
            WHERE destination = ? AND stream_id <= ?
        """
        txn.execute(sql, (True, destination, stream_id,))

    @defer.inlineCallbacks
    def get_user_whose_devices_changed(self, from_key):
        from_key = int(from_key)
        changed = self._device_list_stream_cache.get_all_entities_changed(from_key)
        if changed is not None:
            defer.returnValue(set(changed))

        sql = """
            SELECT user_id FROM device_lists_stream WHERE stream_id > ?
        """
        rows = yield self._execute("get_user_whose_devices_changed", None, sql, from_key)
        defer.returnValue(set(row["user_id"] for row in rows))

    @defer.inlineCallbacks
    def add_device_change_to_streams(self, user_id, device_id, hosts):
        # device_lists_stream
        # device_lists_outbound_pokes
        with self._device_list_id_gen.get_next() as stream_id:
            yield self.runInteraction(
                "add_device_change_to_streams", self._add_device_change_txn,
                user_id, device_id, hosts, stream_id,
            )
        defer.returnValue(stream_id)

    def _add_device_change_txn(self, txn, user_id, device_id, hosts, stream_id):
        txn.call_after(
            self._device_list_stream_cache.entity_has_changed,
            user_id, stream_id,
        )
        for host in hosts:
            txn.call_after(
                self._device_list_federation_stream_cache.entity_has_changed,
                host, stream_id,
            )

        self._simple_insert_txn(
            txn,
            table="device_lists_stream",
            values={
                "stream_id": stream_id,
                "user_id": user_id,
                "device_id": device_id,
            }
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
                }
                for destination in hosts
            ]
        )

    def get_device_stream_token(self):
        return self._device_list_id_gen.get_current_token()
