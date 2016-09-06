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
import ujson

from twisted.internet import defer

from ._base import SQLBaseStore


logger = logging.getLogger(__name__)


class DeviceInboxStore(SQLBaseStore):

    @defer.inlineCallbacks
    def add_messages_to_device_inbox(self, local_messages_by_user_then_device,
                                     remote_messages_by_destination):
        """Used to send messages from this server.

        Args:
            sender_user_id(str): The ID of the user sending these messages.
            local_messages_by_user_and_device(dict):
                Dictionary of user_id to device_id to message.
            remote_messages_by_destination(dict):
                Dictionary of destination server_name to the EDU JSON to send.
        Returns:
            A deferred stream_id that resolves when the messages have been
            inserted.
        """

        def add_messages_to_device_federation_outbox(txn, now_ms, stream_id):
            sql = (
                "INSERT INTO device_federation_outbox"
                " (destination, stream_id, queued_ts, messages_json)"
                " VALUES (?,?,?,?)"
            )
            rows = []
            for destination, edu in remote_messages_by_destination.items():
                edu_json = ujson.dumps(edu)
                rows.append((destination, stream_id, now_ms, edu_json))

            txn.executemany(sql, rows)

        def add_messages_txn(txn, now_ms, stream_id):
            self._add_messages_to_local_device_inbox_txn(
                txn, stream_id, local_messages_by_user_then_device
            )
            add_messages_to_device_federation_outbox(now_ms, stream_id)

        with self._device_inbox_id_gen.get_next() as stream_id:
            now_ms = self.clock.time_now_ms()
            yield self.runInteraction(
                "add_messages_to_device_inbox",
                add_messages_txn,
                now_ms,
                stream_id,
            )

        defer.returnValue(self._device_inbox_id_gen.get_current_token())

    @defer.inlineCallbacks
    def add_messages_from_remote_to_device_inbox(
        self, origin, message_id, local_messages_by_user_then_device
    ):
        def add_messages_txn(txn, now_ms, stream_id):
            already_inserted = self._simple_select_one_txn(
                txn, table="device_federation_inbox",
                keyvalues={"origin": origin, "message_id": message_id},
                retcols=("message_id",),
                allow_none=True,
            )
            if already_inserted is not None:
                return

            self._simple_insert_txn(
                txn, table="device_federation_inbox",
                values={
                    "origin": origin,
                    "message_id": message_id,
                    "received_ts": now_ms,
                },
            )

            self._add_messages_to_local_device_inbox_txn(
                txn, stream_id, local_messages_by_user_then_device
            )

        with self._device_inbox_id_gen.get_next() as stream_id:
            now_ms = self.clock.time_now_ms()
            yield self.runInteraction(
                "add_messages_from_remote_to_device_inbox",
                add_messages_txn,
                now_ms,
                stream_id,
            )

    def _add_messages_to_local_device_inbox_txn(self, txn, stream_id,
                                                messages_by_user_then_device):
        local_users_and_devices = set()
        for user_id, messages_by_device in messages_by_user_then_device.items():
            devices = messages_by_device.keys()
            sql = (
                "SELECT user_id, device_id FROM devices"
                " WHERE user_id = ? AND device_id IN ("
                + ",".join("?" * len(devices))
                + ")"
            )
            # TODO: Maybe this needs to be done in batches if there are
            # too many local devices for a given user.
            txn.execute(sql, [user_id] + devices)
            local_users_and_devices.update(map(tuple, txn.fetchall()))

        sql = (
            "INSERT INTO device_inbox"
            " (user_id, device_id, stream_id, message_json)"
            " VALUES (?,?,?,?)"
        )
        rows = []
        for user_id, messages_by_device in messages_by_user_then_device.items():
            for device_id, message in messages_by_device.items():
                message_json = ujson.dumps(message)
                # Only insert into the local inbox if the device exists on
                # this server
                if (user_id, device_id) in local_users_and_devices:
                    rows.append((user_id, device_id, stream_id, message_json))

        txn.executemany(sql, rows)

    def get_new_messages_for_device(
        self, user_id, device_id, last_stream_id, current_stream_id, limit=100
    ):
        """
        Args:
            user_id(str): The recipient user_id.
            device_id(str): The recipient device_id.
            current_stream_id(int): The current position of the to device
                message stream.
        Returns:
            Deferred ([dict], int): List of messages for the device and where
                in the stream the messages got to.
        """
        def get_new_messages_for_device_txn(txn):
            sql = (
                "SELECT stream_id, message_json FROM device_inbox"
                " WHERE user_id = ? AND device_id = ?"
                " AND ? < stream_id AND stream_id <= ?"
                " ORDER BY stream_id ASC"
                " LIMIT ?"
            )
            txn.execute(sql, (
                user_id, device_id, last_stream_id, current_stream_id, limit
            ))
            messages = []
            for row in txn.fetchall():
                stream_pos = row[0]
                messages.append(ujson.loads(row[1]))
            if len(messages) < limit:
                stream_pos = current_stream_id
            return (messages, stream_pos)

        return self.runInteraction(
            "get_new_messages_for_device", get_new_messages_for_device_txn,
        )

    def delete_messages_for_device(self, user_id, device_id, up_to_stream_id):
        """
        Args:
            user_id(str): The recipient user_id.
            device_id(str): The recipient device_id.
            up_to_stream_id(int): Where to delete messages up to.
        Returns:
            A deferred that resolves when the messages have been deleted.
        """
        def delete_messages_for_device_txn(txn):
            sql = (
                "DELETE FROM device_inbox"
                " WHERE user_id = ? AND device_id = ?"
                " AND stream_id <= ?"
            )
            txn.execute(sql, (user_id, device_id, up_to_stream_id))

        return self.runInteraction(
            "delete_messages_for_device", delete_messages_for_device_txn
        )

    def get_all_new_device_messages(self, last_pos, current_pos, limit):
        """
        Args:
            last_pos(int):
            current_pos(int):
            limit(int):
        Returns:
            A deferred list of rows from the device inbox
        """
        if last_pos == current_pos:
            return defer.succeed([])

        def get_all_new_device_messages_txn(txn):
            sql = (
                "SELECT stream_id FROM device_inbox"
                " WHERE ? < stream_id AND stream_id <= ?"
                " GROUP BY stream_id"
                " ORDER BY stream_id ASC"
                " LIMIT ?"
            )
            txn.execute(sql, (last_pos, current_pos, limit))
            stream_ids = txn.fetchall()
            if not stream_ids:
                return []
            max_stream_id_in_limit = stream_ids[-1]

            sql = (
                "SELECT stream_id, user_id, device_id, message_json"
                " FROM device_inbox"
                " WHERE ? < stream_id AND stream_id <= ?"
                " ORDER BY stream_id ASC"
            )
            txn.execute(sql, (last_pos, max_stream_id_in_limit))
            return txn.fetchall()

        return self.runInteraction(
            "get_all_new_device_messages", get_all_new_device_messages_txn
        )

    def get_to_device_stream_token(self):
        return self._device_inbox_id_gen.get_current_token()

    @defer.inlineCallbacks
    def get_new_device_messages_for_remote_destination(
        self, destination, last_stream_id, current_stream_id, limit=100
    ):
        """
        Args:
            destination(str): The name of the remote server.
            last_stream_id(int): The last position of the device message stream
                that the server sent up to.
            current_stream_id(int): The current position of the device
                message stream.
        Returns:
            Deferred ([dict], int): List of messages for the device and where
                in the stream the messages got to.
        """
        def get_new_messages_for_remote_destination_txn(txn):
            sql = (
                "SELECT stream_id, messages_json FROM device_federation_outbox"
                " WHERE destination = ?"
                " AND ? < stream_id AND stream_id <= ?"
                " ORDER BY stream_id ASC"
                " LIMIT ?"
            )
            txn.execute(sql, (
                destination, last_stream_id, current_stream_id, limit
            ))
            messages = []
            for row in txn.fetchall():
                stream_pos = row[0]
                messages.append(ujson.loads(row[1]))
            if len(messages) < limit:
                stream_pos = current_stream_id
            return (messages, stream_pos)

        return self.runInteraction(
            "get_new_device_messages_for_remote_destination",
            get_new_messages_for_remote_destination_txn,
        )

    @defer.inlineCallbacks
    def delete_device_messages_for_remote_destination(self, destination,
                                                      up_to_stream_id):
        """Used to delete messages when the remote destination acknowledges
        their receipt.

        Args:
            destination(str): The destination server_name
            up_to_stream_id(int): Where to delete messages up to.
        Returns:
            A deferred that resolves when the messages have been deleted.
        """
        def delete_messages_for_remote_destination_txn(txn):
            sql = (
                "DELETE FROM device_federation_outbox"
                " WHERE destination = ? AND"
                " AND stream_id <= ?"
            )
            txn.execute(sql, (destination, up_to_stream_id))

        return self.runInteraction(
            "delete_device_messages_for_remote_destination",
            delete_messages_for_remote_destination_txn
        )
