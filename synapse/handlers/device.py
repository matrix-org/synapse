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

from synapse.api import errors
from synapse.api.constants import EventTypes
from synapse.util import stringutils
from synapse.util.async import Linearizer
from synapse.util.metrics import measure_func
from synapse.types import get_domain_from_id, RoomStreamToken
from twisted.internet import defer
from ._base import BaseHandler

import logging

logger = logging.getLogger(__name__)


class DeviceHandler(BaseHandler):
    def __init__(self, hs):
        super(DeviceHandler, self).__init__(hs)

        self.hs = hs
        self.state = hs.get_state_handler()
        self.federation_sender = hs.get_federation_sender()
        self.federation = hs.get_replication_layer()
        self._remote_edue_linearizer = Linearizer(name="remote_device_list")

        self.federation.register_edu_handler(
            "m.device_list_update", self._incoming_device_list_update,
        )
        self.federation.register_query_handler(
            "user_devices", self.on_federation_query_user_devices,
        )

        hs.get_distributor().observe("user_left_room", self.user_left_room)

    @defer.inlineCallbacks
    def check_device_registered(self, user_id, device_id,
                                initial_device_display_name=None):
        """
        If the given device has not been registered, register it with the
        supplied display name.

        If no device_id is supplied, we make one up.

        Args:
            user_id (str):  @user:id
            device_id (str | None): device id supplied by client
            initial_device_display_name (str | None): device display name from
                 client
        Returns:
            str: device id (generated if none was supplied)
        """
        if device_id is not None:
            new_device = yield self.store.store_device(
                user_id=user_id,
                device_id=device_id,
                initial_device_display_name=initial_device_display_name,
            )
            if new_device:
                yield self.notify_device_update(user_id, [device_id])
            defer.returnValue(device_id)

        # if the device id is not specified, we'll autogen one, but loop a few
        # times in case of a clash.
        attempts = 0
        while attempts < 5:
            device_id = stringutils.random_string(10).upper()
            new_device = yield self.store.store_device(
                user_id=user_id,
                device_id=device_id,
                initial_device_display_name=initial_device_display_name,
            )
            if new_device:
                yield self.notify_device_update(user_id, [device_id])
                defer.returnValue(device_id)
            attempts += 1

        raise errors.StoreError(500, "Couldn't generate a device ID.")

    @defer.inlineCallbacks
    def get_devices_by_user(self, user_id):
        """
        Retrieve the given user's devices

        Args:
            user_id (str):
        Returns:
            defer.Deferred: list[dict[str, X]]: info on each device
        """

        device_map = yield self.store.get_devices_by_user(user_id)

        ips = yield self.store.get_last_client_ip_by_device(
            devices=((user_id, device_id) for device_id in device_map.keys())
        )

        devices = device_map.values()
        for device in devices:
            _update_device_from_client_ips(device, ips)

        defer.returnValue(devices)

    @defer.inlineCallbacks
    def get_device(self, user_id, device_id):
        """ Retrieve the given device

        Args:
            user_id (str):
            device_id (str):

        Returns:
            defer.Deferred: dict[str, X]: info on the device
        Raises:
            errors.NotFoundError: if the device was not found
        """
        try:
            device = yield self.store.get_device(user_id, device_id)
        except errors.StoreError:
            raise errors.NotFoundError
        ips = yield self.store.get_last_client_ip_by_device(
            devices=((user_id, device_id),)
        )
        _update_device_from_client_ips(device, ips)
        defer.returnValue(device)

    @defer.inlineCallbacks
    def delete_device(self, user_id, device_id):
        """ Delete the given device

        Args:
            user_id (str):
            device_id (str):

        Returns:
            defer.Deferred:
        """

        try:
            yield self.store.delete_device(user_id, device_id)
        except errors.StoreError, e:
            if e.code == 404:
                # no match
                pass
            else:
                raise

        yield self.store.user_delete_access_tokens(
            user_id, device_id=device_id,
            delete_refresh_tokens=True,
        )

        yield self.store.delete_e2e_keys_by_device(
            user_id=user_id, device_id=device_id
        )

        yield self.notify_device_update(user_id, [device_id])

    @defer.inlineCallbacks
    def update_device(self, user_id, device_id, content):
        """ Update the given device

        Args:
            user_id (str):
            device_id (str):
            content (dict): body of update request

        Returns:
            defer.Deferred:
        """

        try:
            yield self.store.update_device(
                user_id,
                device_id,
                new_display_name=content.get("display_name")
            )
            yield self.notify_device_update(user_id, [device_id])
        except errors.StoreError, e:
            if e.code == 404:
                raise errors.NotFoundError()
            else:
                raise

    @measure_func("notify_device_update")
    @defer.inlineCallbacks
    def notify_device_update(self, user_id, device_ids):
        """Notify that a user's device(s) has changed. Pokes the notifier, and
        remote servers if the user is local.
        """
        users_who_share_room = yield self.store.get_users_who_share_room_with_user(
            user_id
        )

        hosts = set()
        if self.hs.is_mine_id(user_id):
            hosts.update(get_domain_from_id(u) for u in users_who_share_room)
            hosts.discard(self.server_name)

        position = yield self.store.add_device_change_to_streams(
            user_id, device_ids, list(hosts)
        )

        rooms = yield self.store.get_rooms_for_user(user_id)
        room_ids = [r.room_id for r in rooms]

        yield self.notifier.on_new_event(
            "device_list_key", position, rooms=room_ids,
        )

        if hosts:
            logger.info("Sending device list update notif to: %r", hosts)
            for host in hosts:
                self.federation_sender.send_device_messages(host)

    @measure_func("device.get_user_ids_changed")
    @defer.inlineCallbacks
    def get_user_ids_changed(self, user_id, from_token):
        """Get list of users that have had the devices updated, or have newly
        joined a room, that `user_id` may be interested in.

        Args:
            user_id (str)
            from_token (StreamToken)
        """
        rooms = yield self.store.get_rooms_for_user(user_id)
        room_ids = set(r.room_id for r in rooms)

        # First we check if any devices have changed
        changed = yield self.store.get_user_whose_devices_changed(
            from_token.device_list_key
        )

        # Then work out if any users have since joined
        rooms_changed = self.store.get_rooms_that_changed(room_ids, from_token.room_key)

        possibly_changed = set(changed)
        for room_id in rooms_changed:
            # Fetch  the current state at the time.
            stream_ordering = RoomStreamToken.parse_stream_token(from_token.room_key)

            try:
                event_ids = yield self.store.get_forward_extremeties_for_room(
                    room_id, stream_ordering=stream_ordering
                )
                prev_state_ids = yield self.store.get_state_ids_for_events(event_ids)
            except:
                prev_state_ids = {}

            current_state_ids = yield self.state.get_current_state_ids(room_id)

            # If there has been any change in membership, include them in the
            # possibly changed list. We'll check if they are joined below,
            # and we're not toooo worried about spuriously adding users.
            for key, event_id in current_state_ids.iteritems():
                etype, state_key = key
                if etype == EventTypes.Member:
                    prev_event_id = prev_state_ids.get(key, None)
                    if not prev_event_id or prev_event_id != event_id:
                        possibly_changed.add(state_key)

        users_who_share_room = yield self.store.get_users_who_share_room_with_user(
            user_id
        )

        # Take the intersection of the users whose devices may have changed
        # and those that actually still share a room with the user
        defer.returnValue(users_who_share_room & possibly_changed)

    @measure_func("_incoming_device_list_update")
    @defer.inlineCallbacks
    def _incoming_device_list_update(self, origin, edu_content):
        user_id = edu_content["user_id"]
        device_id = edu_content["device_id"]
        stream_id = edu_content["stream_id"]
        prev_ids = edu_content.get("prev_id", [])

        if get_domain_from_id(user_id) != origin:
            # TODO: Raise?
            logger.warning("Got device list update edu for %r from %r", user_id, origin)
            return

        rooms = yield self.store.get_rooms_for_user(user_id)
        if not rooms:
            # We don't share any rooms with this user. Ignore update, as we
            # probably won't get any further updates.
            return

        with (yield self._remote_edue_linearizer.queue(user_id)):
            # If the prev id matches whats in our cache table, then we don't need
            # to resync the users device list, otherwise we do.
            resync = True
            if len(prev_ids) == 1:
                extremity = yield self.store.get_device_list_last_stream_id_for_remote(
                    user_id
                )
                logger.info("Extrem: %r, prev_ids: %r", extremity, prev_ids)
                if str(extremity) == str(prev_ids[0]):
                    resync = False

            if resync:
                # Fetch all devices for the user.
                result = yield self.federation.query_user_devices(origin, user_id)
                stream_id = result["stream_id"]
                devices = result["devices"]
                yield self.store.update_remote_device_list_cache(
                    user_id, devices, stream_id,
                )
                device_ids = [device["device_id"] for device in devices]
                yield self.notify_device_update(user_id, device_ids)
            else:
                # Simply update the single device, since we know that is the only
                # change (becuase of the single prev_id matching the current cache)
                content = dict(edu_content)
                for key in ("user_id", "device_id", "stream_id", "prev_ids"):
                    content.pop(key, None)
                yield self.store.update_remote_device_list_cache_entry(
                    user_id, device_id, content, stream_id,
                )
                yield self.notify_device_update(user_id, [device_id])

    @defer.inlineCallbacks
    def on_federation_query_user_devices(self, user_id):
        stream_id, devices = yield self.store.get_devices_with_keys_by_user(user_id)
        defer.returnValue({
            "user_id": user_id,
            "stream_id": stream_id,
            "devices": devices,
        })

    @defer.inlineCallbacks
    def user_left_room(self, user, room_id):
        user_id = user.to_string()
        rooms = yield self.store.get_rooms_for_user(user_id)
        if not rooms:
            # We no longer share rooms with this user, so we'll no longer
            # receive device updates. Mark this in DB.
            yield self.store.mark_remote_user_device_list_as_unsubscribed(user_id)


def _update_device_from_client_ips(device, client_ips):
    ip = client_ips.get((device["user_id"], device["device_id"]), {})
    device.update({
        "last_seen_ts": ip.get("last_seen"),
        "last_seen_ip": ip.get("ip"),
    })
