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
from synapse.util import stringutils
from twisted.internet import defer
from ._base import BaseHandler

import logging

logger = logging.getLogger(__name__)


class DeviceHandler(BaseHandler):
    def __init__(self, hs):
        super(DeviceHandler, self).__init__(hs)

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
            yield self.store.store_device(
                user_id=user_id,
                device_id=device_id,
                initial_device_display_name=initial_device_display_name,
                ignore_if_known=True,
            )
            defer.returnValue(device_id)

        # if the device id is not specified, we'll autogen one, but loop a few
        # times in case of a clash.
        attempts = 0
        while attempts < 5:
            try:
                device_id = stringutils.random_string_with_symbols(16)
                yield self.store.store_device(
                    user_id=user_id,
                    device_id=device_id,
                    initial_device_display_name=initial_device_display_name,
                    ignore_if_known=False,
                )
                defer.returnValue(device_id)
            except errors.StoreError:
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
        except errors.StoreError, e:
            if e.code == 404:
                raise errors.NotFoundError()
            else:
                raise


def _update_device_from_client_ips(device, client_ips):
    ip = client_ips.get((device["user_id"], device["device_id"]), {})
    device.update({
        "last_seen_ts": ip.get("last_seen"),
        "last_seen_ip": ip.get("ip"),
    })
