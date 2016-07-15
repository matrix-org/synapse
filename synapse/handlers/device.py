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
from synapse.api.errors import StoreError
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
                                initial_device_display_name):
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
            except StoreError:
                attempts += 1

        raise StoreError(500, "Couldn't generate a device ID.")
