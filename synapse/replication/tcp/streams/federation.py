# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
# Copyright 2019 New Vector Ltd
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
from collections import namedtuple

from synapse.replication.tcp.streams._base import Stream, db_query_to_update_function


class FederationStream(Stream):
    """Data to be sent over federation. Only available when master has federation
    sending disabled.
    """

    FederationStreamRow = namedtuple(
        "FederationStreamRow",
        (
            "type",  # str, the type of data as defined in the BaseFederationRows
            "data",  # dict, serialization of a federation.send_queue.BaseFederationRow
        ),
    )

    NAME = "federation"
    ROW_TYPE = FederationStreamRow

    def __init__(self, hs):
        # Not all synapse instances will have a federation sender instance,
        # whether that's a `FederationSender` or a `FederationRemoteSendQueue`,
        # so we stub the stream out when that is the case.
        if hs.config.worker_app is None or hs.should_send_federation():
            federation_sender = hs.get_federation_sender()
            current_token = federation_sender.get_current_token
            update_function = db_query_to_update_function(
                federation_sender.get_replication_rows
            )
        else:
            current_token = lambda: 0
            update_function = self._stub_update_function

        super().__init__(hs.get_instance_name(), current_token, update_function)

    @staticmethod
    async def _stub_update_function(instance_name, from_token, upto_token, limit):
        return [], upto_token, False
