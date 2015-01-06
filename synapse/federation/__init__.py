# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

""" This package includes all the federation specific logic.
"""

from .replication import ReplicationLayer
from .transport import TransportLayer


def initialize_http_replication(homeserver):
    transport = TransportLayer(
        homeserver,
        homeserver.hostname,
        server=homeserver.get_resource_for_federation(),
        client=homeserver.get_http_client()
    )

    return ReplicationLayer(homeserver, transport)
