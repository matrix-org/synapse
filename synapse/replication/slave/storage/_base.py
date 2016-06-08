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

from synapse.storage._base import SQLBaseStore
from twisted.internet import defer


class BaseSlavedStore(SQLBaseStore):
    def __init__(self, db_conn, hs):
        super(BaseSlavedStore, self).__init__(hs)

    def stream_positions(self):
        return {}

    def process_replication(self, result):
        return defer.succeed(None)
