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

from synapse.storage.util.id_generators import _load_current_id


class SlavedIdTracker(object):
    def __init__(self, db_conn, table, column, extra_tables=[], step=1):
        self.step = step
        self._current = _load_current_id(db_conn, table, column, step)
        for table, column in extra_tables:
            self.advance(_load_current_id(db_conn, table, column))

    def advance(self, new_id):
        self._current = (max if self.step > 0 else min)(self._current, new_id)

    def get_current_token(self):
        return self._current
