# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import warnings
from io import StringIO

from mock import Mock

from pyperf import perf_counter
from synmark import make_homeserver

from synapse.util.caches.lrucache import LruCache
from synapse.logging._structured import setup_structured_logging


async def main(reactor, loops):
    """
    Benchmark `loops` number of insertions into LruCache where half of them are
    evicted.
    """
    cache = LruCache(loops // 2)

    start = perf_counter()

    for i in range(loops):
        cache[i] = True

    end = perf_counter() - start

    return end
