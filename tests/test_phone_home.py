# Copyright 2019 Matrix.org Foundation C.I.C.
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

import resource
from unittest import mock

from synapse.app.phone_stats_home import phone_stats_home
from synapse.types import JsonDict

from tests.unittest import HomeserverTestCase


class PhoneHomeStatsTestCase(HomeserverTestCase):
    def test_performance_frozen_clock(self) -> None:
        """
        If time doesn't move, don't error out.
        """
        past_stats = [
            (self.hs.get_clock().time(), resource.getrusage(resource.RUSAGE_SELF))
        ]
        stats: JsonDict = {}
        self.get_success(phone_stats_home(self.hs, stats, past_stats))
        self.assertEqual(stats["cpu_average"], 0)

    def test_performance_100(self) -> None:
        """
        1 second of usage over 1 second is 100% CPU usage.
        """
        real_res = resource.getrusage(resource.RUSAGE_SELF)
        old_resource = mock.Mock(spec=real_res)
        old_resource.ru_utime = real_res.ru_utime - 1
        old_resource.ru_stime = real_res.ru_stime
        old_resource.ru_maxrss = real_res.ru_maxrss

        past_stats = [(self.hs.get_clock().time(), old_resource)]
        stats: JsonDict = {}
        self.reactor.advance(1)
        # `old_resource` has type `Mock` instead of `struct_rusage`
        self.get_success(phone_stats_home(self.hs, stats, past_stats))  # type: ignore[arg-type]
        self.assertApproximates(stats["cpu_average"], 100, tolerance=2.5)
