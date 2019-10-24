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

import pyperf

from twisted.python import reflect

from synapse.benchmarks import setupdb
from synapse.benchmarks.suites import SUITES

if __name__ == "__main__":

    runner = pyperf.Runner(processes=5, values=1, warmups=0)
    runner.parse_args()
    runner.args.inherit_environ = ["SYNAPSE_POSTGRES"]

    for suite, loops in SUITES:

        func = reflect.namedAny("synapse.benchmarks.suites.%s.main" % (suite.lower(),))
        runner.args.loops = loops
        runner.bench_time_func(suite + "_" + str(loops), func)
