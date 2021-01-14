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
import sys
from argparse import REMAINDER
from contextlib import redirect_stderr
from io import StringIO

import pyperf

from twisted.internet.defer import Deferred, ensureDeferred
from twisted.logger import globalLogBeginner, textFileLogObserver
from twisted.python.failure import Failure

from synmark import make_reactor
from synmark.suites import SUITES

from tests.utils import setupdb


def make_test(main):
    """
    Take a benchmark function and wrap it in a reactor start and stop.
    """

    def _main(loops):

        reactor = make_reactor()

        file_out = StringIO()
        with redirect_stderr(file_out):

            d = Deferred()
            d.addCallback(lambda _: ensureDeferred(main(reactor, loops)))

            def on_done(_):
                if isinstance(_, Failure):
                    _.printTraceback()
                    print(file_out.getvalue())
                reactor.stop()
                return _

            d.addBoth(on_done)
            reactor.callWhenRunning(lambda: d.callback(True))
            reactor.run()

        return d.result

    return _main


if __name__ == "__main__":

    def add_cmdline_args(cmd, args):
        if args.log:
            cmd.extend(["--log"])
        cmd.extend(args.tests)

    runner = pyperf.Runner(
        processes=3, min_time=1.5, show_name=True, add_cmdline_args=add_cmdline_args
    )
    runner.argparser.add_argument("--log", action="store_true")
    runner.argparser.add_argument("tests", nargs=REMAINDER)
    runner.parse_args()

    orig_loops = runner.args.loops
    runner.args.inherit_environ = ["SYNAPSE_POSTGRES"]

    if runner.args.worker:
        if runner.args.log:
            globalLogBeginner.beginLoggingTo(
                [textFileLogObserver(sys.__stdout__)], redirectStandardIO=False
            )
        setupdb()

    if runner.args.tests:
        SUITES = list(
            filter(lambda x: x[0].__name__.split(".")[-1] in runner.args.tests, SUITES)
        )

    for suite, loops in SUITES:
        if loops:
            runner.args.loops = loops
        else:
            runner.args.loops = orig_loops
            loops = "auto"
        runner.bench_time_func(
            suite.__name__ + "_" + str(loops), make_test(suite.main),
        )
