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
from argparse import REMAINDER, Namespace
from contextlib import redirect_stderr
from io import StringIO
from typing import Any, Callable, Coroutine, List, TypeVar

import pyperf

from twisted.internet.defer import Deferred, ensureDeferred
from twisted.logger import globalLogBeginner, textFileLogObserver
from twisted.python.failure import Failure

from synapse.types import ISynapseReactor
from synmark import make_reactor
from synmark.suites import SUITES

from tests.utils import setupdb

T = TypeVar("T")


def make_test(
    main: Callable[[ISynapseReactor, int], Coroutine[Any, Any, float]]
) -> Callable[[int], float]:
    """
    Take a benchmark function and wrap it in a reactor start and stop.
    """

    def _main(loops: int) -> float:
        reactor = make_reactor()

        file_out = StringIO()
        with redirect_stderr(file_out):
            d: "Deferred[float]" = Deferred()
            d.addCallback(lambda _: ensureDeferred(main(reactor, loops)))

            def on_done(res: T) -> T:
                if isinstance(res, Failure):
                    res.printTraceback()
                    print(file_out.getvalue())
                reactor.stop()
                return res

            d.addBoth(on_done)
            reactor.callWhenRunning(lambda: d.callback(True))
            reactor.run()

        # mypy thinks this is an object for some reason.
        return d.result  # type: ignore[return-value]

    return _main


if __name__ == "__main__":

    def add_cmdline_args(cmd: List[str], args: Namespace) -> None:
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
        existing_suites = {s.__name__.split(".")[-1] for s, _ in SUITES}
        for test in runner.args.tests:
            if test not in existing_suites:
                print(f"Test suite {test} does not exist.")
                exit(-1)

        suites = list(
            filter(lambda t: t[0].__name__.split(".")[-1] in runner.args.tests, SUITES)
        )
    else:
        suites = SUITES

    for suite, loops in suites:
        if loops:
            runner.args.loops = loops
            loops_desc = str(loops)
        else:
            runner.args.loops = orig_loops
            loops_desc = "auto"
        runner.bench_time_func(
            suite.__name__ + "_" + loops_desc,
            make_test(suite.main),
        )
