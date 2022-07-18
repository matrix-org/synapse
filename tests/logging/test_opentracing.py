# Copyright 2022 The Matrix.org Foundation C.I.C.
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

from twisted.internet import defer
from twisted.test.proto_helpers import MemoryReactorClock

from synapse.logging.context import (
    LoggingContext,
    make_deferred_yieldable,
    run_in_background,
)
from synapse.logging.opentracing import (
    start_active_span,
    start_active_span_follows_from,
)
from synapse.util import Clock

try:
    from synapse.logging.scopecontextmanager import LogContextScopeManager
except ImportError:
    LogContextScopeManager = None  # type: ignore

try:
    import jaeger_client
except ImportError:
    jaeger_client = None  # type: ignore

from tests.unittest import TestCase


class LogContextScopeManagerTestCase(TestCase):
    if LogContextScopeManager is None:
        skip = "Requires opentracing"  # type: ignore[unreachable]
    if jaeger_client is None:
        skip = "Requires jaeger_client"  # type: ignore[unreachable]

    def setUp(self) -> None:
        # since this is a unit test, we don't really want to mess around with the
        # global variables that power opentracing. We create our own tracer instance
        # and test with it.

        scope_manager = LogContextScopeManager()
        config = jaeger_client.config.Config(
            config={}, service_name="test", scope_manager=scope_manager
        )

        self._reporter = jaeger_client.reporter.InMemoryReporter()

        self._tracer = config.create_tracer(
            sampler=jaeger_client.ConstSampler(True),
            reporter=self._reporter,
        )

    def test_start_active_span(self) -> None:
        # the scope manager assumes a logging context of some sort.
        with LoggingContext("root context"):
            self.assertIsNone(self._tracer.active_span)

            # start_active_span should start and activate a span.
            scope = start_active_span("span", tracer=self._tracer)
            span = scope.span
            self.assertEqual(self._tracer.active_span, span)
            self.assertIsNotNone(span.start_time)

            # entering the context doesn't actually do a whole lot.
            with scope as ctx:
                self.assertIs(ctx, scope)
                self.assertEqual(self._tracer.active_span, span)

            # ... but leaving it unsets the active span, and finishes the span.
            self.assertIsNone(self._tracer.active_span)
            self.assertIsNotNone(span.end_time)

        # the span should have been reported
        self.assertEqual(self._reporter.get_spans(), [span])

    def test_nested_spans(self) -> None:
        """Starting two spans off inside each other should work"""

        with LoggingContext("root context"):
            with start_active_span("root span", tracer=self._tracer) as root_scope:
                self.assertEqual(self._tracer.active_span, root_scope.span)

                scope1 = start_active_span(
                    "child1",
                    tracer=self._tracer,
                )
                self.assertEqual(
                    self._tracer.active_span, scope1.span, "child1 was not activated"
                )
                self.assertEqual(
                    scope1.span.context.parent_id, root_scope.span.context.span_id
                )

                scope2 = start_active_span_follows_from(
                    "child2",
                    contexts=(scope1,),
                    tracer=self._tracer,
                )
                self.assertEqual(self._tracer.active_span, scope2.span)
                self.assertEqual(
                    scope2.span.context.parent_id, scope1.span.context.span_id
                )

                with scope1, scope2:
                    pass

                # the root scope should be restored
                self.assertEqual(self._tracer.active_span, root_scope.span)
                self.assertIsNotNone(scope2.span.end_time)
                self.assertIsNotNone(scope1.span.end_time)

            self.assertIsNone(self._tracer.active_span)

        # the spans should be reported in order of their finishing.
        self.assertEqual(
            self._reporter.get_spans(), [scope2.span, scope1.span, root_scope.span]
        )

    def test_overlapping_spans(self) -> None:
        """Overlapping spans which are not neatly nested should work"""
        reactor = MemoryReactorClock()
        clock = Clock(reactor)

        scopes = []

        async def task(i: int):
            scope = start_active_span(
                f"task{i}",
                tracer=self._tracer,
            )
            scopes.append(scope)

            self.assertEqual(self._tracer.active_span, scope.span)
            await clock.sleep(4)
            self.assertEqual(self._tracer.active_span, scope.span)
            scope.close()

        async def root():
            with start_active_span("root span", tracer=self._tracer) as root_scope:
                self.assertEqual(self._tracer.active_span, root_scope.span)
                scopes.append(root_scope)

                d1 = run_in_background(task, 1)
                await clock.sleep(2)
                d2 = run_in_background(task, 2)

                # because we did run_in_background, the active span should still be the
                # root.
                self.assertEqual(self._tracer.active_span, root_scope.span)

                await make_deferred_yieldable(
                    defer.gatherResults([d1, d2], consumeErrors=True)
                )

                self.assertEqual(self._tracer.active_span, root_scope.span)

        with LoggingContext("root context"):
            # start the test off
            d1 = defer.ensureDeferred(root())

            # let the tasks complete
            reactor.pump((2,) * 8)

            self.successResultOf(d1)
            self.assertIsNone(self._tracer.active_span)

        # the spans should be reported in order of their finishing: task 1, task 2,
        # root.
        self.assertEqual(
            self._reporter.get_spans(),
            [scopes[1].span, scopes[2].span, scopes[0].span],
        )
