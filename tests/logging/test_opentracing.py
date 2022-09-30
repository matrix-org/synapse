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

from typing import cast

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
    tag_args,
    trace_with_opname,
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

import logging

from tests.unittest import TestCase

logger = logging.getLogger(__name__)


class LogContextScopeManagerTestCase(TestCase):
    """
    Test logging contexts and active opentracing spans.

    There's casts throughout this from generic opentracing objects (e.g.
    opentracing.Span) to the ones specific to Jaeger since they have additional
    properties that these tests depend on. This is safe since the only supported
    opentracing backend is Jaeger.
    """

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
            span = cast(jaeger_client.Span, scope.span)
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
                root_context = cast(jaeger_client.SpanContext, root_scope.span.context)

                scope1 = start_active_span(
                    "child1",
                    tracer=self._tracer,
                )
                self.assertEqual(
                    self._tracer.active_span, scope1.span, "child1 was not activated"
                )
                context1 = cast(jaeger_client.SpanContext, scope1.span.context)
                self.assertEqual(context1.parent_id, root_context.span_id)

                scope2 = start_active_span_follows_from(
                    "child2",
                    contexts=(scope1,),
                    tracer=self._tracer,
                )
                self.assertEqual(self._tracer.active_span, scope2.span)
                context2 = cast(jaeger_client.SpanContext, scope2.span.context)
                self.assertEqual(context2.parent_id, context1.span_id)

                with scope1, scope2:
                    pass

                # the root scope should be restored
                self.assertEqual(self._tracer.active_span, root_scope.span)
                span2 = cast(jaeger_client.Span, scope2.span)
                span1 = cast(jaeger_client.Span, scope1.span)
                self.assertIsNotNone(span2.end_time)
                self.assertIsNotNone(span1.end_time)

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

    def test_trace_decorator_sync(self) -> None:
        """
        Test whether we can use `@trace_with_opname` (`@trace`) and `@tag_args`
        with sync functions
        """
        with LoggingContext("root context"):

            @trace_with_opname("fixture_sync_func", tracer=self._tracer)
            @tag_args
            def fixture_sync_func() -> str:
                return "foo"

            result = fixture_sync_func()
            self.assertEqual(result, "foo")

        # the span should have been reported
        self.assertEqual(
            [span.operation_name for span in self._reporter.get_spans()],
            ["fixture_sync_func"],
        )

    def test_trace_decorator_deferred(self) -> None:
        """
        Test whether we can use `@trace_with_opname` (`@trace`) and `@tag_args`
        with functions that return deferreds
        """
        reactor = MemoryReactorClock()

        with LoggingContext("root context"):

            @trace_with_opname("fixture_deferred_func", tracer=self._tracer)
            @tag_args
            def fixture_deferred_func() -> "defer.Deferred[str]":
                d1: defer.Deferred[str] = defer.Deferred()
                d1.callback("foo")
                return d1

            result_d1 = fixture_deferred_func()

            # let the tasks complete
            reactor.pump((2,) * 8)

            self.assertEqual(self.successResultOf(result_d1), "foo")

        # the span should have been reported
        self.assertEqual(
            [span.operation_name for span in self._reporter.get_spans()],
            ["fixture_deferred_func"],
        )

    def test_trace_decorator_async(self) -> None:
        """
        Test whether we can use `@trace_with_opname` (`@trace`) and `@tag_args`
        with async functions
        """
        reactor = MemoryReactorClock()

        with LoggingContext("root context"):

            @trace_with_opname("fixture_async_func", tracer=self._tracer)
            @tag_args
            async def fixture_async_func() -> str:
                return "foo"

            d1 = defer.ensureDeferred(fixture_async_func())

            # let the tasks complete
            reactor.pump((2,) * 8)

            self.assertEqual(self.successResultOf(d1), "foo")

        # the span should have been reported
        self.assertEqual(
            [span.operation_name for span in self._reporter.get_spans()],
            ["fixture_async_func"],
        )
