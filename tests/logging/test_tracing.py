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

import logging
from typing import cast

from twisted.internet import defer
from twisted.test.proto_helpers import MemoryReactorClock

from synapse.logging.context import (
    LoggingContext,
    make_deferred_yieldable,
    run_in_background,
)
from synapse.logging.tracing import start_active_span
from synapse.util import Clock

logger = logging.getLogger(__name__)

try:
    import opentelemetry
    import opentelemetry.sdk.trace
    import opentelemetry.sdk.trace.export
    import opentelemetry.sdk.trace.export.in_memory_span_exporter
    import opentelemetry.trace
    import opentelemetry.trace.propagation
except ImportError:
    opentelemetry = None  # type: ignore[assignment]

from tests.unittest import TestCase


class LogContextScopeManagerTestCase(TestCase):
    """
    Test logging contexts and active opentelemetry spans.
    """

    if opentelemetry is None:
        skip = "Requires opentelemetry"  # type: ignore[unreachable]

    def setUp(self) -> None:
        # since this is a unit test, we don't really want to mess around with the
        # global variables that power opentracing. We create our own tracer instance
        # and test with it.

        self._tracer_provider = opentelemetry.sdk.trace.TracerProvider()

        self._exporter = (
            opentelemetry.sdk.trace.export.in_memory_span_exporter.InMemorySpanExporter()
        )
        processor = opentelemetry.sdk.trace.export.SimpleSpanProcessor(self._exporter)
        self._tracer_provider.add_span_processor(processor)

        self._tracer = self._tracer_provider.get_tracer(__name__)

    def test_start_active_span(self) -> None:
        # This means no current span
        self.assertEqual(
            opentelemetry.trace.get_current_span(), opentelemetry.trace.INVALID_SPAN
        )

        # start_active_span should start and activate a span.
        with start_active_span("new-span", tracer=self._tracer) as span:
            self.assertEqual(opentelemetry.trace.get_current_span(), span)
            self.assertIsNotNone(span.start_time)

        # ... but leaving it unsets the active span, and finishes the span.
        self.assertEqual(
            opentelemetry.trace.get_current_span(), opentelemetry.trace.INVALID_SPAN
        )
        self.assertIsNotNone(span.end_time)

        # the span should have been reported
        self.assertListEqual(
            [span.name for span in self._exporter.get_finished_spans()], ["new-span"]
        )

    def test_nested_spans(self) -> None:
        """Starting two spans off inside each other should work"""
        with start_active_span("root_span", tracer=self._tracer) as root_span:
            self.assertEqual(opentelemetry.trace.get_current_span(), root_span)
            root_context = root_span.get_span_context()

            with start_active_span(
                "child_span1",
                tracer=self._tracer,
            ) as child_span1:
                self.assertEqual(
                    opentelemetry.trace.get_current_span(),
                    child_span1,
                    "child_span1 was not activated",
                )
                self.assertEqual(child_span1.parent.span_id, root_context.span_id)

            ctx1 = opentelemetry.trace.propagation.set_span_in_context(child_span1)
            with start_active_span(
                "child_span2",
                context=ctx1,
                tracer=self._tracer,
            ) as child_span2:
                self.assertEqual(opentelemetry.trace.get_current_span(), child_span2)
                self.assertEqual(
                    child_span2.parent.span_id, child_span1.get_span_context().span_id
                )

            # the root scope should be restored
            self.assertEqual(opentelemetry.trace.get_current_span(), root_span)
            self.assertIsNotNone(child_span1.end_time)
            self.assertIsNotNone(child_span2.end_time)

        # Active span is unset outside of the with scopes
        self.assertEqual(
            opentelemetry.trace.get_current_span(), opentelemetry.trace.INVALID_SPAN
        )

        # the spans should be reported in order of their finishing.
        self.assertEqual(
            self._reporter.get_spans(), [scope2.span, scope1.span, root_scope.span]
        )

    # def test_overlapping_spans(self) -> None:
    #     """Overlapping spans which are not neatly nested should work"""
    #     reactor = MemoryReactorClock()
    #     clock = Clock(reactor)

    #     scopes = []

    #     async def task(i: int):
    #         scope = start_active_span(
    #             f"task{i}",
    #             tracer=self._tracer,
    #         )
    #         scopes.append(scope)

    #         self.assertEqual(self._tracer.active_span, scope.span)
    #         await clock.sleep(4)
    #         self.assertEqual(self._tracer.active_span, scope.span)
    #         scope.close()

    #     async def root():
    #         with start_active_span("root span", tracer=self._tracer) as root_scope:
    #             self.assertEqual(self._tracer.active_span, root_scope.span)
    #             scopes.append(root_scope)

    #             d1 = run_in_background(task, 1)
    #             await clock.sleep(2)
    #             d2 = run_in_background(task, 2)

    #             # because we did run_in_background, the active span should still be the
    #             # root.
    #             self.assertEqual(self._tracer.active_span, root_scope.span)

    #             await make_deferred_yieldable(
    #                 defer.gatherResults([d1, d2], consumeErrors=True)
    #             )

    #             self.assertEqual(self._tracer.active_span, root_scope.span)

    #     with LoggingContext("root context"):
    #         # start the test off
    #         d1 = defer.ensureDeferred(root())

    #         # let the tasks complete
    #         reactor.pump((2,) * 8)

    #         self.successResultOf(d1)
    #         self.assertIsNone(self._tracer.active_span)

    #     # the spans should be reported in order of their finishing: task 1, task 2,
    #     # root.
    #     self.assertEqual(
    #         self._reporter.get_spans(),
    #         [scopes[1].span, scopes[2].span, scopes[0].span],
    #     )
