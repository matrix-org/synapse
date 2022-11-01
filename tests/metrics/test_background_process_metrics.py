from unittest import TestCase as StdlibTestCase
from unittest.mock import Mock

from synapse.logging.context import ContextResourceUsage, LoggingContext
from synapse.metrics.background_process_metrics import _BackgroundProcess


class TestBackgroundProcessMetrics(StdlibTestCase):
    def test_update_metrics_with_negative_time_diff(self) -> None:
        """We should ignore negative reported utime and stime differences"""
        usage = ContextResourceUsage()
        usage.ru_stime = usage.ru_utime = -1.0

        mock_logging_context = Mock(spec=LoggingContext)
        mock_logging_context.get_resource_usage.return_value = usage

        process = _BackgroundProcess("test process", mock_logging_context)
        # Should not raise
        process.update_metrics()
