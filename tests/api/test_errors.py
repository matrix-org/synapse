import json

from synapse.api.errors import LimitExceededError

from tests.unittest import TestCase


class LimitExceededErrorTestCase(TestCase):
    def test_key_appears_in_context_but_not_error_dict(self) -> None:
        err = LimitExceededError("needle")
        serialised = json.dumps(err.error_dict(None))
        self.assertIn("needle", err.debug_context)
        self.assertNotIn("needle", serialised)
