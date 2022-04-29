from tests import unittest


class RustTestCase(unittest.TestCase):
    def test_basic(self):
        from synapse.synapse_rust import sum_as_string

        result = sum_as_string(1, 2)
        self.assertEqual("3", result)
