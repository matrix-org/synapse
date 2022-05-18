from unittest import TestCase

from pydantic import BaseModel, ValidationError, validator, StrictStr

from synapse.config.validators import string_length_between, string_contains_characters


class TestValidators(TestCase):
    def test_string_length_between(self) -> None:
        class TestModel(BaseModel):
            x: StrictStr
            _x_length = validator("x")(string_length_between(5, 10))

        with self.assertRaises(ValidationError):
            TestModel(x="")
        with self.assertRaises(ValidationError):
            TestModel(x="a" * 4)

        # Should not raise:
        TestModel(x="a" * 5)
        TestModel(x="a" * 10)

        with self.assertRaises(ValidationError):
            TestModel(x="a" * 11)
        with self.assertRaises(ValidationError):
            TestModel(x="a" * 1000)

    def test_string_contains_characters(self) -> None:
        class TestModel(BaseModel):
            x: StrictStr
            _x_characters = validator("x")(string_contains_characters("A-Z0-9"))

        # Should not raise
        TestModel(x="")
        TestModel(x="A")
        TestModel(x="B")
        TestModel(x="Z")
        TestModel(x="123456789")

        with self.assertRaises(ValidationError):
            TestModel(x="---")
        with self.assertRaises(ValidationError):
            TestModel(x="$")
        with self.assertRaises(ValidationError):
            TestModel(x="A$")
        with self.assertRaises(ValidationError):
            TestModel(x="a")
        with self.assertRaises(ValidationError):
            TestModel(x="\u0000")
        with self.assertRaises(ValidationError):
            TestModel(x="☃")

