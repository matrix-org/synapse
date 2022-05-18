import re
from typing import Type

from pydantic import BaseModel
from pydantic.fields import ModelField


def string_length_between(lower: int, upper: int):
    def validator(cls: Type[BaseModel], value: str, field: ModelField) -> str:
        print(f"validate {lower=} {upper=} {value=}")
        if lower <= len(value) <= upper:
            print("ok")
            return value
        print("bad")
        raise ValueError(
            f"{field.name} must be between {lower} and {upper} characters long"
        )

    return validator


def string_contains_characters(charset: str):
    def validator(cls: Type[BaseModel], value: str, field: ModelField) -> str:
        pattern = f"^[{charset}]*$"
        if re.match(pattern, value):
            return value
        raise ValueError(
            f"{field.name} must be only contain the characters {charset}"
        )

    return validator
