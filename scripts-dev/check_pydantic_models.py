#! /usr/bin/env python
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
import argparse
import contextlib
import functools
import sys
import textwrap
import unittest.mock
from contextlib import contextmanager
from typing import Generator, Any

from pydantic import confloat, conint, conbytes, constr

CONSTRAINED_TYPE_FACTORIES_WITH_STRICT_FLAG = [
    constr,
    conbytes,
    conint,
    confloat,
]


@contextmanager
def monkeypatch_pydantic() -> Generator[None, None, None]:
    with contextlib.ExitStack() as patches:
        for factory in CONSTRAINED_TYPE_FACTORIES_WITH_STRICT_FLAG:

            @functools.wraps(factory)
            def wrapper(**kwargs: object) -> Any:
                assert "strict" in kwargs
                assert kwargs["strict"]
                return factory(**kwargs)

            patch1 = unittest.mock.patch(f"pydantic.{factory.__name__}", new=wrapper)
            patch2 = unittest.mock.patch(
                f"pydantic.types.{factory.__name__}", new=wrapper
            )
            patches.enter_context(patch1)
            patches.enter_context(patch2)
        yield


def run_test_snippet(source: str) -> None:
    exec(textwrap.dedent(source), {}, {})


class TestConstrainedTypesPatch(unittest.TestCase):
    def test_expression_without_strict_raises(self):
        with monkeypatch_pydantic(), self.assertRaises(Exception):
            run_test_snippet(
                """
                from pydantic import constr
                constr()
                """
            )

    def test_called_as_module_attribute_raises(self):
        with monkeypatch_pydantic(), self.assertRaises(Exception):
            run_test_snippet(
                """
                import pydantic
                pydantic.constr()
                """
            )

    def test_alternative_import_raises(self):
        with monkeypatch_pydantic(), self.assertRaises(Exception):
            run_test_snippet(
                """
                from pydantic.types import constr
                constr()
                """
            )

    def test_alternative_import_attribute_raises(self):
        with monkeypatch_pydantic(), self.assertRaises(Exception):
            run_test_snippet(
                """
                import pydantic.types
                pydantic.types.constr()
                """
            )

    def test_kwarg_but_no_strict_raises(self):
        with monkeypatch_pydantic(), self.assertRaises(Exception):
            run_test_snippet(
                """
                from pydantic import constr
                constr(min_length=10)
                """
            )

    def test_kwarg_strict_False_raises(self):
        with monkeypatch_pydantic(), self.assertRaises(Exception):
            run_test_snippet(
                """
                from pydantic import constr
                constr(strict=False)
                """
            )

    def test_kwarg_strict_True_doesnt_raise(self):
        with monkeypatch_pydantic():
            run_test_snippet(
                """
                from pydantic import constr
                constr(strict=True)
                """
            )

    def test_annotation_without_strict_raises(self):
        with monkeypatch_pydantic(), self.assertRaises(Exception):
            run_test_snippet(
                """
                from pydantic import constr
                x: constr()
                """
            )

    def test_field_annotation_without_strict_raises(self):
        with monkeypatch_pydantic(), self.assertRaises(Exception):
            run_test_snippet(
                """
                from pydantic import BaseModel, constr
                class C(BaseModel):
                    f: constr()
                """
            )


parser = argparse.ArgumentParser()
parser.add_argument("mode", choices=["lint", "test"])


if __name__ == "__main__":
    args = parser.parse_args(sys.argv[1:])
    if args.mode == "lint":
        ...
    elif args.mode == "test":
        unittest.main(argv=sys.argv[:1])
