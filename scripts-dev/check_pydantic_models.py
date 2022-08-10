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
"""
A script which enforces that Synapse always uses strict types when defining a Pydantic
model.

Pydantic does not yet offer a strict mode (), but it is expected for V2. See
    https://github.com/pydantic/pydantic/issues/1098
    https://pydantic-docs.helpmanual.io/blog/pydantic-v2/#strict-mode

until then, this script stops us from introducing type coersion bugs like stringy power
levels.
"""
import argparse
import contextlib
import functools
import importlib
import logging
import os
import pkgutil
import sys
import textwrap
import traceback
import unittest.mock
from contextlib import contextmanager
from typing import Callable, Generator, Set, Type, TypeVar

from parameterized import parameterized
from pydantic import BaseModel as PydanticBaseModel, conbytes, confloat, conint, constr
from typing_extensions import ParamSpec

logger = logging.getLogger(__name__)

CONSTRAINED_TYPE_FACTORIES_WITH_STRICT_FLAG = [
    constr,
    conbytes,
    conint,
    confloat,
]

TYPES_THAT_PYDANTIC_WILL_COERCE_TO = [
    str,
    bytes,
    int,
    float,
    bool,
]


P = ParamSpec("P")
R = TypeVar("R")


class NonStrictTypeError(Exception):
    ...


def make_wrapper(factory: Callable[P, R]) -> Callable[P, R]:
    @functools.wraps(factory)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        if "strict" not in kwargs:
            raise NonStrictTypeError()
        if not kwargs["strict"]:
            raise NonStrictTypeError()
        return factory(*args, **kwargs)

    return wrapper


class BaseModel(PydanticBaseModel):
    @classmethod
    def __init_subclass__(cls: Type[PydanticBaseModel], **kwargs):
        for field in cls.__fields__.values():
            if field.type_ in TYPES_THAT_PYDANTIC_WILL_COERCE_TO:
                raise NonStrictTypeError()
        # breakpoint()
        # print(cls, kwargs)


@contextmanager
def monkeypatch_pydantic() -> Generator[None, None, None]:
    with contextlib.ExitStack() as patches:
        patch_basemodel1 = unittest.mock.patch("pydantic.BaseModel", new=BaseModel)
        patch_basemodel2 = unittest.mock.patch("pydantic.main.BaseModel", new=BaseModel)
        patches.enter_context(patch_basemodel1)
        patches.enter_context(patch_basemodel2)
        for factory in CONSTRAINED_TYPE_FACTORIES_WITH_STRICT_FLAG:
            wrapper = make_wrapper(factory)
            patch1 = unittest.mock.patch(f"pydantic.{factory.__name__}", new=wrapper)
            patch2 = unittest.mock.patch(
                f"pydantic.types.{factory.__name__}", new=wrapper
            )
            patches.enter_context(patch1)
            patches.enter_context(patch2)
        yield


def format_error(e: Exception) -> str:
    frame_summary = traceback.extract_tb(e.__traceback__)[-2]
    return traceback.format_list([frame_summary])[0].lstrip()


def lint() -> int:
    failures = do_lint()
    if failures:
        print(f"Found {len(failures)} problem(s)")
    for failure in sorted(failures):
        print(failure)
    return os.EX_DATAERR if failures else os.EX_OK


def do_lint() -> Set[str]:
    failures = set()

    with monkeypatch_pydantic():
        try:
            synapse = importlib.import_module("synapse")
        except NonStrictTypeError as e:
            logger.warning("Bad annotation found when importing synapse")
            failures.add(format_error(e))
            return failures

        try:
            modules = list(pkgutil.walk_packages(synapse.__path__, "synapse."))
        except NonStrictTypeError as e:
            logger.warning("Bad annotation found when looking for modules to import")
            failures.add(format_error(e))
            return failures

        for module in modules:
            logger.debug("Importing %s", module.name)
            try:
                importlib.import_module(module.name)
            except NonStrictTypeError as e:
                logger.warning(f"Bad annotation found when importing {module.name}")
                failures.add(format_error(e))

    return failures


def run_test_snippet(source: str) -> None:
    # To emulate `source` being called at the top level of the module,
    # the globals and locals we provide apparently have to be the same mapping.
    #
    # > Remember that at the module level, globals and locals are the same dictionary.
    # > If exec gets two separate objects as globals and locals, the code will be
    # > executed as if it were embedded in a class definition.
    globals_ = locals_ = {}
    exec(textwrap.dedent(source), globals_, locals_)


class TestConstrainedTypesPatch(unittest.TestCase):
    def test_expression_without_strict_raises(self) -> None:
        with monkeypatch_pydantic(), self.assertRaises(NonStrictTypeError):
            run_test_snippet(
                """
                from pydantic import constr
                constr()
                """
            )

    def test_called_as_module_attribute_raises(self) -> None:
        with monkeypatch_pydantic(), self.assertRaises(NonStrictTypeError):
            run_test_snippet(
                """
                import pydantic
                pydantic.constr()
                """
            )

    def test_alternative_import_raises(self) -> None:
        with monkeypatch_pydantic(), self.assertRaises(NonStrictTypeError):
            run_test_snippet(
                """
                from pydantic.types import constr
                constr()
                """
            )

    def test_alternative_import_attribute_raises(self) -> None:
        with monkeypatch_pydantic(), self.assertRaises(NonStrictTypeError):
            run_test_snippet(
                """
                import pydantic.types
                pydantic.types.constr()
                """
            )

    def test_kwarg_but_no_strict_raises(self) -> None:
        with monkeypatch_pydantic(), self.assertRaises(NonStrictTypeError):
            run_test_snippet(
                """
                from pydantic import constr
                constr(min_length=10)
                """
            )

    def test_kwarg_strict_False_raises(self) -> None:
        with monkeypatch_pydantic(), self.assertRaises(NonStrictTypeError):
            run_test_snippet(
                """
                from pydantic import constr
                constr(strict=False)
                """
            )

    def test_kwarg_strict_True_doesnt_raise(self) -> None:
        with monkeypatch_pydantic():
            run_test_snippet(
                """
                from pydantic import constr
                constr(strict=True)
                """
            )

    def test_annotation_without_strict_raises(self) -> None:
        with monkeypatch_pydantic(), self.assertRaises(NonStrictTypeError):
            run_test_snippet(
                """
                from pydantic import constr
                x: constr()
                """
            )

    def test_field_annotation_without_strict_raises(self) -> None:
        with monkeypatch_pydantic(), self.assertRaises(NonStrictTypeError):
            run_test_snippet(
                """
                from pydantic import BaseModel, conint
                class C:
                    x: conint()
                """
            )


class TestMetaclassPatch(unittest.TestCase):
    @parameterized.expand(
        [
            ("str",),
            ("bytes"),
            ("int",),
            ("float",),
            ("bool"),
        ]
    )
    def test_field_holding_plain_value_type_raises(self, type_name: str) -> None:
        with monkeypatch_pydantic(), self.assertRaises(NonStrictTypeError):
            run_test_snippet(
                f"""
                from pydantic import BaseModel
                class C(BaseModel):
                    f: {type_name}
                """
            )

    def test_field_holding_str_raises_with_alternative_import(self) -> None:
        with monkeypatch_pydantic(), self.assertRaises(NonStrictTypeError):
            run_test_snippet(
                """
                from pydantic.main import BaseModel
                class C(BaseModel):
                    f: str
                """
            )


parser = argparse.ArgumentParser()
parser.add_argument("mode", choices=["lint", "test"])
parser.add_argument("-v", "--verbose", action="store_true")


if __name__ == "__main__":
    args = parser.parse_args(sys.argv[1:])
    logging.basicConfig(
        format="%(asctime)s %(name)s:%(lineno)d %(levelname)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )
    # suppress logs we don't care about
    logging.getLogger("xmlschema").setLevel(logging.WARNING)
    if args.mode == "lint":
        sys.exit(lint())
    elif args.mode == "test":
        unittest.main(argv=sys.argv[:1])
