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

Pydantic does not yet offer a strict mode, but it is planned for pydantic v2. See

    https://github.com/pydantic/pydantic/issues/1098
    https://pydantic-docs.helpmanual.io/blog/pydantic-v2/#strict-mode

until then, this script is a best effort to stop us from introducing type coersion bugs
(like the infamous stringy power levels fixed in room version 10).
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
from typing import Any, Callable, Generator, Set, Type, TypeVar, List, Dict

from parameterized import parameterized
from pydantic import BaseModel as PydanticBaseModel, conbytes, confloat, conint, constr
from pydantic.typing import get_args
from typing_extensions import ParamSpec

logger = logging.getLogger(__name__)

CONSTRAINED_TYPE_FACTORIES_WITH_STRICT_FLAG: List[Callable] = [
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
        # type-ignore: should be redundant once we can use https://github.com/python/mypy/pull/12668
        if "strict" not in kwargs:  # type: ignore[attr-defined]
            raise NonStrictTypeError()
        if not kwargs["strict"]:  # type: ignore[index]
            raise NonStrictTypeError()
        return factory(*args, **kwargs)

    return wrapper


def field_type_unwanted(type_: Any) -> bool:
    logger.debug("Is %s unwanted?")
    if type_ in TYPES_THAT_PYDANTIC_WILL_COERCE_TO:
        logger.debug("yes")
        return True
    logger.debug("Maybe. Subargs are %s", get_args(type_))
    rv = any(field_type_unwanted(t) for t in get_args(type_))
    logger.debug("Conclusion: %s %s unwanted", type_, "is" if rv else "is not")
    return rv


class PatchedBaseModel(PydanticBaseModel):
    """Try to detect fields whose

    ModelField.type_ is presumably private, so this is likely to be very brittle.
    """

    @classmethod
    def __init_subclass__(cls: Type[PydanticBaseModel], **kwargs: object):
        for field in cls.__fields__.values():
            # Note that field.type_ and field.outer_type are computed based on the
            # annotation type, see pydantic.fields.ModelField._type_analysis
            if field_type_unwanted(field.outer_type_):
                raise NonStrictTypeError()


@contextmanager
def monkeypatch_pydantic() -> Generator[None, None, None]:
    with contextlib.ExitStack() as patches:
        patch_basemodel1 = unittest.mock.patch(
            "pydantic.BaseModel", new=PatchedBaseModel
        )
        patch_basemodel2 = unittest.mock.patch(
            "pydantic.main.BaseModel", new=PatchedBaseModel
        )
        patches.enter_context(patch_basemodel1)
        patches.enter_context(patch_basemodel2)
        for factory in CONSTRAINED_TYPE_FACTORIES_WITH_STRICT_FLAG:
            wrapper: Callable = make_wrapper(factory)
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
    globals_: Dict[str, object]
    locals_: Dict[str, object]
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

    def test_wildcard_import_raises(self) -> None:
        with monkeypatch_pydantic(), self.assertRaises(NonStrictTypeError):
            run_test_snippet(
                """
                from pydantic import *
                constr()
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


class TestFieldTypeInspection(unittest.TestCase):
    @parameterized.expand(
        [
            ("str",),
            ("bytes"),
            ("int",),
            ("float",),
            ("bool"),
            ("Optional[str]",),
            ("Union[None, str]",),
            ("List[str]",),
            ("List[List[str]]",),
            ("Dict[StrictStr, str]",),
            ("Dict[str, StrictStr]",),
            ("TypedDict('D', x=int)",),
        ]
    )
    def test_field_holding_unwanted_type_raises(self, annotation: str) -> None:
        with monkeypatch_pydantic(), self.assertRaises(NonStrictTypeError):
            run_test_snippet(
                f"""
                from typing import *
                from pydantic import *
                class C(BaseModel):
                    f: {annotation}
                """
            )

    @parameterized.expand(
        [
            ("StrictStr",),
            ("StrictBytes"),
            ("StrictInt",),
            ("StrictFloat",),
            ("StrictBool"),
            ("constr(strict=True, min_length=10)",),
            ("Optional[StrictStr]",),
            ("Union[None, StrictStr]",),
            ("List[StrictStr]",),
            ("List[List[StrictStr]]",),
            ("Dict[StrictStr, StrictStr]",),
            ("TypedDict('D', x=StrictInt)",),
        ]
    )
    def test_field_holding_accepted_type_raises(self, annotation: str) -> None:
        with monkeypatch_pydantic():
            run_test_snippet(
                f"""
                from typing import *
                from pydantic import *
                class C(BaseModel):
                    f: {annotation}
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
parser.add_argument("mode", choices=["lint", "test"], default="lint")
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
