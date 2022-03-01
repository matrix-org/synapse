from contextlib import contextmanager
from typing import Generator, Optional
from unittest.mock import patch

from synapse.util.check_dependencies import (
    DependencyException,
    check_requirements,
    metadata,
)

from tests.unittest import TestCase


class DummyDistribution(metadata.Distribution):
    def __init__(self, version: str):
        self._version = version

    @property
    def version(self):
        return self._version

    def locate_file(self, path):
        raise NotImplementedError()

    def read_text(self, filename):
        raise NotImplementedError()


old = DummyDistribution("0.1.2")
new = DummyDistribution("1.2.3")

# could probably use stdlib TestCase --- no need for twisted here


class TestDependencyChecker(TestCase):
    @contextmanager
    def mock_installed_package(
        self, distribution: Optional[DummyDistribution]
    ) -> Generator[None, None, None]:
        """Pretend that looking up any distribution yields the given `distribution`."""

        def mock_distribution(name: str):
            if distribution is None:
                raise metadata.PackageNotFoundError
            else:
                return distribution

        with patch(
            "synapse.util.check_dependencies.metadata.distribution",
            mock_distribution,
        ):
            yield

    def test_mandatory_dependency(self) -> None:
        """Complain if a required package is missing or old."""
        with patch(
            "synapse.util.check_dependencies.metadata.requires",
            return_value=["dummypkg >= 1"],
        ):
            with self.mock_installed_package(None):
                self.assertRaises(DependencyException, check_requirements)
            with self.mock_installed_package(old):
                self.assertRaises(DependencyException, check_requirements)
            with self.mock_installed_package(new):
                # should not raise
                check_requirements()

    def test_generic_check_of_optional_dependency(self) -> None:
        """Complain if an optional package is old."""
        with patch(
            "synapse.util.check_dependencies.metadata.requires",
            return_value=["dummypkg >= 1; extra == 'cool-extra'"],
        ):
            with self.mock_installed_package(None):
                # should not raise
                check_requirements()
            with self.mock_installed_package(old):
                self.assertRaises(DependencyException, check_requirements)
            with self.mock_installed_package(new):
                # should not raise
                check_requirements()

    def test_check_for_extra_dependencies(self) -> None:
        """Complain if a package required for an extra is missing or old."""
        with patch(
            "synapse.util.check_dependencies.metadata.requires",
            return_value=["dummypkg >= 1; extra == 'cool-extra'"],
        ), patch("synapse.util.check_dependencies.EXTRAS", {"cool-extra"}):
            with self.mock_installed_package(None):
                self.assertRaises(DependencyException, check_requirements, "cool-extra")
            with self.mock_installed_package(old):
                self.assertRaises(DependencyException, check_requirements, "cool-extra")
            with self.mock_installed_package(new):
                # should not raise
                check_requirements()
