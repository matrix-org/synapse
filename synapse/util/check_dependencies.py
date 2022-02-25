import logging
from typing import List

from pkg_resources import (
    DistributionNotFound,
    Requirement,
    VersionConflict,
    get_provider,
)

from synapse.python_dependencies import CONDITIONAL_REQUIREMENTS, REQUIREMENTS


class DependencyException(Exception):
    @property
    def message(self):
        return "\n".join(
            [
                "Missing Requirements: %s" % (", ".join(self.dependencies),),
                "To install run:",
                "    pip install --upgrade --force %s" % (" ".join(self.dependencies),),
                "",
            ]
        )

    @property
    def dependencies(self):
        for i in self.args[0]:
            yield '"' + i + '"'


def check_requirements(for_feature=None):
    deps_needed = []
    errors = []

    if for_feature:
        reqs = CONDITIONAL_REQUIREMENTS[for_feature]
    else:
        reqs = REQUIREMENTS

    for dependency in reqs:
        try:
            _check_requirement(dependency)
        except VersionConflict as e:
            deps_needed.append(dependency)
            errors.append(
                "Needed %s, got %s==%s"
                % (
                    dependency,
                    e.dist.project_name,  # type: ignore[attr-defined] # noqa
                    e.dist.version,  # type: ignore[attr-defined] # noqa
                )
            )
        except DistributionNotFound:
            deps_needed.append(dependency)
            if for_feature:
                errors.append(
                    "Needed %s for the '%s' feature but it was not installed"
                    % (dependency, for_feature)
                )
            else:
                errors.append("Needed %s but it was not installed" % (dependency,))

    if not for_feature:
        # Check the optional dependencies are up to date. We allow them to not be
        # installed.
        OPTS: List[str] = sum(CONDITIONAL_REQUIREMENTS.values(), [])

        for dependency in OPTS:
            try:
                _check_requirement(dependency)
            except VersionConflict as e:
                deps_needed.append(dependency)
                errors.append(
                    "Needed optional %s, got %s==%s"
                    % (
                        dependency,
                        e.dist.project_name,  # type: ignore[attr-defined] # noqa
                        e.dist.version,  # type: ignore[attr-defined] # noqa
                    )
                )
            except DistributionNotFound:
                # If it's not found, we don't care
                pass

    if deps_needed:
        for err in errors:
            logging.error(err)

        raise DependencyException(deps_needed)


def _check_requirement(dependency_string):
    """Parses a dependency string, and checks if the specified requirement is installed

    Raises:
        VersionConflict if the requirement is installed, but with the the wrong version
        DistributionNotFound if nothing is found to provide the requirement
    """
    req = Requirement.parse(dependency_string)

    # first check if the markers specify that this requirement needs installing
    if req.marker is not None and not req.marker.evaluate():
        # not required for this environment
        return

    get_provider(req)
