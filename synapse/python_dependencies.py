# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
# Copyright 2018 New Vector Ltd
# Copyright 2020 The Matrix.org Foundation C.I.C.
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

import itertools
import logging
from typing import List, Set

from pkg_resources import (
    DistributionNotFound,
    Requirement,
    VersionConflict,
    get_provider,
)

logger = logging.getLogger(__name__)


# REQUIREMENTS is a simple list of requirement specifiers[1], and must be
# installed. It is passed to setup() as install_requires in setup.py.
#
# CONDITIONAL_REQUIREMENTS is the optional dependencies, represented as a dict
# of lists. The dict key is the optional dependency name and can be passed to
# pip when installing. The list is a series of requirement specifiers[1] to be
# installed when that optional dependency requirement is specified. It is passed
# to setup() as extras_require in setup.py
#
# Note that these both represent runtime dependencies (and the versions
# installed are checked at runtime).
#
# Also note that we replicate these constraints in the Synapse Dockerfile while
# pre-installing dependencies. If these constraints are updated here, the same
# change should be made in the Dockerfile.
#
# [1] https://pip.pypa.io/en/stable/reference/pip_install/#requirement-specifiers.

REQUIREMENTS = [
    "jsonschema>=2.5.1",
    "frozendict>=1",
    "unpaddedbase64>=1.1.0",
    "canonicaljson>=1.4.0",
    # we use the type definitions added in signedjson 1.1.
    "signedjson>=1.1.0",
    "pynacl>=1.2.1",
    "idna>=2.5",
    # validating SSL certs for IP addresses requires service_identity 18.1.
    "service_identity>=18.1.0",
    # Twisted 18.9 introduces some logger improvements that the structured
    # logger utilises
    "Twisted>=18.9.0",
    "treq>=15.1",
    # Twisted has required pyopenssl 16.0 since about Twisted 16.6.
    "pyopenssl>=16.0.0",
    "pyyaml>=3.11",
    "pyasn1>=0.1.9",
    "pyasn1-modules>=0.0.7",
    "bcrypt>=3.1.0",
    "pillow>=4.3.0",
    "sortedcontainers>=1.4.4",
    "pymacaroons>=0.13.0",
    "msgpack>=0.5.2",
    "phonenumbers>=8.2.0",
    # we use GaugeHistogramMetric, which was added in prom-client 0.4.0.
    "prometheus_client>=0.4.0",
    # we use attr.validators.deep_iterable, which arrived in 19.1.0 (Note:
    # Fedora 31 only has 19.1, so if we want to upgrade we should wait until 33
    # is out in November.)
    # Note: 21.1.0 broke `/sync`, see #9936
    "attrs>=19.1.0,!=21.1.0",
    "netaddr>=0.7.18",
    "Jinja2>=2.9",
    "bleach>=1.4.3",
    "typing-extensions>=3.7.4",
    # We enforce that we have a `cryptography` version that bundles an `openssl`
    # with the latest security patches.
    "cryptography>=3.4.7",
    "ijson>=3.0",
]

CONDITIONAL_REQUIREMENTS = {
    "matrix-synapse-ldap3": ["matrix-synapse-ldap3>=0.1"],
    "postgres": [
        # we use execute_values with the fetch param, which arrived in psycopg 2.8.
        "psycopg2>=2.8 ; platform_python_implementation != 'PyPy'",
        "psycopg2cffi>=2.8 ; platform_python_implementation == 'PyPy'",
        "psycopg2cffi-compat==1.1 ; platform_python_implementation == 'PyPy'",
    ],
    # ACME support is required to provision TLS certificates from authorities
    # that use the protocol, such as Let's Encrypt.
    "acme": [
        "txacme>=0.9.2",
    ],
    "saml2": [
        "pysaml2>=4.5.0",
    ],
    "oidc": ["authlib>=0.14.0"],
    # systemd-python is necessary for logging to the systemd journal via
    # `systemd.journal.JournalHandler`, as is documented in
    # `contrib/systemd/log_config.yaml`.
    "systemd": ["systemd-python>=231"],
    "url_preview": ["lxml>=3.5.0"],
    "sentry": ["sentry-sdk>=0.7.2"],
    "opentracing": ["jaeger-client>=4.0.0", "opentracing>=2.2.0"],
    "jwt": ["pyjwt>=1.6.4"],
    # hiredis is not a *strict* dependency, but it makes things much faster.
    # (if it is not installed, we fall back to slow code.)
    "redis": ["txredisapi>=1.4.7", "hiredis"],
    # Required to use experimental `caches.track_memory_usage` config option.
    "cache_memory": ["pympler"],
}

ALL_OPTIONAL_REQUIREMENTS = set()  # type: Set[str]

for name, optional_deps in CONDITIONAL_REQUIREMENTS.items():
    # Exclude systemd as it's a system-based requirement.
    # Exclude lint as it's a dev-based requirement.
    if name not in ["systemd"]:
        ALL_OPTIONAL_REQUIREMENTS = set(optional_deps) | ALL_OPTIONAL_REQUIREMENTS


# ensure there are no double-quote characters in any of the deps (otherwise the
# 'pip install' incantation in DependencyException will break)
for dep in itertools.chain(
    REQUIREMENTS,
    *CONDITIONAL_REQUIREMENTS.values(),
):
    if '"' in dep:
        raise Exception(
            "Dependency `%s` contains double-quote; use single-quotes instead" % (dep,)
        )


def list_requirements():
    return list(set(REQUIREMENTS) | ALL_OPTIONAL_REQUIREMENTS)


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
        OPTS = sum(CONDITIONAL_REQUIREMENTS.values(), [])  # type: List[str]

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


if __name__ == "__main__":
    import sys

    sys.stdout.writelines(req + "\n" for req in list_requirements())
