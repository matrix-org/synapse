#!/usr/bin/env python

# Copyright 2014 OpenMarket Ltd
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

import os
from setuptools import setup, find_packages


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name="matrix-synapse",
    version=read("VERSION").strip(),
    packages=find_packages(exclude=["tests", "tests.*"]),
    description="Reference Synapse Home Server",
    install_requires=[
        "syutil==0.0.2",
        "matrix_angular_sdk>=0.6.1",
        "Twisted>=14.0.0",
        "service_identity>=1.0.0",
        "pyopenssl>=0.14",
        "pyyaml",
        "pyasn1",
        "pynacl",
        "daemonize",
        "py-bcrypt",
        "frozendict>=0.4",
        "pillow",
    ],
    dependency_links=[
        "https://github.com/matrix-org/syutil/tarball/v0.0.2#egg=syutil-0.0.2",
        "https://github.com/pyca/pynacl/tarball/d4d3175589b892f6ea7c22f466e0e223853516fa#egg=pynacl-0.3.0",
        "https://github.com/matrix-org/matrix-angular-sdk/tarball/v0.6.1/#egg=matrix_angular_sdk-0.6.1",
    ],
    setup_requires=[
        "setuptools_trial",
        "setuptools>=1.0.0", # Needs setuptools that supports git+ssh.
                             # TODO: Do we need this now? we don't use git+ssh.
        "mock"
    ],
    include_package_data=True,
    zip_safe=False,
    long_description=read("README.rst"),
    entry_points="""
    [console_scripts]
    synctl=synapse.app.synctl:main
    synapse-homeserver=synapse.app.homeserver:main
    """
)
