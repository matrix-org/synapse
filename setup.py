#!/usr/bin/env python

# Copyright 2014-2017 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
# Copyright 2017-2018 New Vector Ltd
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

import glob
import os
from setuptools import setup, find_packages, Command
import sys


here = os.path.abspath(os.path.dirname(__file__))


# Some notes on `setup.py test`:
#
# Once upon a time we used to try to make `setup.py test` run `tox` to run the
# tests. That's a bad idea for three reasons:
#
# 1: `setup.py test` is supposed to find out whether the tests work in the
#    *current* environmentt, not whatever tox sets up.
# 2: Empirically, trying to install tox during the test run wasn't working ("No
#    module named virtualenv").
# 3: The tox documentation advises against it[1].
#
# Even further back in time, we used to use setuptools_trial [2]. That has its
# own set of issues: for instance, it requires installation of Twisted to build
# an sdist (because the recommended mode of usage is to add it to
# `setup_requires`). That in turn means that in order to successfully run tox
# you have to have the python header files installed for whichever version of
# python tox uses (which is python3 on recent ubuntus, for example).
#
# So, for now at least, we stick with what appears to be the convention among
# Twisted projects, and don't attempt to do anything when someone runs
# `setup.py test`; instead we direct people to run `trial` directly if they
# care.
#
# [1]: http://tox.readthedocs.io/en/2.5.0/example/basic.html#integration-with-setup-py-test-command
# [2]: https://pypi.python.org/pypi/setuptools_trial
class TestCommand(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        print ("""Synapse's tests cannot be run via setup.py. To run them, try:
     PYTHONPATH="." trial tests
""")

def read_file(path_segments):
    """Read a file from the package. Takes a list of strings to join to
    make the path"""
    file_path = os.path.join(here, *path_segments)
    with open(file_path) as f:
        return f.read()


def exec_file(path_segments):
    """Execute a single python file to get the variables defined in it"""
    result = {}
    code = read_file(path_segments)
    exec(code, result)
    return result


version = exec_file(("synapse", "__init__.py"))["__version__"]
dependencies = exec_file(("synapse", "python_dependencies.py"))
long_description = read_file(("README.rst",))

REQUIREMENTS = dependencies['REQUIREMENTS']
CONDITIONAL_REQUIREMENTS = dependencies['CONDITIONAL_REQUIREMENTS']
ALL_OPTIONAL_REQUIREMENTS = dependencies['ALL_OPTIONAL_REQUIREMENTS']

# Make `pip install matrix-synapse[all]` install all the optional dependencies.
CONDITIONAL_REQUIREMENTS["all"] = list(ALL_OPTIONAL_REQUIREMENTS)


setup(
    name="matrix-synapse",
    version=version,
    packages=find_packages(exclude=["tests", "tests.*"]),
    description="Reference homeserver for the Matrix decentralised comms protocol",
    install_requires=REQUIREMENTS,
    extras_require=CONDITIONAL_REQUIREMENTS,
    include_package_data=True,
    zip_safe=False,
    long_description=long_description,
    scripts=["synctl"] + glob.glob("scripts/*"),
    cmdclass={'test': TestCommand},
)
