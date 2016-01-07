#!/usr/bin/env python

# Copyright 2014-2016 OpenMarket Ltd
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


class Tox(Command):
    user_options = [('tox-args=', 'a', "Arguments to pass to tox")]

    def initialize_options(self):
        self.tox_args = None

    def finalize_options(self):
        self.test_args = []
        self.test_suite = True

    def run(self):
        #import here, cause outside the eggs aren't loaded
        try:
            import tox
        except ImportError:
            try:
                self.distribution.fetch_build_eggs("tox")
                import tox
            except:
                raise RuntimeError(
                    "The tests need 'tox' to run. Please install 'tox'."
                )
        import shlex
        args = self.tox_args
        if args:
            args = shlex.split(self.tox_args)
        else:
            args = []
        errno = tox.cmdline(args=args)
        sys.exit(errno)


version = exec_file(("synapse", "__init__.py"))["__version__"]
dependencies = exec_file(("synapse", "python_dependencies.py"))
long_description = read_file(("README.rst",))

setup(
    name="matrix-synapse",
    version=version,
    packages=find_packages(exclude=["tests", "tests.*"]),
    description="Reference Synapse Home Server",
    install_requires=dependencies['requirements'](include_conditional=True).keys(),
    dependency_links=dependencies["DEPENDENCY_LINKS"].values(),
    include_package_data=True,
    zip_safe=False,
    long_description=long_description,
    scripts=["synctl"] + glob.glob("scripts/*"),
    cmdclass={'test': Tox},
)
