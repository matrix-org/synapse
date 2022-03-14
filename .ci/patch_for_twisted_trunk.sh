#!/bin/sh

# replaces the dependency on Twisted with Twisted's trunk.
# We make full use of the poetry machinery (rather than just `pip install ...`)
# so that we'll catch dependency resolver problems that could arise from twisted
# bumping its dependencies.

set -xe
cd "$(dirname "$0")"/..

sed -ibackup -e 's!^Twisted = .*!Twisted = { git = "https://github.com/twisted/twisted.git", rev = "trunk" }!' pyproject.toml

poetry lock --no-update
poetry install --no-interaction --extras "all test"
# Confirm the version of twisted in use
poetry run pip show twisted
