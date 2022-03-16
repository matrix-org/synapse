#!/bin/sh

# replaces the dependency on Twisted with Twisted's trunk.

set -xe
cd "$(dirname "$0")"/..

# We could make full use of the poetry machinery (rather than just `pip install ...`)
# so that we can catch dependency resolver problems that could arise from twisted
# bumping its dependencies...
# sed -ibackup -e 's!^Twisted = .*!Twisted = { git = "https://github.com/twisted/twisted.git", rev = "trunk" }!' pyproject.toml
# poetry lock --no-update
# poetry install --no-interaction --extras "all test"

# ...except we run into https://github.com/python-poetry/poetry/issues/5311, where
# poetry insists on installing an old version of treq, which isn't actually compatible
# with recent twisted releases. So let's just install twisted trunk using pip.
poetry install --no-interaction --extras "all test"
poetry run pip install git+https://github.com/twisted/twisted.git@trunk

# Confirm the version of twisted in use
poetry run pip show twisted
