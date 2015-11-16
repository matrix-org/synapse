#!/bin/bash -eu

export PYTHONDONTWRITEBYTECODE=yep
TOXSUFFIX="--reporter=subunit | subunit-1to2 | subunit2junitxml --no-passthrough --output-to=results.xml" tox
