#!/bin/sh
#
# Runs linting scripts over the local Synapse checkout
# isort - sorts import statements
# black - opinionated code formatter
# flake8 - lints and finds mistakes

set -e

if [ $# -ge 1 ]
then
  files=$*
else
  files="synapse tests scripts-dev scripts contrib synctl"
fi

echo "Linting these locations: $files"
isort $files
python3 -m black $files
./scripts-dev/config-lint.sh
flake8 $files
