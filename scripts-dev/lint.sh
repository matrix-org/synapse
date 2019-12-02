#!/bin/sh
#
# Runs linting scripts over the local Synapse checkout
# isort - sorts import statements
# flake8 - lints and finds mistakes
# black - opinionated code formatter

set -e

if [ $# -ge 1 ]
then
  files=$*
else
  files="synapse tests scripts-dev scripts"
fi

echo "Linting these locations: $files"
isort -y -rc $files
flake8 $files
python3 -m black $files
./scripts-dev/config-lint.sh
