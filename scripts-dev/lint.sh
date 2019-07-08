#!/bin/sh

set -e

# Runs linting scripts over the local Synapse checkout
# isort - sorts import statements
# flake8 - lints and finds mistakes
# black - opinionated code formatter

isort -y -rc synapse tests scripts-dev scripts
flake8 synapse tests
python3 -m black synapse tests scripts-dev scripts
