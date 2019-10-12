#!/bin/bash
# Find linting errors in Synapse's default config file.
# Exits with 0 if there are no problems, or another code otherwise.

# Fix non-lowercase true/false values
sed -i -E "s/(#.*): +True(.*)/\1: true\2/g; s/(#.*): +False(.*)/\1: false\2/g;" synapse/config/*.py

# Check if anything changed
git diff --quiet
