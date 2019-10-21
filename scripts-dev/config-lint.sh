#!/bin/bash
# Find linting errors in Synapse's default config file.
# Exits with 0 if there are no problems, or another code otherwise.

# Fix non-lowercase true/false values
sed -i -E "s/(#.*): +True/\1: true/g; s/(#.*): +False/\1: false/g;" synapse/config/*.py

# Check if anything changed
git diff --exit-code
