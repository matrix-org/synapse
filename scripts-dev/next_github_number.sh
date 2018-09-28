#!/bin/bash

set -e

# Fetch the current GitHub issue number, add one to it -- presto! The likely
# next PR number.
CURRENT_NUMBER=`curl -s "https://api.github.com/repos/matrix-org/synapse/issues?state=all&per_page=1" | jq -r ".[0].number"`
CURRENT_NUMBER=$((CURRENT_NUMBER+1))
echo $CURRENT_NUMBER