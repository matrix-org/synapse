#!/usr/bin/env bash

set -e

# CircleCI doesn't give CIRCLE_PR_NUMBER in the environment for non-forked PRs. Wonderful.
# In this case, we just need to do some ~shell magic~ to strip it out of the PULL_REQUEST URL.
echo 'export CIRCLE_PR_NUMBER="${CIRCLE_PR_NUMBER:-${CIRCLE_PULL_REQUEST##*/}}"' >> $BASH_ENV
source $BASH_ENV

if [[ -z "${CIRCLE_PR_NUMBER}" ]]
then
    echo "Can't figure out what the PR number is! Assuming merge target is dinsic."

    # It probably hasn't had a PR opened yet. Since all PRs for dinsic land on
    # dinsic, we can probably assume it's based on it and will be merged into
    # it.
    GITBASE="dinsic"
else
    # Get the reference, using the GitHub API
    GITBASE=`wget -O- https://api.github.com/repos/matrix-org/synapse-dinsic/pulls/${CIRCLE_PR_NUMBER} | jq -r '.base.ref'`
fi

# Show what we are before
git --no-pager show -s

# Set up username so it can do a merge
git config --global user.email bot@matrix.org
git config --global user.name "A robot"

# Fetch and merge. If it doesn't work, it will raise due to set -e.
git fetch -u origin $GITBASE
git merge --no-edit origin/$GITBASE

# Show what we are after.
git --no-pager show -s
