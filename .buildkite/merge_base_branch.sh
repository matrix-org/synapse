#!/usr/bin/env bash

set -e

if [[ "$BUILDKITE_BRANCH" =~ ^(develop|master|dinsic|shhs|release-.*)$ ]]; then
    echo "Not merging forward, as this is a release branch"
    exit 0
fi

if [[ -z $BUILDKITE_PULL_REQUEST_BASE_BRANCH ]]; then
    echo "Not a pull request, or hasn't had a PR opened yet..."

    # It probably hasn't had a PR opened yet. Since all PRs land on develop, we
    # can probably assume it's based on it and will be merged into it.
    GITBASE="develop"
else
    # Get the reference, using the GitHub API
    GITBASE=$BUILDKITE_PULL_REQUEST_BASE_BRANCH
fi

echo "--- merge_base_branch $GITBASE"

# Show what we are before
git --no-pager show -s

# Set up username so it can do a merge
git config --global user.email bot@matrix.org
git config --global user.name "A robot"

# Fetch and merge. If it doesn't work, it will raise due to set -e.
git fetch -u origin $GITBASE
git merge --no-edit --no-commit origin/$GITBASE

# Show what we are after.
git --no-pager show -s
