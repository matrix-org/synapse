#! /bin/bash

# This clones a project from github into a named subdirectory
# If the project has a branch with the same name as this branch
# then it will checkout that branch after cloning.
# Otherwise it will checkout "origin/develop."
# The first argument is the name of the directory to checkout
# the branch into.
# The second argument is the URL of the remote repository to checkout.
# Usually something like https://github.com/matrix-org/sytest.git

set -eux

NAME=$1
PROJECT=$2
BASE=".$NAME-base"

# Update our mirror.
if [ ! -d ".$NAME-base" ]; then
  # Create a local mirror of the source repository.
  # This saves us from having to download the entire repository
  # when this script is next run.
  git clone "$PROJECT" "$BASE" --mirror
else
  # Fetch any updates from the source repository.
  (cd "$BASE"; git fetch -p)
fi

# Remove the existing repository so that we have a clean copy
rm -rf "$NAME"
# Cloning with --shared means that we will share portions of the
# .git directory with our local mirror.
git clone "$BASE" "$NAME" --shared

# Jenkins may have supplied us with the name of the branch in the
# environment. Otherwise we will have to guess based on the current
# commit.
: ${GIT_BRANCH:="origin/$(git rev-parse --abbrev-ref HEAD)"}
cd "$NAME"
# check out the relevant branch
git checkout "${GIT_BRANCH}" || (
    echo >&2 "No ref ${GIT_BRANCH} found, falling back to develop"
    git checkout "origin/develop"
)
