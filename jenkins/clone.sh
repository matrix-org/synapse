#! /bin/bash

NAME=$1
PROJECT=$2
BASE=".$NAME-base"

# update our clone
if [ ! -d .$NAME-base ]; then
  git clone $PROJECT $BASE --mirror
else
  (cd $BASE; git fetch -p)
fi

rm -rf $NAME
git clone $BASE $NAME --shared

: ${GIT_BRANCH:="origin/$(git rev-parse --abbrev-ref HEAD)"}
cd $NAME
# check out the relevant branch
git checkout "${GIT_BRANCH}" || (
    echo >&2 "No ref ${GIT_BRANCH} found, falling back to develop"
    git checkout "origin/develop"
)
git clean -df .
