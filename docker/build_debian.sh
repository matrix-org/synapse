#!/bin/bash

# The script to build the Debian package, as ran inside the Docker image.

set -ex

# Get the codename from distro env
DIST=`cut -d ':' -f2 <<< $distro`

# we get a read-only copy of the source: make a writeable copy
cp -aT /synapse/source /synapse/build
cd /synapse/build

# add an entry to the changelog for this distribution
dch -M -l "+$DIST" "build for $DIST"
dch -M -r "" --force-distribution --distribution "$DIST"

dpkg-buildpackage -us -uc

ls -l ..

# copy the build results out, setting perms if necessary
shopt -s nullglob
for i in ../*.deb ../*.dsc ../*.tar.xz ../*.changes ../*.buildinfo; do
    [ -z "$TARGET_USERID" ] || chown "$TARGET_USERID" "$i"
    [ -z "$TARGET_GROUPID" ] || chgrp "$TARGET_GROUPID" "$i"
    mv "$i" /debs
done
