#!/bin/bash

# The script to build the Debian package, as ran inside the Docker image.

set -e

dpkg-buildpackage -us -uc -b

cp ../*.deb /synapse/build/debs
