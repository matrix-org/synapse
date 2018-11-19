#!/bin/bash

set -e

dpkg-buildpackage -us -uc -b
cp ../*.deb /build/debs