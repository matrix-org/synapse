#!/bin/sh

# replaces the dependency on Twisted in `python_dependencies` with trunk.

set -e
cd "$(dirname "$0")"/..

sed -i -e 's#"Twisted.*"#"Twisted @ git+https://github.com/twisted/twisted"#' synapse/python_dependencies.py
