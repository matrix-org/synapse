#!/usr/bin/env python3
# This script will write a json file to $OUTPUT_FILE that contains the name of
# each available Synapse version with documentation.
#
# This script assumes that any top-level directory in the "gh-pages" branch is
# named after a documentation version and contains documentation website files.

import os.path
import json

OUTPUT_FILE = "versions.json"

# Determine the list of Synapse versions that have documentation.
doc_versions = []
for filepath in os.listdir():
    if os.path.isdir(filepath):
        doc_versions.append(filepath)

# Record the documentation versions in a json file, such that the
# frontend javascript is aware of what versions exist.
to_write = {
    "versions": doc_versions,
    "default_version": "latest",
}

# Write the file.
with open(OUTPUT_FILE, "w") as f:
    f.write(json.dumps(to_write))
