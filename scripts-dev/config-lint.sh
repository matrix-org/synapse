#!/usr/bin/env bash
# Find linting errors in Synapse's default config file.
# Exits with 0 if there are no problems, or another code otherwise.

# cd to the root of the repository
cd "$(dirname "$0")/.." || exit

# Restore backup of sample config upon script exit
trap "mv docs/sample_config.yaml.bak docs/sample_config.yaml" EXIT

# Fix non-lowercase true/false values
sed -i.bak -E "s/: +True/: true/g; s/: +False/: false/g;" docs/sample_config.yaml

# Check if anything changed
diff docs/sample_config.yaml docs/sample_config.yaml.bak
