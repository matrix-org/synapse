#!/usr/bin/env bash
#
# Update/check the docs/sample_config.yaml

set -e

cd "$(dirname "$0")/.."

SAMPLE_CONFIG="docs/sample_config.yaml"
SAMPLE_LOG_CONFIG="docs/sample_log_config.yaml"

check() {
    diff -u "$SAMPLE_LOG_CONFIG" <(synapse/_scripts/generate_log_config.py) >/dev/null || return 1
}

if [ "$1" == "--check" ]; then
    diff -u "$SAMPLE_CONFIG" <(synapse/_scripts/generate_config.py --header-file docs/.sample_config_header.yaml) >/dev/null || {
        echo -e "\e[1m\e[31m$SAMPLE_CONFIG is not up-to-date. Regenerate it with \`scripts-dev/generate_sample_config.sh\`.\e[0m" >&2
        exit 1
    }
    diff -u "$SAMPLE_LOG_CONFIG" <(synapse/_scripts/generate_log_config.py) >/dev/null || {
        echo -e "\e[1m\e[31m$SAMPLE_LOG_CONFIG is not up-to-date. Regenerate it with \`scripts-dev/generate_sample_config.sh\`.\e[0m" >&2
        exit 1
    }
else
    synapse/_scripts/generate_config.py --header-file docs/.sample_config_header.yaml -o "$SAMPLE_CONFIG"
    synapse/_scripts/generate_log_config.py -o "$SAMPLE_LOG_CONFIG"
fi
