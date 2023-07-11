#!/bin/sh
#
# Common commands to set up Complement's prerequisites in a GitHub Actions CI run.
#
# Must be called after Synapse has been checked out to `synapse/`.
#
set -eu

alias block='{ set +x; } 2>/dev/null; func() { echo "::group::$*"; set -x; }; func'
alias endblock='{ set +x; } 2>/dev/null; func() { echo "::endgroup::"; set -x; }; func'

block Install Complement Dependencies
  sudo apt-get -qq update && sudo apt-get install -qqy libolm3 libolm-dev
  go install -v github.com/gotesttools/gotestfmt/v2/cmd/gotestfmt@latest
endblock

block Install custom gotestfmt template
  mkdir .gotestfmt/github -p
  cp synapse/.ci/complement_package.gotpl .gotestfmt/github/package.gotpl
endblock

block Check out Complement
  # Attempt to check out the same branch of Complement as the PR. If it
  # doesn't exist, fallback to HEAD.
  synapse/.ci/scripts/checkout_complement.sh
endblock
