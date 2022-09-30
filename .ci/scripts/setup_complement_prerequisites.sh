#!/bin/sh
#
# Common commands to set up Complement's prerequisites in a GitHub Actions CI run.
#
# Must be called after Synapse has been checked out to `synapse/`.
#
set -eu

alias block='{ set +x; } 2>/dev/null; func() { echo "::group::$*"; set -x; }; func'
alias endblock='{ set +x; } 2>/dev/null; func() { echo "::endgroup::"; set -x; }; func'

block Set Go Version
  # The path is set via a file given by $GITHUB_PATH. We need both Go 1.17 and GOPATH on the path to run Complement.
  # See https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#adding-a-system-path

  # Add Go 1.17 to the PATH: see https://github.com/actions/virtual-environments/blob/main/images/linux/Ubuntu2004-Readme.md#environment-variables-2
  echo "$GOROOT_1_17_X64/bin" >> $GITHUB_PATH
  # Add the Go path to the PATH: We need this so we can call gotestfmt
  echo "~/go/bin" >> $GITHUB_PATH
endblock

block Install Complement Dependencies
  sudo apt-get -qq update && sudo apt-get install -qqy libolm3 libolm-dev
  go get -v github.com/haveyoudebuggedit/gotestfmt/v2/cmd/gotestfmt@latest
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
