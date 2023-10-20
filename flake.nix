# A Nix flake that sets up a complete Synapse development environment. Dependencies
# for the SyTest (https://github.com/matrix-org/sytest) and Complement
# (https://github.com/matrix-org/complement) Matrix homeserver test suites are also
# installed automatically.
#
# You must have already installed Nix (https://nixos.org) on your system to use this.
# Nix can be installed on Linux or MacOS; NixOS is not required. Windows is not
# directly supported, but Nix can be installed inside of WSL2 or even Docker
# containers. Please refer to https://nixos.org/download for details.
#
# You must also enable support for flakes in Nix. See the following for how to
# do so permanently: https://nixos.wiki/wiki/Flakes#Enable_flakes
#
# Be warned: you'll need over 3.75 GB of free space to download all the dependencies.
#
# Usage:
#
# With Nix installed, navigate to the directory containing this flake and run
# `nix develop --impure`. The `--impure` is necessary in order to store state
# locally from "services", such as PostgreSQL and Redis.
#
# You should now be dropped into a new shell with all programs and dependencies
# availabile to you!
#
# You can start up pre-configured local Synapse, PostgreSQL and Redis instances by
# running: `devenv up`. To stop them, use Ctrl-C.
#
# All state (the venv, postgres and redis data and config) are stored in
# .devenv/state. Deleting a file from here and then re-entering the shell
# will recreate these files from scratch.
#
# You can exit the development shell by typing `exit`, or using Ctrl-D.
#
# If you would like this development environment to activate automatically
# upon entering this directory in your terminal, first install `direnv`
# (https://direnv.net/). Then run `echo 'use flake . --impure' >> .envrc` at
# the root of the Synapse repo. Finally, run `direnv allow .` to allow the
# contents of '.envrc' to run every time you enter this directory. Voilà!

{
  inputs = {
    # A repository of nix development environment flakes.
    element-nix-flakes.url = "github:vector-im/nix-flakes";
  };

  outputs = { self, element-nix-flakes, ... }:
    {
      # Use the `composeShell` function provided by nix-flakes
      # and specify the projects we'd like dependencies for.
      devShells = element-nix-flakes.outputs.composeShell [
        "complement"
        "synapse"
        "sytest"
      ];
    };
}
