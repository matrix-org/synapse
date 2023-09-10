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
    # Use the master/unstable branch of nixpkgs. Used to fetch the latest
    # available versions of packages.
    nixpkgs.url = "github:NixOS/nixpkgs/master";
    # Output a development shell for x86_64/aarch64 Linux/Darwin (MacOS).
    systems.url = "github:nix-systems/default";
    # A development environment manager built on Nix. See https://devenv.sh.
    devenv.url = "github:cachix/devenv/v0.6.3";
    # Rust toolchain.
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, devenv, systems, rust-overlay, ... } @ inputs:
    let
      forEachSystem = nixpkgs.lib.genAttrs (import systems);
    in {
      devShells = forEachSystem (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
        in {
          # Everything is configured via devenv - a Nix module for creating declarative
          # developer environments. See https://devenv.sh/reference/options/ for a list
          # of all possible options.
          default = devenv.lib.mkShell {
            inherit inputs pkgs;
            modules = [
              {
                # Make use of the Starship command prompt when this development environment
                # is manually activated (via `nix develop --impure`).
                # See https://starship.rs/ for details on the prompt itself.
                starship.enable = true;

                # Configure packages to install.
                # Search for package names at https://search.nixos.org/packages?channel=unstable
                packages = with pkgs; [
                  # The rust toolchain and related tools.
                  # This will install the "default" profile of rust components.
                  # https://rust-lang.github.io/rustup/concepts/profiles.html
                  #
                  # NOTE: We currently need to set the Rust version unnecessarily high
                  # in order to work around https://github.com/matrix-org/synapse/issues/15939
                  (rust-bin.stable."1.71.1".default.override {
                    # Additionally install the "rust-src" extension to allow diving into the
                    # Rust source code in an IDE (rust-analyzer will also make use of it).
                    extensions = [ "rust-src" ];
                  })
                  # The rust-analyzer language server implementation.
                  rust-analyzer

                  # GCC includes a linker; needed for building `ruff`
                  gcc
                  # Needed for building `ruff`
                  gnumake

                  # Native dependencies for running Synapse.
                  icu
                  libffi
                  libjpeg
                  libpqxx
                  libwebp
                  libxml2
                  libxslt
                  sqlite

                  # Native dependencies for unit tests (SyTest also requires OpenSSL).
                  openssl
                  xmlsec

                  # Native dependencies for running Complement.
                  olm

                  # For building the Synapse documentation website.
                  mdbook

                  # For releasing Synapse
                  debian-devscripts # (`dch` for manipulating the Debian changelog)
                  libnotify # (the release script uses `notify-send` to tell you when CI jobs are done)
                ];

                # Install Python and manage a virtualenv with Poetry.
                languages.python.enable = true;
                languages.python.poetry.enable = true;
                # Automatically activate the poetry virtualenv upon entering the shell.
                languages.python.poetry.activate.enable = true;
                # Install all extra Python dependencies; this is needed to run the unit
                # tests and utilitise all Synapse features.
                languages.python.poetry.install.arguments = ["--extras all"];
                # Install the 'matrix-synapse' package from the local checkout.
                languages.python.poetry.install.installRootPackage = true;

                # This is a work-around for NixOS systems. NixOS is special in
                # that you can have multiple versions of packages installed at
                # once, including your libc linker!
                #
                # Some binaries built for Linux expect those to be in a certain
                # filepath, but that is not the case on NixOS. In that case, we
                # force compiling those binaries locally instead.
                env.POETRY_INSTALLER_NO_BINARY = "ruff";

                # Install dependencies for the additional programming languages
                # involved with Synapse development.
                #
                # * Golang is needed to run the Complement test suite.
                # * Perl is needed to run the SyTest test suite.
                # * Rust is used for developing and running Synapse.
                #   It is installed manually with `packages` above.
                languages.go.enable = true;
                languages.perl.enable = true;

                # Postgres is needed to run Synapse with postgres support and
                # to run certain unit tests that require postgres.
                services.postgres.enable = true;

                # On the first invocation of `devenv up`, create a database for
                # Synapse to store data in.
                services.postgres.initdbArgs = ["--locale=C" "--encoding=UTF8"];
                services.postgres.initialDatabases = [
                  { name = "synapse"; }
                ];
                # Create a postgres user called 'synapse_user' which has ownership
                # over the 'synapse' database.
                services.postgres.initialScript = ''
                CREATE USER synapse_user;
                ALTER DATABASE synapse OWNER TO synapse_user;
                '';

                # Redis is needed in order to run Synapse in worker mode.
                services.redis.enable = true;

                # Configure and start Synapse. Before starting Synapse, this shell code:
                #  * generates a default homeserver.yaml config file if one does not exist, and
                #  * ensures a directory containing two additional homeserver config files exists;
                #    one to configure using the development environment's PostgreSQL as the
                #    database backend and another for enabling Redis support.
                process.before = ''
                  python -m synapse.app.homeserver -c homeserver.yaml --generate-config --server-name=synapse.dev --report-stats=no
                  mkdir -p homeserver-config-overrides.d
                  cat > homeserver-config-overrides.d/database.yaml << EOF
                  ## Do not edit this file. This file is generated by flake.nix
                  database:
                    name: psycopg2
                    args:
                      user: synapse_user
                      database: synapse
                      host: $PGHOST
                      cp_min: 5
                      cp_max: 10
                  EOF
                  cat > homeserver-config-overrides.d/redis.yaml << EOF
                  ## Do not edit this file. This file is generated by flake.nix
                  redis:
                    enabled: true
                  EOF
                '';
                # Start synapse when `devenv up` is run.
                processes.synapse.exec = "poetry run python -m synapse.app.homeserver -c homeserver.yaml -c homeserver-config-overrides.d";

                # Define the perl modules we require to run SyTest.
                #
                # This list was compiled by cross-referencing https://metacpan.org/
                # with the modules defined in './cpanfile' and then finding the
                # corresponding Nix packages on https://search.nixos.org/packages.
                #
                # This was done until `./install-deps.pl --dryrun` produced no output.
                env.PERL5LIB = "${with pkgs.perl536Packages; makePerlPath [
                  DBI
                  ClassMethodModifiers
                  CryptEd25519
                  DataDump
                  DBDPg
                  DigestHMAC
                  DigestSHA1
                  EmailAddressXS
                  EmailMIME
                  EmailSimple  # required by Email::Mime
                  EmailMessageID  # required by Email::Mime
                  EmailMIMEContentType  # required by Email::Mime
                  TextUnidecode  # required by Email::Mime
                  ModuleRuntime  # required by Email::Mime
                  EmailMIMEEncodings  # required by Email::Mime
                  FilePath
                  FileSlurper
                  Future
                  GetoptLong
                  HTTPMessage
                  IOAsync
                  IOAsyncSSL
                  IOSocketSSL
                  NetSSLeay
                  JSON
                  ListUtilsBy
                  ScalarListUtils
                  ModulePluggable
                  NetAsyncHTTP
                  MetricsAny  # required by Net::Async::HTTP
                  NetAsyncHTTPServer
                  StructDumb
                  URI
                  YAMLLibYAML
                ]}";

                # Clear the LD_LIBRARY_PATH environment variable on shell init.
                #
                # By default, devenv will set LD_LIBRARY_PATH to point to .devenv/profile/lib. This causes
                # issues when we include `gcc` as a dependency to build C libraries, as the version of glibc
                # that the development environment's cc compiler uses may differ from that of the system.
                #
                # When LD_LIBRARY_PATH is set, system tools will attempt to use the development environment's
                # libraries. Which, when built against a different glibc version lead, to "version 'GLIBC_X.YY'
                # not found" errors.
                enterShell = ''
                  unset LD_LIBRARY_PATH
                '';
              }
            ];
          };
        });
    };
}
