{ inputs, pkgs, ... }:

{
  # Configure packages to install.
  # Search for package names at https://search.nixos.org/packages?channel=unstable
  packages = with pkgs; [
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

    # Native dependencies for running Complement.
    olm

    # Development tools.
    poetry
  ];

  # Activate (and create if necessary) a poetry virtualenv on startup.
  enterShell = ''
    . "$(dirname $(poetry run which python))/activate"
  '';

  # Install dependencies for the additional programming languages
  # involved with Synapse development. Python is already available
  # from poetry's virtual environment.
  #
  # * Rust is used for developing and running Synapse.
  # * Golang is needed to run the Complement test suite.
  # * Perl is needed to run the SyTest test suite.
  languages.go.enable = true;
  languages.rust.enable = true;
  languages.rust.version = "latest";
  languages.perl.enable = true;

  # Postgres is needed to run Synapse with postgres support and
  # to run certain unit tests that require postgres.
  services.postgres.enable = true;

  # On the first invocation of `devenv up`, create a database for
  # Syanpse to store data in.
  services.postgres.initdbArgs = ["--locale=C" "--encoding=UTF8"];
  services.postgres.initialDatabases = [
    { name = "synapse"; }
  ];

  # Redis is needed in order to run Synapse in worker mode.
  services.redis.enable = true;

  # We wrap `poetry` with a bash script that disables the download
  # of binary wheels for certain packages if the user is running
  # NixOS. NixOS is special in that you can have multiple versions
  # of packages installed at once, including your libc linker!
  #
  # Some binaries built for Linux expect those to be in a certain
  # filepath, but that is not the case on NixOS. In that case, we
  # force compiling those binaries locally instead.
  scripts.poetry.exec = ''
  if [ -z "$__NIXOS_SET_ENVIRONMENT_DONE" ]; then
    # We are running on NixOS.
    #
    # Prevent poetry from downloading known problematic,
    # dynamically-linked binaries for python dependencies.
    POETRY_INSTALLER_NO_BINARY=ruff ${pkgs.poetry}/bin/poetry $@
  else
    ${pkgs.poetry}/bin/poetry $@
  fi
  '';

  # Define the perl modules we require to run SyTest.
  #
  # This list was compiled by cross-referencing https://metacpan.org/
  # with the modules defined in './cpanfile' and then finding the
  # corresponding nix packages on https://search.nixos.org/packages.
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

}
