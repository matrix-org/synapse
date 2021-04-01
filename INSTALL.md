# Installation Instructions

There are 3 steps to follow under **Installation Instructions**.

- [Installation Instructions](#installation-instructions)
  - [Choosing your server name](#choosing-your-server-name)
  - [Installing Synapse](#installing-synapse)
    - [Installing from source](#installing-from-source)
      - [Platform-specific prerequisites](#platform-specific-prerequisites)
        - [Debian/Ubuntu/Raspbian](#debianubunturaspbian)
        - [ArchLinux](#archlinux)
        - [CentOS/Fedora](#centosfedora)
        - [macOS](#macos)
        - [OpenSUSE](#opensuse)
        - [OpenBSD](#openbsd)
        - [Windows](#windows)
    - [Prebuilt packages](#prebuilt-packages)
      - [Docker images and Ansible playbooks](#docker-images-and-ansible-playbooks)
      - [Debian/Ubuntu](#debianubuntu)
        - [Matrix.org packages](#matrixorg-packages)
        - [Downstream Debian packages](#downstream-debian-packages)
        - [Downstream Ubuntu packages](#downstream-ubuntu-packages)
      - [Fedora](#fedora)
      - [OpenSUSE](#opensuse-1)
      - [SUSE Linux Enterprise Server](#suse-linux-enterprise-server)
      - [ArchLinux](#archlinux-1)
      - [Void Linux](#void-linux)
      - [FreeBSD](#freebsd)
      - [OpenBSD](#openbsd-1)
      - [NixOS](#nixos)
  - [Setting up Synapse](#setting-up-synapse)
    - [Using PostgreSQL](#using-postgresql)
    - [TLS certificates](#tls-certificates)
    - [Client Well-Known URI](#client-well-known-uri)
    - [Email](#email)
    - [Registering a user](#registering-a-user)
    - [Setting up a TURN server](#setting-up-a-turn-server)
    - [URL previews](#url-previews)
    - [Troubleshooting Installation](#troubleshooting-installation)


## Choosing your server name

It is important to choose the name for your server before you install Synapse,
because it cannot be changed later.

The server name determines the "domain" part of user-ids for users on your
server: these will all be of the format `@user:my.domain.name`. It also
determines how other matrix servers will reach yours for federation.

For a test configuration, set this to the hostname of your server. For a more
production-ready setup, you will probably want to specify your domain
(`example.com`) rather than a matrix-specific hostname here (in the same way
that your email address is probably `user@example.com` rather than
`user@email.example.com`) - but doing so may require more advanced setup: see
[Setting up Federation](docs/federate.md).

## Installing Synapse

### Installing from source

(Prebuilt packages are available for some platforms - see [Prebuilt packages](#prebuilt-packages).)

When installing from source please make sure that the [Platform-specific prerequisites](#platform-specific-prerequisites) are already installed.

System requirements:

- POSIX-compliant system (tested on Linux & OS X)
- Python 3.5.2 or later, up to Python 3.9.
- At least 1GB of free RAM if you want to join large public rooms like #matrix:matrix.org


To install the Synapse homeserver run:

```sh
mkdir -p ~/synapse
virtualenv -p python3 ~/synapse/env
source ~/synapse/env/bin/activate
pip install --upgrade pip
pip install --upgrade setuptools
pip install matrix-synapse
```

This will download Synapse from [PyPI](https://pypi.org/project/matrix-synapse)
and install it, along with the python libraries it uses, into a virtual environment
under `~/synapse/env`.  Feel free to pick a different directory if you
prefer.

This Synapse installation can then be later upgraded by using pip again with the
update flag:

```sh
source ~/synapse/env/bin/activate
pip install -U matrix-synapse
```

Before you can start Synapse, you will need to generate a configuration
file. To do this, run (in your virtualenv, as before):

```sh
cd ~/synapse
python -m synapse.app.homeserver \
    --server-name my.domain.name \
    --config-path homeserver.yaml \
    --generate-config \
    --report-stats=[yes|no]
```

... substituting an appropriate value for `--server-name`.

This command will generate you a config file that you can then customise, but it will
also generate a set of keys for you. These keys will allow your homeserver to
identify itself to other homeserver, so don't lose or delete them. It would be
wise to back them up somewhere safe. (If, for whatever reason, you do need to
change your homeserver's keys, you may find that other homeserver have the
old key cached. If you update the signing key, you should change the name of the
key in the `<server name>.signing.key` file (the second word) to something
different. See the [spec](https://matrix.org/docs/spec/server_server/latest.html#retrieving-server-keys) for more information on key management).

To actually run your new homeserver, pick a working directory for Synapse to
run (e.g. `~/synapse`), and:

```sh
cd ~/synapse
source env/bin/activate
synctl start
```

#### Platform-specific prerequisites

Synapse is written in Python but some of the libraries it uses are written in
C. So before we can install Synapse itself we need a working C compiler and the
header files for Python C extensions.

##### Debian/Ubuntu/Raspbian

Installing prerequisites on Ubuntu or Debian:

```sh
sudo apt install build-essential python3-dev libffi-dev \
                     python3-pip python3-setuptools sqlite3 \
                     libssl-dev virtualenv libjpeg-dev libxslt1-dev
```

##### ArchLinux

Installing prerequisites on ArchLinux:

```sh
sudo pacman -S base-devel python python-pip \
               python-setuptools python-virtualenv sqlite3
```

##### CentOS/Fedora

Installing prerequisites on CentOS or Fedora Linux:

```sh
sudo dnf install libtiff-devel libjpeg-devel libzip-devel freetype-devel \
                 libwebp-devel libxml2-devel libxslt-devel libpq-devel \
                 python3-virtualenv libffi-devel openssl-devel python3-devel
sudo dnf groupinstall "Development Tools"
```

##### macOS

Installing prerequisites on macOS:

```sh
xcode-select --install
sudo easy_install pip
sudo pip install virtualenv
brew install pkg-config libffi
```

On macOS Catalina (10.15) you may need to explicitly install OpenSSL
via brew and inform `pip` about it so that `psycopg2` builds:

```sh
brew install openssl@1.1
export LDFLAGS="-L/usr/local/opt/openssl/lib"
export CPPFLAGS="-I/usr/local/opt/openssl/include"
```

##### OpenSUSE

Installing prerequisites on openSUSE:

```sh
sudo zypper in -t pattern devel_basis
sudo zypper in python-pip python-setuptools sqlite3 python-virtualenv \
               python-devel libffi-devel libopenssl-devel libjpeg62-devel
```

##### OpenBSD

A port of Synapse is available under `net/synapse`. The filesystem
underlying the homeserver directory (defaults to `/var/synapse`) has to be
mounted with `wxallowed` (cf. `mount(8)`), so creating a separate filesystem
and mounting it to `/var/synapse` should be taken into consideration.

To be able to build Synapse's dependency on python the `WRKOBJDIR`
(cf. `bsd.port.mk(5)`) for building python, too, needs to be on a filesystem
mounted with `wxallowed` (cf. `mount(8)`).

Creating a `WRKOBJDIR` for building python under `/usr/local` (which on a
default OpenBSD installation is mounted with `wxallowed`):

```sh
doas mkdir /usr/local/pobj_wxallowed
```

Assuming `PORTS_PRIVSEP=Yes` (cf. `bsd.port.mk(5)`) and `SUDO=doas` are
configured in `/etc/mk.conf`:

```sh
doas chown _pbuild:_pbuild /usr/local/pobj_wxallowed
```

Setting the `WRKOBJDIR` for building python:

```sh
echo WRKOBJDIR_lang/python/3.7=/usr/local/pobj_wxallowed  \\nWRKOBJDIR_lang/python/2.7=/usr/local/pobj_wxallowed >> /etc/mk.conf
```

Building Synapse:

```sh
cd /usr/ports/net/synapse
make install
```

##### Windows

If you wish to run or develop Synapse on Windows, the Windows Subsystem For
Linux provides a Linux environment on Windows 10 which is capable of using the
Debian, Fedora, or source installation methods. More information about WSL can
be found at <https://docs.microsoft.com/en-us/windows/wsl/install-win10> for
Windows 10 and <https://docs.microsoft.com/en-us/windows/wsl/install-on-server>
for Windows Server.

### Prebuilt packages

As an alternative to installing from source, prebuilt packages are available
for a number of platforms.

#### Docker images and Ansible playbooks

There is an official synapse image available at
<https://hub.docker.com/r/matrixdotorg/synapse> which can be used with
the docker-compose file available at [contrib/docker](contrib/docker). Further
information on this including configuration options is available in the README
on hub.docker.com.

Alternatively, Andreas Peters (previously Silvio Fricke) has contributed a
Dockerfile to automate a synapse server in a single Docker image, at
<https://hub.docker.com/r/avhost/docker-matrix/tags/>

Slavi Pantaleev has created an Ansible playbook,
which installs the offical Docker image of Matrix Synapse
along with many other Matrix-related services (Postgres database, Element, coturn,
ma1sd, SSL support, etc.).
For more details, see
<https://github.com/spantaleev/matrix-docker-ansible-deploy>

#### Debian/Ubuntu

##### Matrix.org packages

Matrix.org provides Debian/Ubuntu packages of the latest stable version of
Synapse via <https://packages.matrix.org/debian/>. They are available for Debian
9 (Stretch), Ubuntu 16.04 (Xenial), and later. To use them:

```sh
sudo apt install -y lsb-release wget apt-transport-https
sudo wget -O /usr/share/keyrings/matrix-org-archive-keyring.gpg https://packages.matrix.org/debian/matrix-org-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/matrix-org-archive-keyring.gpg] https://packages.matrix.org/debian/ $(lsb_release -cs) main" |
    sudo tee /etc/apt/sources.list.d/matrix-org.list
sudo apt update
sudo apt install matrix-synapse-py3
```

**Note**: if you followed a previous version of these instructions which
recommended using `apt-key add` to add an old key from
`https://matrix.org/packages/debian/`, you should note that this key has been
revoked. You should remove the old key with `sudo apt-key remove
C35EB17E1EAE708E6603A9B3AD0592FE47F0DF61`, and follow the above instructions to
update your configuration.

The fingerprint of the repository signing key (as shown by `gpg
/usr/share/keyrings/matrix-org-archive-keyring.gpg`) is
`AAF9AE843A7584B5A3E4CD2BCF45A512DE2DA058`.

##### Downstream Debian packages

We do not recommend using the packages from the default Debian `buster`
repository at this time, as they are old and suffer from known security
vulnerabilities. You can install the latest version of Synapse from
[our repository](#matrixorg-packages) or from `buster-backports`. Please
see the [Debian documentation](https://backports.debian.org/Instructions/)
for information on how to use backports.

If you are using Debian `sid` or testing, Synapse is available in the default
repositories and it should be possible to install it simply with:

```sh
sudo apt install matrix-synapse
```

##### Downstream Ubuntu packages

We do not recommend using the packages in the default Ubuntu repository
at this time, as they are old and suffer from known security vulnerabilities.
The latest version of Synapse can be installed from [our repository](#matrixorg-packages).

#### Fedora

Synapse is in the Fedora repositories as `matrix-synapse`:

```sh
sudo dnf install matrix-synapse
```

Oleg Girko provides Fedora RPMs at
<https://obs.infoserver.lv/project/monitor/matrix-synapse>

#### OpenSUSE

Synapse is in the OpenSUSE repositories as `matrix-synapse`:

```sh
sudo zypper install matrix-synapse
```

#### SUSE Linux Enterprise Server

Unofficial package are built for SLES 15 in the openSUSE:Backports:SLE-15 repository at
<https://download.opensuse.org/repositories/openSUSE:/Backports:/SLE-15/standard/>

#### ArchLinux

The quickest way to get up and running with ArchLinux is probably with the community package
<https://www.archlinux.org/packages/community/any/matrix-synapse/>, which should pull in most of
the necessary dependencies.

pip may be outdated (6.0.7-1 and needs to be upgraded to 6.0.8-1 ):

```sh
sudo pip install --upgrade pip
```

If you encounter an error with lib bcrypt causing an Wrong ELF Class:
ELFCLASS32 (x64 Systems), you may need to reinstall py-bcrypt to correctly
compile it under the right architecture. (This should not be needed if
installing under virtualenv):

```sh
sudo pip uninstall py-bcrypt
sudo pip install py-bcrypt
```

#### Void Linux

Synapse can be found in the void repositories as 'synapse':

```sh
xbps-install -Su
xbps-install -S synapse
```

#### FreeBSD

Synapse can be installed via FreeBSD Ports or Packages contributed by Brendan Molloy from:

- Ports: `cd /usr/ports/net-im/py-matrix-synapse && make install clean`
- Packages: `pkg install py37-matrix-synapse`

#### OpenBSD

As of OpenBSD 6.7 Synapse is available as a pre-compiled binary. The filesystem
underlying the homeserver directory (defaults to `/var/synapse`) has to be
mounted with `wxallowed` (cf. `mount(8)`), so creating a separate filesystem
and mounting it to `/var/synapse` should be taken into consideration.

Installing Synapse:

```sh
doas pkg_add synapse
```

#### NixOS

Robin Lambertz has packaged Synapse for NixOS at:
<https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/services/misc/matrix-synapse.nix>

## Setting up Synapse

Once you have installed synapse as above, you will need to configure it.

### Using PostgreSQL

By default Synapse uses [SQLite](https://sqlite.org/) and in doing so trades performance for convenience.
SQLite is only recommended in Synapse for testing purposes or for servers with
very light workloads.

Almost all installations should opt to use [PostgreSQL](https://www.postgresql.org). Advantages include:

- significant performance improvements due to the superior threading and
  caching model, smarter query optimiser
- allowing the DB to be run on separate hardware

For information on how to install and use PostgreSQL in Synapse, please see
[docs/postgres.md](docs/postgres.md)

### TLS certificates

The default configuration exposes a single HTTP port on the local
interface: `http://localhost:8008`. It is suitable for local testing,
but for any practical use, you will need Synapse's APIs to be served
over HTTPS.

The recommended way to do so is to set up a reverse proxy on port
`8448`. You can find documentation on doing so in
[docs/reverse_proxy.md](docs/reverse_proxy.md).

Alternatively, you can configure Synapse to expose an HTTPS port. To do
so, you will need to edit `homeserver.yaml`, as follows:

- First, under the `listeners` section, uncomment the configuration for the
  TLS-enabled listener. (Remove the hash sign (`#`) at the start of
  each line). The relevant lines are like this:

```yaml
  - port: 8448
    type: http
    tls: true
    resources:
      - names: [client, federation]
  ```

- You will also need to uncomment the `tls_certificate_path` and
  `tls_private_key_path` lines under the `TLS` section. You will need to manage
  provisioning of these certificates yourself — Synapse had built-in ACME
  support, but the ACMEv1 protocol Synapse implements is deprecated, not
  allowed by LetsEncrypt for new sites, and will break for existing sites in
  late 2020. See [ACME.md](docs/ACME.md).

  If you are using your own certificate, be sure to use a `.pem` file that
  includes the full certificate chain including any intermediate certificates
  (for instance, if using certbot, use `fullchain.pem` as your certificate, not
  `cert.pem`).

For a more detailed guide to configuring your server for federation, see
[federate.md](docs/federate.md).

### Client Well-Known URI

Setting up the client Well-Known URI is optional but if you set it up, it will
allow users to enter their full username (e.g. `@user:<server_name>`) into clients
which support well-known lookup to automatically configure the homeserver and
identity server URLs. This is useful so that users don't have to memorize or think
about the actual homeserver URL you are using.

The URL `https://<server_name>/.well-known/matrix/client` should return JSON in
the following format.

```json
{
  "m.homeserver": {
    "base_url": "https://<matrix.example.com>"
  }
}
```

It can optionally contain identity server information as well.

```json
{
  "m.homeserver": {
    "base_url": "https://<matrix.example.com>"
  },
  "m.identity_server": {
    "base_url": "https://<identity.example.com>"
  }
}
```

To work in browser based clients, the file must be served with the appropriate
Cross-Origin Resource Sharing (CORS) headers. A recommended value would be
`Access-Control-Allow-Origin: *` which would allow all browser based clients to
view it.

In nginx this would be something like:

```nginx
location /.well-known/matrix/client {
    return 200 '{"m.homeserver": {"base_url": "https://<matrix.example.com>"}}';
    default_type application/json;
    add_header Access-Control-Allow-Origin *;
}
```

You should also ensure the `public_baseurl` option in `homeserver.yaml` is set
correctly. `public_baseurl` should be set to the URL that clients will use to
connect to your server. This is the same URL you put for the `m.homeserver`
`base_url` above.

```yaml
public_baseurl: "https://<matrix.example.com>"
```

### Email

It is desirable for Synapse to have the capability to send email. This allows
Synapse to send password reset emails, send verifications when an email address
is added to a user's account, and send email notifications to users when they
receive new messages.

To configure an SMTP server for Synapse, modify the configuration section
headed `email`, and be sure to have at least the `smtp_host`, `smtp_port`
and `notif_from` fields filled out.  You may also need to set `smtp_user`,
`smtp_pass`, and `require_transport_security`.

If email is not configured, password reset, registration and notifications via
email will be disabled.

### Registering a user

The easiest way to create a new user is to do so from a client like [Element](https://element.io/).

Alternatively, you can do so from the command line. This can be done as follows:

 1. If synapse was installed via pip, activate the virtualenv as follows (if Synapse was
    installed via a prebuilt package, `register_new_matrix_user` should already be
    on the search path):
    ```sh
    cd ~/synapse
    source env/bin/activate
    synctl start # if not already running
    ```
 2. Run the following command:
    ```sh
    register_new_matrix_user -c homeserver.yaml http://localhost:8008
    ```

This will prompt you to add details for the new user, and will then connect to
the running Synapse to create the new user. For example:
```
New user localpart: erikj
Password:
Confirm password:
Make admin [no]:
Success!
```

This process uses a setting `registration_shared_secret` in
`homeserver.yaml`, which is shared between Synapse itself and the
`register_new_matrix_user` script. It doesn't matter what it is (a random
value is generated by `--generate-config`), but it should be kept secret, as
anyone with knowledge of it can register users, including admin accounts,
on your server even if `enable_registration` is `false`.

### Setting up a TURN server

For reliable VoIP calls to be routed via this homeserver, you MUST configure
a TURN server. See [docs/turn-howto.md](docs/turn-howto.md) for details.

### URL previews

Synapse includes support for previewing URLs, which is disabled by default.  To
turn it on you must enable the `url_preview_enabled: True` config parameter
and explicitly specify the IP ranges that Synapse is not allowed to spider for
previewing in the `url_preview_ip_range_blacklist` configuration parameter.
This is critical from a security perspective to stop arbitrary Matrix users
spidering 'internal' URLs on your network. At the very least we recommend that
your loopback and RFC1918 IP addresses are blacklisted.

This also requires the optional `lxml` python dependency to be  installed. This
in turn requires the `libxml2` library to be available - on  Debian/Ubuntu this
means `apt-get install libxml2-dev`, or equivalent for your OS.

### Troubleshooting Installation

`pip` seems to leak *lots* of memory during installation. For instance, a Linux
host with 512MB of RAM may run out of memory whilst installing Twisted. If this
happens, you will have to individually install the dependencies which are
failing, e.g.:

```sh
pip install twisted
```

If you have any other problems, feel free to ask in
[#synapse:matrix.org](https://matrix.to/#/#synapse:matrix.org).
