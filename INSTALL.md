- [Choosing your server name](#choosing-your-server-name)
- [Installing Synapse](#installing-synapse)
  - [Installing from source](#installing-from-source)
    - [Platform-Specific Instructions](#platform-specific-instructions)
  - [Prebuilt packages](#prebuilt-packages)
- [Setting up Synapse](#setting-up-synapse)
  - [TLS certificates](#tls-certificates)
  - [Email](#email)
  - [Registering a user](#registering-a-user)
  - [Setting up a TURN server](#setting-up-a-turn-server)
  - [URL previews](#url-previews)
- [Troubleshooting Installation](#troubleshooting-installation)

# Choosing your server name

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

# Installing Synapse

## Installing from source

(Prebuilt packages are available for some platforms - see [Prebuilt packages](#prebuilt-packages).)

System requirements:

- POSIX-compliant system (tested on Linux & OS X)
- Python 3.5.2 or later, up to Python 3.8.
- At least 1GB of free RAM if you want to join large public rooms like #matrix:matrix.org

Synapse is written in Python but some of the libraries it uses are written in
C. So before we can install Synapse itself we need a working C compiler and the
header files for Python C extensions. See [Platform-Specific
Instructions](#platform-specific-instructions) for information on installing
these on various platforms.

To install the Synapse homeserver run:

```
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

```
source ~/synapse/env/bin/activate
pip install -U matrix-synapse
```

Before you can start Synapse, you will need to generate a configuration
file. To do this, run (in your virtualenv, as before):

```
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
different. See the
[spec](https://matrix.org/docs/spec/server_server/latest.html#retrieving-server-keys)
for more information on key management).

To actually run your new homeserver, pick a working directory for Synapse to
run (e.g. `~/synapse`), and:

```
cd ~/synapse
source env/bin/activate
synctl start
```

### Platform-Specific Instructions

#### Debian/Ubuntu/Raspbian

Installing prerequisites on Ubuntu or Debian:

```
sudo apt-get install build-essential python3-dev libffi-dev \
                     python3-pip python3-setuptools sqlite3 \
                     libssl-dev virtualenv libjpeg-dev libxslt1-dev
```

#### ArchLinux

Installing prerequisites on ArchLinux:

```
sudo pacman -S base-devel python python-pip \
               python-setuptools python-virtualenv sqlite3
```

#### CentOS/Fedora

Installing prerequisites on CentOS 8 or Fedora>26:

```
sudo dnf install libtiff-devel libjpeg-devel libzip-devel freetype-devel \
                 libwebp-devel tk-devel redhat-rpm-config \
                 python3-virtualenv libffi-devel openssl-devel
sudo dnf groupinstall "Development Tools"
```

Installing prerequisites on CentOS 7 or Fedora<=25:

```
sudo yum install libtiff-devel libjpeg-devel libzip-devel freetype-devel \
                 lcms2-devel libwebp-devel tcl-devel tk-devel redhat-rpm-config \
                 python3-virtualenv libffi-devel openssl-devel
sudo yum groupinstall "Development Tools"
```

Note that Synapse does not support versions of SQLite before 3.11, and CentOS 7
uses SQLite 3.7. You may be able to work around this by installing a more
recent SQLite version, but it is recommended that you instead use a Postgres
database: see [docs/postgres.md](docs/postgres.md).

#### macOS

Installing prerequisites on macOS:

```
xcode-select --install
sudo easy_install pip
sudo pip install virtualenv
brew install pkg-config libffi
```

On macOS Catalina (10.15) you may need to explicitly install OpenSSL
via brew and inform `pip` about it so that `psycopg2` builds:

```
brew install openssl@1.1
export LDFLAGS=-L/usr/local/Cellar/openssl\@1.1/1.1.1d/lib/
```

#### OpenSUSE

Installing prerequisites on openSUSE:

```
sudo zypper in -t pattern devel_basis
sudo zypper in python-pip python-setuptools sqlite3 python-virtualenv \
               python-devel libffi-devel libopenssl-devel libjpeg62-devel
```

#### OpenBSD

A port of Synapse is available under `net/synapse`. The filesystem
underlying the homeserver directory (defaults to `/var/synapse`) has to be
mounted with `wxallowed` (cf. `mount(8)`), so creating a separate filesystem
and mounting it to `/var/synapse` should be taken into consideration.

To be able to build Synapse's dependency on python the `WRKOBJDIR`
(cf. `bsd.port.mk(5)`) for building python, too, needs to be on a filesystem
mounted with `wxallowed` (cf. `mount(8)`).

Creating a `WRKOBJDIR` for building python under `/usr/local` (which on a
default OpenBSD installation is mounted with `wxallowed`):

```
doas mkdir /usr/local/pobj_wxallowed
```

Assuming `PORTS_PRIVSEP=Yes` (cf. `bsd.port.mk(5)`) and `SUDO=doas` are
configured in `/etc/mk.conf`:

```
doas chown _pbuild:_pbuild /usr/local/pobj_wxallowed
```

Setting the `WRKOBJDIR` for building python:

```
echo WRKOBJDIR_lang/python/3.7=/usr/local/pobj_wxallowed  \\nWRKOBJDIR_lang/python/2.7=/usr/local/pobj_wxallowed >> /etc/mk.conf
```

Building Synapse:

```
cd /usr/ports/net/synapse
make install
```

#### Windows

If you wish to run or develop Synapse on Windows, the Windows Subsystem For
Linux provides a Linux environment on Windows 10 which is capable of using the
Debian, Fedora, or source installation methods. More information about WSL can
be found at https://docs.microsoft.com/en-us/windows/wsl/install-win10 for
Windows 10 and https://docs.microsoft.com/en-us/windows/wsl/install-on-server
for Windows Server.

## Prebuilt packages

As an alternative to installing from source, prebuilt packages are available
for a number of platforms.

### Docker images and Ansible playbooks

There is an offical synapse image available at
https://hub.docker.com/r/matrixdotorg/synapse which can be used with
the docker-compose file available at [contrib/docker](contrib/docker). Further information on
this including configuration options is available in the README on
hub.docker.com.

Alternatively, Andreas Peters (previously Silvio Fricke) has contributed a
Dockerfile to automate a synapse server in a single Docker image, at
https://hub.docker.com/r/avhost/docker-matrix/tags/

Slavi Pantaleev has created an Ansible playbook,
which installs the offical Docker image of Matrix Synapse
along with many other Matrix-related services (Postgres database, riot-web, coturn, mxisd, SSL support, etc.).
For more details, see
https://github.com/spantaleev/matrix-docker-ansible-deploy


### Debian/Ubuntu

#### Matrix.org packages

Matrix.org provides Debian/Ubuntu packages of the latest stable version of
Synapse via https://packages.matrix.org/debian/. They are available for Debian
9 (Stretch), Ubuntu 16.04 (Xenial), and later. To use them:

```
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

#### Downstream Debian/Ubuntu packages

For `buster` and `sid`, Synapse is available in the Debian repositories and
it should be possible to install it with simply:

```
sudo apt install matrix-synapse
```

There is also a version of `matrix-synapse` in `stretch-backports`. Please see
the [Debian documentation on
backports](https://backports.debian.org/Instructions/) for information on how
to use them.

We do not recommend using the packages in downstream Ubuntu at this time, as
they are old and suffer from known security vulnerabilities.

### Fedora

Synapse is in the Fedora repositories as `matrix-synapse`:

```
sudo dnf install matrix-synapse
```

Oleg Girko provides Fedora RPMs at
https://obs.infoserver.lv/project/monitor/matrix-synapse

### OpenSUSE

Synapse is in the OpenSUSE repositories as `matrix-synapse`:

```
sudo zypper install matrix-synapse
```

### SUSE Linux Enterprise Server

Unofficial package are built for SLES 15 in the openSUSE:Backports:SLE-15 repository at
https://download.opensuse.org/repositories/openSUSE:/Backports:/SLE-15/standard/

### ArchLinux

The quickest way to get up and running with ArchLinux is probably with the community package
https://www.archlinux.org/packages/community/any/matrix-synapse/, which should pull in most of
the necessary dependencies.

pip may be outdated (6.0.7-1 and needs to be upgraded to 6.0.8-1 ):

```
sudo pip install --upgrade pip
```

If you encounter an error with lib bcrypt causing an Wrong ELF Class:
ELFCLASS32 (x64 Systems), you may need to reinstall py-bcrypt to correctly
compile it under the right architecture. (This should not be needed if
installing under virtualenv):

```
sudo pip uninstall py-bcrypt
sudo pip install py-bcrypt
```

### Void Linux

Synapse can be found in the void repositories as 'synapse':

```
xbps-install -Su
xbps-install -S synapse
```

### FreeBSD

Synapse can be installed via FreeBSD Ports or Packages contributed by Brendan Molloy from:

 - Ports: `cd /usr/ports/net-im/py-matrix-synapse && make install clean`
 - Packages: `pkg install py37-matrix-synapse`

### OpenBSD

As of OpenBSD 6.7 Synapse is available as a pre-compiled binary. The filesystem
underlying the homeserver directory (defaults to `/var/synapse`) has to be
mounted with `wxallowed` (cf. `mount(8)`), so creating a separate filesystem
and mounting it to `/var/synapse` should be taken into consideration.

Installing Synapse:

```
doas pkg_add synapse
```

### NixOS

Robin Lambertz has packaged Synapse for NixOS at:
https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/services/misc/matrix-synapse.nix

# Setting up Synapse

Once you have installed synapse as above, you will need to configure it.

## TLS certificates

The default configuration exposes a single HTTP port on the local
interface: `http://localhost:8008`. It is suitable for local testing,
but for any practical use, you will need Synapse's APIs to be served
over HTTPS.

The recommended way to do so is to set up a reverse proxy on port
`8448`. You can find documentation on doing so in
[docs/reverse_proxy.md](docs/reverse_proxy.md).

Alternatively, you can configure Synapse to expose an HTTPS port. To do
so, you will need to edit `homeserver.yaml`, as follows:

* First, under the `listeners` section, uncomment the configuration for the
  TLS-enabled listener. (Remove the hash sign (`#`) at the start of
  each line). The relevant lines are like this:

  ```
    - port: 8448
      type: http
      tls: true
      resources:
        - names: [client, federation]
  ```

* You will also need to uncomment the `tls_certificate_path` and
  `tls_private_key_path` lines under the `TLS` section. You can either
  point these settings at an existing certificate and key, or you can
  enable Synapse's built-in ACME (Let's Encrypt) support. Instructions
  for having Synapse automatically provision and renew federation
  certificates through ACME can be found at [ACME.md](docs/ACME.md).
  Note that, as pointed out in that document, this feature will not
  work with installs set up after November 2019.

  If you are using your own certificate, be sure to use a `.pem` file that
  includes the full certificate chain including any intermediate certificates
  (for instance, if using certbot, use `fullchain.pem` as your certificate, not
  `cert.pem`).

For a more detailed guide to configuring your server for federation, see
[federate.md](docs/federate.md).


## Email

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

## Registering a user

The easiest way to create a new user is to do so from a client like [Riot](https://riot.im).

Alternatively you can do so from the command line if you have installed via pip.

This can be done as follows:

```
$ source ~/synapse/env/bin/activate
$ synctl start # if not already running
$ register_new_matrix_user -c homeserver.yaml http://localhost:8008
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

## Setting up a TURN server

For reliable VoIP calls to be routed via this homeserver, you MUST configure
a TURN server. See [docs/turn-howto.md](docs/turn-howto.md) for details.

## URL previews

Synapse includes support for previewing URLs, which is disabled by default.  To
turn it on you must enable the `url_preview_enabled: True` config parameter
and explicitly specify the IP ranges that Synapse is not allowed to spider for
previewing in the `url_preview_ip_range_blacklist` configuration parameter.
This is critical from a security perspective to stop arbitrary Matrix users
spidering 'internal' URLs on your network. At the very least we recommend that
your loopback and RFC1918 IP addresses are blacklisted.

This also requires the optional `lxml` and `netaddr` python dependencies to be
installed. This in turn requires the `libxml2` library to be available - on
Debian/Ubuntu this means `apt-get install libxml2-dev`, or equivalent for
your OS.

# Troubleshooting Installation

`pip` seems to leak *lots* of memory during installation. For instance, a Linux
host with 512MB of RAM may run out of memory whilst installing Twisted. If this
happens, you will have to individually install the dependencies which are
failing, e.g.:

```
pip install twisted
```

If you have any other problems, feel free to ask in
[#synapse:matrix.org](https://matrix.to/#/#synapse:matrix.org).
