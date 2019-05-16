* [Installing Synapse](#installing-synapse)
  * [Installing from source](#installing-from-source)
    * [Platform-Specific Instructions](#platform-specific-instructions)
    * [Troubleshooting Installation](#troubleshooting-installation)
  * [Prebuilt packages](#prebuilt-packages)
* [Setting up Synapse](#setting-up-synapse)
  * [TLS certificates](#tls-certificates)
  * [Registering a user](#registering-a-user)
  * [Setting up a TURN server](#setting-up-a-turn-server)
  * [URL previews](#url-previews)

# Installing Synapse

## Installing from source

(Prebuilt packages are available for some platforms - see [Prebuilt packages](#prebuilt-packages).)

System requirements:

- POSIX-compliant system (tested on Linux & OS X)
- Python 3.5, 3.6, 3.7, or 2.7
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
pip install matrix-synapse[all]
```

This will download Synapse from [PyPI](https://pypi.org/project/matrix-synapse)
and install it, along with the python libraries it uses, into a virtual environment
under `~/synapse/env`.  Feel free to pick a different directory if you
prefer.

This Synapse installation can then be later upgraded by using pip again with the
update flag:

```
source ~/synapse/env/bin/activate
pip install -U matrix-synapse[all]
```

Before you can start Synapse, you will need to generate a configuration
file. To do this, run (in your virtualenv, as before)::

```
cd ~/synapse
python -m synapse.app.homeserver \
    --server-name my.domain.name \
    --config-path homeserver.yaml \
    --generate-config \
    --report-stats=[yes|no]
```

... substituting an appropriate value for `--server-name`. The server name
determines the "domain" part of user-ids for users on your server: these will
all be of the format `@user:my.domain.name`. It also determines how other
matrix servers will reach yours for Federation. For a test configuration,
set this to the hostname of your server. For a more production-ready setup, you
will probably want to specify your domain (`example.com`) rather than a
matrix-specific hostname here (in the same way that your email address is
probably `user@example.com` rather than `user@email.example.com`) - but
doing so may require more advanced setup: see [Setting up Federation](docs/federate.md).
Beware that the server name cannot be changed later.

This command will generate you a config file that you can then customise, but it will
also generate a set of keys for you. These keys will allow your Home Server to
identify itself to other Home Servers, so don't lose or delete them. It would be
wise to back them up somewhere safe. (If, for whatever reason, you do need to
change your Home Server's keys, you may find that other Home Servers have the
old key cached. If you update the signing key, you should change the name of the
key in the `<server name>.signing.key` file (the second word) to something
different. See the
[spec](https://matrix.org/docs/spec/server_server/latest.html#retrieving-server-keys)
for more information on key management.)

You will need to give Synapse a TLS certficate before it will start - see [TLS
certificates](#tls-certificates).

To actually run your new homeserver, pick a working directory for Synapse to
run (e.g. `~/synapse`), and::

    cd ~/synapse
    source env/bin/activate
    synctl start

### Platform-Specific Instructions

#### Debian/Ubuntu/Raspbian

Installing prerequisites on Ubuntu or Debian:

```
sudo apt-get install build-essential python3-dev libffi-dev \
                     python-pip python-setuptools sqlite3 \
                     libssl-dev python-virtualenv libjpeg-dev libxslt1-dev
```

#### ArchLinux

Installing prerequisites on ArchLinux:

```
sudo pacman -S base-devel python python-pip \
               python-setuptools python-virtualenv sqlite3
```

#### CentOS/Fedora

Installing prerequisites on CentOS 7 or Fedora 25:

```
sudo yum install libtiff-devel libjpeg-devel libzip-devel freetype-devel \
                 lcms2-devel libwebp-devel tcl-devel tk-devel redhat-rpm-config \
                 python-virtualenv libffi-devel openssl-devel
sudo yum groupinstall "Development Tools"
```

#### Mac OS X

Installing prerequisites on Mac OS X:

```
xcode-select --install
sudo easy_install pip
sudo pip install virtualenv
brew install pkg-config libffi
```

#### OpenSUSE

Installing prerequisites on openSUSE:

```
sudo zypper in -t pattern devel_basis
sudo zypper in python-pip python-setuptools sqlite3 python-virtualenv \
               python-devel libffi-devel libopenssl-devel libjpeg62-devel
```

#### OpenBSD

Installing prerequisites on OpenBSD:

```
doas pkg_add python libffi py-pip py-setuptools sqlite3 py-virtualenv \
              libxslt jpeg
```

There is currently no port for OpenBSD. Additionally, OpenBSD's security
settings require a slightly more difficult installation process.

XXX: I suspect this is out of date.

1. Create a new directory in `/usr/local` called `_synapse`. Also, create a
   new user called `_synapse` and set that directory as the new user's home.
   This is required because, by default, OpenBSD only allows binaries which need
   write and execute permissions on the same memory space to be run from
   `/usr/local`.
2. `su` to the new `_synapse` user and change to their home directory.
3. Create a new virtualenv: `virtualenv -p python2.7 ~/.synapse`
4. Source the virtualenv configuration located at
   `/usr/local/_synapse/.synapse/bin/activate`. This is done in `ksh` by
   using the `.` command, rather than `bash`'s `source`.
5. Optionally, use `pip` to install `lxml`, which Synapse needs to parse
   webpages for their titles.
6. Use `pip` to install this repository: `pip install matrix-synapse`
7. Optionally, change `_synapse`'s shell to `/bin/false` to reduce the
   chance of a compromised Synapse server being used to take over your box.

After this, you may proceed with the rest of the install directions.

#### Windows

If you wish to run or develop Synapse on Windows, the Windows Subsystem For
Linux provides a Linux environment on Windows 10 which is capable of using the
Debian, Fedora, or source installation methods. More information about WSL can
be found at https://docs.microsoft.com/en-us/windows/wsl/install-win10 for
Windows 10 and https://docs.microsoft.com/en-us/windows/wsl/install-on-server
for Windows Server.

### Troubleshooting Installation

XXX a bunch of this is no longer relevant.

Synapse requires pip 8 or later, so if your OS provides too old a version you
may need to manually upgrade it::

    sudo pip install --upgrade pip

Installing may fail with `Could not find any downloads that satisfy the requirement pymacaroons-pynacl (from matrix-synapse==0.12.0)`.
You can fix this by manually upgrading pip and virtualenv::

    sudo pip install --upgrade virtualenv

You can next rerun `virtualenv -p python3 synapse` to update the virtual env.

Installing may fail during installing virtualenv with `InsecurePlatformWarning: A true SSLContext object is not available. This prevents urllib3 from configuring SSL appropriately and may cause certain SSL connections to fail. For more information, see https://urllib3.readthedocs.org/en/latest/security.html#insecureplatformwarning.`
You can fix this  by manually installing ndg-httpsclient::

    pip install --upgrade ndg-httpsclient

Installing may fail with `mock requires setuptools>=17.1. Aborting installation`.
You can fix this by upgrading setuptools::

    pip install --upgrade setuptools

If pip crashes mid-installation for reason (e.g. lost terminal), pip may
refuse to run until you remove the temporary installation directory it
created. To reset the installation::

    rm -rf /tmp/pip_install_matrix

pip seems to leak *lots* of memory during installation.  For instance, a Linux
host with 512MB of RAM may run out of memory whilst installing Twisted.  If this
happens, you will have to individually install the dependencies which are
failing, e.g.::

    pip install twisted

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

### FreeBSD

Synapse can be installed via FreeBSD Ports or Packages contributed by Brendan Molloy from:

 - Ports: `cd /usr/ports/net-im/py-matrix-synapse && make install clean`
 - Packages: `pkg install py27-matrix-synapse`


### NixOS

Robin Lambertz has packaged Synapse for NixOS at:
https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/services/misc/matrix-synapse.nix

# Setting up Synapse

Once you have installed synapse as above, you will need to configure it.

## TLS certificates

The default configuration exposes a single HTTP port: http://localhost:8008. It
is suitable for local testing, but for any practical use, you will either need
to enable a reverse proxy, or configure Synapse to expose an HTTPS port.

For information on using a reverse proxy, see
[docs/reverse_proxy.rst](docs/reverse_proxy.rst).

To configure Synapse to expose an HTTPS port, you will need to edit
`homeserver.yaml`, as follows:

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
  certificates through ACME can be found at [ACME.md](docs/ACME.md). If you
  are using your own certificate, be sure to use a `.pem` file that includes
  the full certificate chain including any intermediate certificates (for
  instance, if using certbot, use `fullchain.pem` as your certificate, not
  `cert.pem`).

For those of you upgrading your TLS certificate in readiness for Synapse 1.0,
please take a look at [our guide](docs/MSC1711_certificates_FAQ.md#configuring-certificates-for-compatibility-with-synapse-100).

## Registering a user

You will need at least one user on your server in order to use a Matrix
client. Users can be registered either via a Matrix client, or via a
commandline script.

To get started, it is easiest to use the command line to register new
users. This can be done as follows:

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
a TURN server.  See [docs/turn-howto.rst](docs/turn-howto.rst) for details.

## URL previews

Synapse includes support for previewing URLs, which is disabled by default.  To
turn it on you must enable the `url_preview_enabled: True` config parameter
and explicitly specify the IP ranges that Synapse is not allowed to spider for
previewing in the `url_preview_ip_range_blacklist` configuration parameter.
This is critical from a security perspective to stop arbitrary Matrix users
spidering 'internal' URLs on your network.  At the very least we recommend that
your loopback and RFC1918 IP addresses are blacklisted.

This also requires the optional lxml and netaddr python dependencies to be
installed.  This in turn requires the libxml2 library to be available - on
Debian/Ubuntu this means `apt-get install libxml2-dev`, or equivalent for
your OS.
