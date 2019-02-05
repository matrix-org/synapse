# Installing Synapse

## Installing from source

(Prebuilt packages are available for some platforms - see [Prebuilt
packages](#prebuilt packages).)

System requirements:

- POSIX-compliant system (tested on Linux & OS X)
- Python 3.5, 3.6, 3.7, or 2.7
- At least 1GB of free RAM if you want to join large public rooms like #matrix:matrix.org

Synapse is written in Python but some of the libraries it uses are written in
C. So before we can install Synapse itself we need a working C compiler and the
header files for Python C extensions. See [Platform-Specific
Instructions][#platform-specific-instructions] for information on installing
these on various platforms.

To install the Synapse homeserver run::

    mkdir -p ~/synapse
    virtualenv -p python3 ~/synapse/env
    source ~/synapse/env/bin/activate
    pip install --upgrade pip
    pip install --upgrade setuptools
    pip install matrix-synapse[all]

This installs Synapse, along with the libraries it uses, into a virtual
environment under ``~/synapse/env``.  Feel free to pick a different directory
if you prefer.

This Synapse installation can then be later upgraded by using pip again with the
update flag::

    source ~/synapse/env/bin/activate
    pip install -U matrix-synapse[all]

### Platform-Specific Instructions

#### Debian/Ubuntu/Raspbian

Installing prerequisites on Ubuntu or Debian:

```sh
sudo apt-get install build-essential python3-dev libffi-dev \
                     python-pip python-setuptools sqlite3 \
                     libssl-dev python-virtualenv libjpeg-dev libxslt1-dev
```

#### ArchLinux

Installing prerequisites on ArchLinux:

```sh
sudo pacman -S base-devel python python-pip \
               python-setuptools python-virtualenv sqlite3
```

#### CentOS/Fedora

Installing prerequisites on CentOS 7 or Fedora 25:

```sh
sudo yum install libtiff-devel libjpeg-devel libzip-devel freetype-devel \
                 lcms2-devel libwebp-devel tcl-devel tk-devel redhat-rpm-config \
                 python-virtualenv libffi-devel openssl-devel
sudo yum groupinstall "Development Tools"
```

#### Mac OS X

Installing prerequisites on Mac OS X:

```sh
xcode-select --install
sudo easy_install pip
sudo pip install virtualenv
brew install pkg-config libffi
```

#### OpenSUSE

Installing prerequisites on openSUSE:

```sh
sudo zypper in -t pattern devel_basis
sudo zypper in python-pip python-setuptools sqlite3 python-virtualenv \
               python-devel libffi-devel libopenssl-devel libjpeg62-devel
```

#### OpenBSD

Installing prerequisites on OpenBSD:

```sh
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

Installing may fail with ``Could not find any downloads that satisfy the requirement pymacaroons-pynacl (from matrix-synapse==0.12.0)``.
You can fix this by manually upgrading pip and virtualenv::

    sudo pip install --upgrade virtualenv

You can next rerun ``virtualenv -p python3 synapse`` to update the virtual env.

Installing may fail during installing virtualenv with ``InsecurePlatformWarning: A true SSLContext object is not available. This prevents urllib3 from configuring SSL appropriately and may cause certain SSL connections to fail. For more information, see https://urllib3.readthedocs.org/en/latest/security.html#insecureplatformwarning.``
You can fix this  by manually installing ndg-httpsclient::

    pip install --upgrade ndg-httpsclient

Installing may fail with ``mock requires setuptools>=17.1. Aborting installation``.
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
the docker-compose file available at `contrib/docker <contrib/docker>`_. Further information on
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
Synapse via https://matrix.org/packages/debian/. To use them:

```sh
sudo apt install -y lsb-release curl apt-transport-https
echo "deb https://matrix.org/packages/debian `lsb_release -cs` main" |
    sudo tee /etc/apt/sources.list.d/matrix-org.list
curl "https://matrix.org/packages/debian/repo-key.asc" |
    sudo apt-key add -
sudo apt update
sudo apt install matrix-synapse-py3
```

#### Downstream Debian/Ubuntu packages

For `buster` and `sid`, Synapse is available in the Debian repositories and
it should be possible to install it with simply:

```sh
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

```sh
sudo dnf install matrix-synapse
```

Oleg Girko provides Fedora RPMs at
https://obs.infoserver.lv/project/monitor/matrix-synapse

### OpenSUSE

Synapse is in the OpenSUSE repositories as `matrix-synapse`:

```sh
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

### FreeBSD

Synapse can be installed via FreeBSD Ports or Packages contributed by Brendan Molloy from:

 - Ports: `cd /usr/ports/net-im/py-matrix-synapse && make install clean`
 - Packages: `pkg install py27-matrix-synapse`


### NixOS

Robin Lambertz has packaged Synapse for NixOS at:
https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/services/misc/matrix-synapse.nix
