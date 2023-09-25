# Installation Instructions

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
[Setting up Federation](../federate.md).

## Installing Synapse

### Prebuilt packages

Prebuilt packages are available for a number of platforms. These are recommended
for most users.

#### Docker images and Ansible playbooks

There is an official synapse image available at
<https://hub.docker.com/r/matrixdotorg/synapse> or at [`ghcr.io/matrix-org/synapse`](https://ghcr.io/matrix-org/synapse)
which can be used with the docker-compose file available at
[contrib/docker](https://github.com/matrix-org/synapse/tree/develop/contrib/docker).
Further information on this including configuration options is available in the README
on hub.docker.com.

Alternatively, Andreas Peters (previously Silvio Fricke) has contributed a
Dockerfile to automate a synapse server in a single Docker image, at
<https://hub.docker.com/r/avhost/docker-matrix/tags/>

Slavi Pantaleev has created an Ansible playbook,
which installs the official Docker image of Matrix Synapse
along with many other Matrix-related services (Postgres database, Element, coturn,
ma1sd, SSL support, etc.).
For more details, see
<https://github.com/spantaleev/matrix-docker-ansible-deploy>

#### Debian/Ubuntu

##### Matrix.org packages

Matrix.org provides Debian/Ubuntu packages of Synapse, for the amd64
architecture via <https://packages.matrix.org/debian/>.  

To install the latest release:

```sh
sudo apt install -y lsb-release wget apt-transport-https
sudo wget -O /usr/share/keyrings/matrix-org-archive-keyring.gpg https://packages.matrix.org/debian/matrix-org-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/matrix-org-archive-keyring.gpg] https://packages.matrix.org/debian/ $(lsb_release -cs) main" |
    sudo tee /etc/apt/sources.list.d/matrix-org.list
sudo apt update
sudo apt install matrix-synapse-py3
```

Packages are also published for release candidates. To enable the prerelease
channel, add `prerelease` to the `sources.list` line. For example:

```sh
sudo wget -O /usr/share/keyrings/matrix-org-archive-keyring.gpg https://packages.matrix.org/debian/matrix-org-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/matrix-org-archive-keyring.gpg] https://packages.matrix.org/debian/ $(lsb_release -cs) main prerelease" |
    sudo tee /etc/apt/sources.list.d/matrix-org.list
sudo apt update
sudo apt install matrix-synapse-py3
```

The fingerprint of the repository signing key (as shown by `gpg
/usr/share/keyrings/matrix-org-archive-keyring.gpg`) is
`AAF9AE843A7584B5A3E4CD2BCF45A512DE2DA058`.

When installing with Debian packages, you might prefer to place files in
`/etc/matrix-synapse/conf.d/` to override your configuration without editing
the main configuration file at `/etc/matrix-synapse/homeserver.yaml`.
By doing that, you won't be asked if you want to replace your configuration
file when you upgrade the Debian package to a later version.

##### Downstream Debian packages

Andrej Shadura maintains a
[`matrix-synapse`](https://packages.debian.org/sid/matrix-synapse) package in
the Debian repositories.
For `bookworm` and `sid`, it can be installed simply with:

```sh
sudo apt install matrix-synapse
```

Synapse is also available in `bullseye-backports`.  Please
see the [Debian documentation](https://backports.debian.org/Instructions/)
for information on how to use backports.

`matrix-synapse` is no longer maintained for `buster` and older.

##### Downstream Ubuntu packages

We do not recommend using the packages in the default Ubuntu repository
at this time, as they are [old and suffer from known security vulnerabilities](
    https://bugs.launchpad.net/ubuntu/+source/matrix-synapse/+bug/1848709
).
The latest version of Synapse can be installed from [our repository](#matrixorg-packages).

#### Fedora

Synapse is in the Fedora repositories as
[`matrix-synapse`](https://src.fedoraproject.org/rpms/matrix-synapse):

```sh
sudo dnf install matrix-synapse
```

Additionally, Oleg Girko provides Fedora RPMs at
<https://obs.infoserver.lv/project/monitor/matrix-synapse>

#### OpenSUSE

Synapse is in the OpenSUSE repositories as
[`matrix-synapse`](https://software.opensuse.org/package/matrix-synapse):

```sh
sudo zypper install matrix-synapse
```

#### SUSE Linux Enterprise Server

Unofficial package are built for SLES 15 in the openSUSE:Backports:SLE-15 repository at
<https://download.opensuse.org/repositories/openSUSE:/Backports:/SLE-15/standard/>

#### ArchLinux

The quickest way to get up and running with ArchLinux is probably with the package provided by ArchLinux
<https://archlinux.org/packages/extra/x86_64/matrix-synapse/>, which should pull in most of
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

#### Alpine Linux

6543 maintains [Synapse packages for Alpine Linux](https://pkgs.alpinelinux.org/packages?name=synapse&branch=edge) in the community repository. Install with:

```sh
sudo apk add synapse
```

#### Void Linux

Synapse can be found in the void repositories as
['synapse'](https://github.com/void-linux/void-packages/tree/master/srcpkgs/synapse):

```sh
xbps-install -Su
xbps-install -S synapse
```

#### FreeBSD

Synapse can be installed via FreeBSD Ports or Packages contributed by Brendan Molloy from:

- Ports: `cd /usr/ports/net-im/py-matrix-synapse && make install clean`
- Packages: `pkg install py38-matrix-synapse`

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
<https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/services/matrix/synapse.nix>


### Installing as a Python module from PyPI

It's also possible to install Synapse as a Python module from PyPI.

When following this route please make sure that the [Platform-specific prerequisites](#platform-specific-prerequisites) are already installed.

System requirements:

- POSIX-compliant system (tested on Linux & OS X)
- Python 3.8 or later, up to Python 3.11.
- At least 1GB of free RAM if you want to join large public rooms like #matrix:matrix.org

If building on an uncommon architecture for which pre-built wheels are
unavailable, you will need to have a recent Rust compiler installed. The easiest
way of installing the latest version is to use [rustup](https://rustup.rs/).

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

... substituting an appropriate value for `--server-name` and choosing whether
or not to report usage statistics (hostname, Synapse version, uptime, total
users, etc.) to the developers via the `--report-stats` argument.

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
                     libssl-dev virtualenv libjpeg-dev libxslt1-dev libicu-dev
```

##### ArchLinux

Installing prerequisites on ArchLinux:

```sh
sudo pacman -S base-devel python python-pip \
               python-setuptools python-virtualenv sqlite3 icu
```

##### CentOS/Fedora

Installing prerequisites on CentOS or Fedora Linux:

```sh
sudo dnf install libtiff-devel libjpeg-devel libzip-devel freetype-devel \
                 libwebp-devel libxml2-devel libxslt-devel libpq-devel \
                 python3-virtualenv libffi-devel openssl-devel python3-devel \
                 libicu-devel
sudo dnf groupinstall "Development Tools"
```

##### macOS

Installing prerequisites on macOS:

You may need to install the latest Xcode developer tools:
```sh
xcode-select --install
```

Some extra dependencies may be needed. You can use Homebrew (https://brew.sh) for them.

You may need to install icu, and make the icu binaries and libraries accessible.
Please follow [the official instructions of PyICU](https://pypi.org/project/PyICU/) to do so.

On ARM-based Macs you may also need to install libjpeg and libpq:
```sh
 brew install jpeg libpq
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
               python-devel libffi-devel libopenssl-devel libjpeg62-devel \
               libicu-devel
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

Running Synapse natively on Windows is not officially supported.

If you wish to run or develop Synapse on Windows, the Windows Subsystem for
Linux provides a Linux environment which is capable of using the Debian, Fedora,
or source installation methods. More information about WSL can be found at
<https://docs.microsoft.com/en-us/windows/wsl/install> for Windows 10/11 and
<https://docs.microsoft.com/en-us/windows/wsl/install-on-server> for
Windows Server.

## Setting up Synapse

Once you have installed synapse as above, you will need to configure it.

### Using PostgreSQL

By default Synapse uses an [SQLite](https://sqlite.org/) database and in doing so trades
performance for convenience. Almost all installations should opt to use [PostgreSQL](https://www.postgresql.org)
instead. Advantages include:

- significant performance improvements due to the superior threading and
  caching model, smarter query optimiser
- allowing the DB to be run on separate hardware

For information on how to install and use PostgreSQL in Synapse, please see
[Using Postgres](../postgres.md)

SQLite is only acceptable for testing purposes. SQLite should not be used in
a production server. Synapse will perform poorly when using
SQLite, especially when participating in large rooms.

### TLS certificates

The default configuration exposes a single HTTP port on the local
interface: `http://localhost:8008`. It is suitable for local testing,
but for any practical use, you will need Synapse's APIs to be served
over HTTPS.

The recommended way to do so is to set up a reverse proxy on port
`8448`. You can find documentation on doing so in
[the reverse proxy documentation](../reverse_proxy.md).

Alternatively, you can configure Synapse to expose an HTTPS port. To do
so, you will need to edit `homeserver.yaml`, as follows:

- First, under the `listeners` option, add the configuration for the
  TLS-enabled listener like so:

```yaml
listeners:
  - port: 8448
    type: http
    tls: true
    resources:
      - names: [client, federation]
  ```

- You will also need to add the options `tls_certificate_path` and
  `tls_private_key_path`. to your configuration file. You will need to manage provisioning of 
   these certificates yourself.
- You can find more information about these options as well as how to configure synapse in the 
  [configuration manual](../usage/configuration/config_documentation.md).

  If you are using your own certificate, be sure to use a `.pem` file that
  includes the full certificate chain including any intermediate certificates
  (for instance, if using certbot, use `fullchain.pem` as your certificate, not
  `cert.pem`).

For a more detailed guide to configuring your server for federation, see
[Federation](../federate.md).

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

One way to create a new user is to do so from a client like
[Element](https://element.io/).  This requires registration to be enabled via
the
[`enable_registration`](../usage/configuration/config_documentation.md#enable_registration)
setting.

Alternatively, you can create new users from the command line. This can be done as follows:

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
    register_new_matrix_user -c homeserver.yaml
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

This process uses a setting
[`registration_shared_secret`](../usage/configuration/config_documentation.md#registration_shared_secret),
which is shared between Synapse itself and the `register_new_matrix_user`
script. It doesn't matter what it is (a random value is generated by
`--generate-config`), but it should be kept secret, as anyone with knowledge of
it can register users, including admin accounts, on your server even if
`enable_registration` is `false`.

### Setting up a TURN server

For reliable VoIP calls to be routed via this homeserver, you MUST configure
a TURN server. See [TURN setup](../turn-howto.md) for details.

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
