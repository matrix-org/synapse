# Managing dependencies with Poetry

This is a quick cheat sheet for developers on how to use [`poetry`](https://python-poetry.org/).

# Installing

See the [contributing guide](contributing_guide.md#4-install-the-dependencies).

Developers should use Poetry 1.3.2 or higher. If you encounter problems related
to poetry, please [double-check your poetry version](#check-the-version-of-poetry-with-poetry---version).

# Background

Synapse uses a variety of third-party Python packages to function as a homeserver.
Some of these are direct dependencies, listed in `pyproject.toml` under the
`[tool.poetry.dependencies]` section. The rest are transitive dependencies (the
things that our direct dependencies themselves depend on, and so on recursively.)

We maintain a locked list of all our dependencies (transitive included) so that
we can track exactly which version of each dependency appears in a given release.
See [here](https://github.com/matrix-org/synapse/issues/11537#issue-1074469665)
for discussion of why we wanted this for Synapse. We chose to use
[`poetry`](https://python-poetry.org/) to manage this locked list; see
[this comment](https://github.com/matrix-org/synapse/issues/11537#issuecomment-1015975819)
for the reasoning.

The locked dependencies get included in our "self-contained" releases: namely,
our docker images and our debian packages. We also use the locked dependencies
in development and our continuous integration.

Separately, our "broad" dependencies—the version ranges specified in
`pyproject.toml`—are included as metadata in our "sdists" and "wheels" [uploaded
to PyPI](https://pypi.org/project/matrix-synapse). Installing from PyPI or from
the Synapse source tree directly will _not_ use the locked dependencies; instead,
they'll pull in the latest version of each package available at install time.

## Example dependency

An example may help. We have a broad dependency on
[`phonenumbers`](https://pypi.org/project/phonenumbers/), as declared in
this snippet from pyproject.toml [as of Synapse 1.57](
https://github.com/matrix-org/synapse/blob/release-v1.57/pyproject.toml#L133
):

```toml
[tool.poetry.dependencies]
# ...
phonenumbers = ">=8.2.0"
```

In our lockfile this is
[pinned]( https://github.com/matrix-org/synapse/blob/dfc7646504cef3e4ff396c36089e1c6f1b1634de/poetry.lock#L679-L685)
to version 8.12.44, even though
[newer versions are available](https://pypi.org/project/phonenumbers/#history).

```toml
[[package]]
name = "phonenumbers"
version = "8.12.44"
description = "Python version of Google's common library for parsing, formatting, storing and validating international phone numbers."
category = "main"
optional = false
python-versions = "*"
```

The lockfile also includes a
[cryptographic checksum](https://github.com/matrix-org/synapse/blob/release-v1.57/poetry.lock#L2178-L2181)
of the sdists and wheels provided for this version of `phonenumbers`.

```toml
[metadata.files]
# ...
phonenumbers = [
    {file = "phonenumbers-8.12.44-py2.py3-none-any.whl", hash = "sha256:cc1299cf37b309ecab6214297663ab86cb3d64ae37fd5b88e904fe7983a874a6"},
    {file = "phonenumbers-8.12.44.tar.gz", hash = "sha256:26cfd0257d1704fe2f88caff2caabb70d16a877b1e65b6aae51f9fbbe10aa8ce"},
]
```

We can see this pinned version inside the docker image for that release:

```
$ docker pull matrixdotorg/synapse:v1.57.0
...
$ docker run --entrypoint pip matrixdotorg/synapse:v1.57.0 show phonenumbers
Name: phonenumbers
Version: 8.12.44
Summary: Python version of Google's common library for parsing, formatting, storing and validating international phone numbers.
Home-page: https://github.com/daviddrysdale/python-phonenumbers
Author: David Drysdale
Author-email: dmd@lurklurk.org
License: Apache License 2.0
Location: /usr/local/lib/python3.9/site-packages
Requires:
Required-by: matrix-synapse
```

Whereas the wheel metadata just contains the broad dependencies:

```
$ cd /tmp
$ wget https://files.pythonhosted.org/packages/ca/5e/d722d572cc5b3092402b783d6b7185901b444427633bd8a6b00ea0dd41b7/matrix_synapse-1.57.0rc1-py3-none-any.whl
...
$ unzip -c matrix_synapse-1.57.0rc1-py3-none-any.whl matrix_synapse-1.57.0rc1.dist-info/METADATA | grep phonenumbers
Requires-Dist: phonenumbers (>=8.2.0)
```

# Tooling recommendation: direnv

[`direnv`](https://direnv.net/) is a tool for activating environments in your
shell inside a given directory. Its support for poetry is unofficial (a
community wiki recipe only), but works solidly in our experience. We thoroughly
recommend it for daily use. To use it:

1. [Install `direnv`](https://direnv.net/docs/installation.html) - it's likely
   packaged for your system already.
2. Teach direnv about poetry. The [shell config here](https://github.com/direnv/direnv/wiki/Python#poetry)
   needs to be added to `~/.config/direnv/direnvrc` (or more generally `$XDG_CONFIG_HOME/direnv/direnvrc`).
3. Mark the synapse checkout as a poetry project: `echo layout poetry > .envrc`.
4. Convince yourself that you trust this `.envrc` configuration and project.
   Then formally confirm this to `direnv` by running `direnv allow`.

Then whenever you navigate to the synapse checkout, you should be able to run
e.g. `mypy` instead of `poetry run mypy`; `python` instead of
`poetry run python`; and your shell commands will automatically run in the
context of poetry's venv, without having to run `poetry shell` beforehand.


# How do I...

## ...reset my venv to the locked environment?

```shell
poetry install --all-extras --sync
```

## ...delete everything and start over from scratch?

```shell
# Stop the current virtualenv if active
$ deactivate

# Remove all of the files from the current environment.
# Don't worry, even though it says "all", this will only
# remove the Poetry virtualenvs for the current project.
$ poetry env remove --all

# Reactivate Poetry shell to create the virtualenv again
$ poetry shell
# Install everything again
$ poetry install --extras all
```

## ...run a command in the `poetry` virtualenv?

Use `poetry run cmd args` when you need the python virtualenv context.
To avoid typing `poetry run` all the time, you can run  `poetry shell`
to start a new shell in the poetry virtualenv context. Within `poetry shell`,
`python`, `pip`, `mypy`, `trial`, etc. are all run inside the project virtualenv
and isolated from the rest o the system.

Roughly speaking, the translation from a traditional virtualenv is:
- `env/bin/activate` -> `poetry shell`, and
- `deactivate` -> close the terminal (Ctrl-D, `exit`, etc.)

See also the direnv recommendation above, which makes `poetry run` and
`poetry shell` unnecessary.


## ...inspect the `poetry` virtualenv?

Some suggestions:

```shell
# Current env only
poetry env info
# All envs: this allows you to have e.g. a poetry managed venv for Python 3.7,
# and another for Python 3.10.
poetry env list --full-path
poetry run pip list
```

Note that `poetry show` describes the abstract *lock file* rather than your
on-disk environment. With that said, `poetry show --tree` can sometimes be
useful.


## ...add a new dependency?

Either:
- manually update `pyproject.toml`; then `poetry lock --no-update`; or else
- `poetry add packagename`. See `poetry add --help`; note the `--dev`,
  `--extras` and `--optional` flags in particular.

Include the updated `pyproject.toml` and `poetry.lock` files in your commit.

## ...remove a dependency?

This is not done often and is untested, but

```shell
poetry remove packagename
```

ought to do the trick. Alternatively, manually update `pyproject.toml` and
`poetry lock --no-update`. Include the updated `pyproject.toml` and `poetry.lock`
files in your commit.

## ...update the version range for an existing dependency?

Best done by manually editing `pyproject.toml`, then `poetry lock --no-update`.
Include the updated `pyproject.toml` and `poetry.lock` in your commit.

## ...update a dependency in the locked environment?

Use

```shell
poetry update packagename
```

to use the latest version of `packagename` in the locked environment, without
affecting the broad dependencies listed in the wheel.

There doesn't seem to be a way to do this whilst locking a _specific_ version of
`packagename`. We can workaround this (crudely) as follows:

```shell
poetry add packagename==1.2.3
# This should update pyproject.lock.

# Now undo the changes to pyproject.toml. For example
# git restore pyproject.toml

# Get poetry to recompute the content-hash of pyproject.toml without changing
# the locked package versions.
poetry lock --no-update
```

Either way, include the updated `poetry.lock` file in your commit.

## ...export a `requirements.txt` file?

```shell
poetry export --extras all
```

Be wary of bugs in `poetry export` and `pip install -r requirements.txt`.

## ...build a test wheel?

I usually use

```shell
poetry run pip install build && poetry run python -m build
```

because [`build`](https://github.com/pypa/build) is a standardish tool which
doesn't require poetry. (It's what we use in CI too). However, you could try
`poetry build` too.

## ...handle a Dependabot pull request?

Synapse uses Dependabot to keep the `poetry.lock` and `Cargo.lock` file 
up-to-date with the latest releases of our dependencies. The changelog check is
omitted for Dependabot PRs; the release script will include them in the 
changelog.

When reviewing a dependabot PR, ensure that:

* the lockfile changes look reasonable;
* the upstream changelog file (linked in the description) doesn't include any
  breaking changes;
* continuous integration passes.

In particular, any updates to the type hints (usually packages which start with `types-`)
should be safe to merge if linting passes.

# Troubleshooting

## Check the version of poetry with `poetry --version`.

The minimum version of poetry supported by Synapse is 1.3.2.

It can also be useful to check the version of `poetry-core` in use. If you've
installed `poetry` with `pipx`, try `pipx runpip poetry list | grep
poetry-core`.

## Clear caches: `poetry cache clear --all pypi`.

Poetry caches a bunch of information about packages that isn't readily available
from PyPI. (This is what makes poetry seem slow when doing the first
`poetry install`.) Try `poetry cache list` and `poetry cache clear --all
<name of cache>` to see if that fixes things.

## Remove outdated egg-info

Delete the `matrix_synapse.egg-info/` directory from the root of your Synapse
install.

This stores some cached information about dependencies and often conflicts with
letting Poetry do the right thing.



## Try `--verbose` or `--dry-run` arguments.

Sometimes useful to see what poetry's internal logic is.
