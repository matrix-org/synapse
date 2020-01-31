# Contributing code to Matrix

Everyone is welcome to contribute code to Matrix
(https://github.com/matrix-org), provided that they are willing to license
their contributions under the same license as the project itself. We follow a
simple 'inbound=outbound' model for contributions: the act of submitting an
'inbound' contribution means that the contributor agrees to license the code
under the same terms as the project's overall 'outbound' license - in our
case, this is almost always Apache Software License v2 (see [LICENSE](LICENSE)).

## How to contribute

The preferred and easiest way to contribute changes to Matrix is to fork the
relevant project on github, and then [create a pull request](
https://help.github.com/articles/using-pull-requests/) to ask us to pull
your changes into our repo.

**The single biggest thing you need to know is: please base your changes on
the develop branch - *not* master.**

We use the master branch to track the most recent release, so that folks who
blindly clone the repo and automatically check out master get something that
works. Develop is the unstable branch where all the development actually
happens: the workflow is that contributors should fork the develop branch to
make a 'feature' branch for a particular contribution, and then make a pull
request to merge this back into the matrix.org 'official' develop branch. We
use github's pull request workflow to review the contribution, and either ask
you to make any refinements needed or merge it and make them ourselves. The
changes will then land on master when we next do a release.

We use [Buildkite](https://buildkite.com/matrix-dot-org/synapse) for continuous
integration. If your change breaks the build, this will be shown in GitHub, so
please keep an eye on the pull request for feedback.

To run unit tests in a local development environment, you can use:

- ``tox -e py35`` (requires tox to be installed by ``pip install tox``)
  for SQLite-backed Synapse on Python 3.5.
- ``tox -e py36`` for SQLite-backed Synapse on Python 3.6.
- ``tox -e py36-postgres`` for PostgreSQL-backed Synapse on Python 3.6
  (requires a running local PostgreSQL with access to create databases).
- ``./test_postgresql.sh`` for PostgreSQL-backed Synapse on Python 3.5
  (requires Docker). Entirely self-contained, recommended if you don't want to
  set up PostgreSQL yourself.

Docker images are available for running the integration tests (SyTest) locally,
see the [documentation in the SyTest repo](
https://github.com/matrix-org/sytest/blob/develop/docker/README.md) for more
information.

## Code style

All Matrix projects have a well-defined code-style - and sometimes we've even
got as far as documenting it... For instance, synapse's code style doc lives
[here](docs/code_style.md).

To facilitate meeting these criteria you can run `scripts-dev/lint.sh`
locally. Since this runs the tools listed in the above document, you'll need
python 3.6 and to install each tool:

```
# Install the dependencies
pip install -U black flake8 isort

# Run the linter script
./scripts-dev/lint.sh
```

**Note that the script does not just test/check, but also reformats code, so you
may wish to ensure any new code is committed first**. By default this script
checks all files and can take some time; if you alter only certain files, you
might wish to specify paths as arguments to reduce the run-time:

```
./scripts-dev/lint.sh path/to/file1.py path/to/file2.py path/to/folder
```

Before pushing new changes, ensure they don't produce linting errors. Commit any
files that were corrected.

Please ensure your changes match the cosmetic style of the existing project,
and **never** mix cosmetic and functional changes in the same commit, as it
makes it horribly hard to review otherwise.


## Changelog

All changes, even minor ones, need a corresponding changelog / newsfragment
entry. These are managed by [Towncrier](https://github.com/hawkowl/towncrier).

To create a changelog entry, make a new file in the `changelog.d` directory named
in the format of `PRnumber.type`. The type can be one of the following:

* `feature`
* `bugfix`
* `docker` (for updates to the Docker image)
* `doc` (for updates to the documentation)
* `removal` (also used for deprecations)
* `misc` (for internal-only changes)

The content of the file is your changelog entry, which should be a short
description of your change in the same style as the rest of our [changelog](
https://github.com/matrix-org/synapse/blob/master/CHANGES.md). The file can
contain Markdown formatting, and should end with a full stop (.) or an
exclamation mark (!) for consistency.

Adding credits to the changelog is encouraged, we value your
contributions and would like to have you shouted out in the release notes!

For example, a fix in PR #1234 would have its changelog entry in
`changelog.d/1234.bugfix`, and contain content like "The security levels of
Florbs are now validated when received over federation. Contributed by Jane
Matrix.".

## Debian changelog

Changes which affect the debian packaging files (in `debian`) are an
exception.

In this case, you will need to add an entry to the debian changelog for the
next release. For this, run the following command:

```
dch
```

This will make up a new version number (if there isn't already an unreleased
version in flight), and open an editor where you can add a new changelog entry.
(Our release process will ensure that the version number and maintainer name is
corrected for the release.)

If your change affects both the debian packaging *and* files outside the debian
directory, you will need both a regular newsfragment *and* an entry in the
debian changelog. (Though typically such changes should be submitted as two
separate pull requests.)

## Sign off

In order to have a concrete record that your contribution is intentional
and you agree to license it under the same terms as the project's license, we've adopted the
same lightweight approach that the Linux Kernel
[submitting patches process](
https://www.kernel.org/doc/html/latest/process/submitting-patches.html#sign-your-work-the-developer-s-certificate-of-origin>),
[Docker](https://github.com/docker/docker/blob/master/CONTRIBUTING.md), and many other
projects use: the DCO (Developer Certificate of Origin:
http://developercertificate.org/). This is a simple declaration that you wrote
the contribution or otherwise have the right to contribute it to Matrix:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
660 York Street, Suite 102,
San Francisco, CA 94110 USA

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

If you agree to this for your contribution, then all that's needed is to
include the line in your commit or pull request comment:

```
Signed-off-by: Your Name <your@email.example.org>
```

We accept contributions under a legally identifiable name, such as
your name on government documentation or common-law names (names
claimed by legitimate usage or repute). Unfortunately, we cannot
accept anonymous contributions at this time.

Git allows you to add this signoff automatically when using the `-s`
flag to `git commit`, which uses the name and email set in your
`user.name` and `user.email` git configs.

## Conclusion

That's it! Matrix is a very open and collaborative project as you might expect
given our obsession with open communication. If we're going to successfully
matrix together all the fragmented communication technologies out there we are
reliant on contributions and collaboration from the community to do so. So
please get involved - and we hope you have as much fun hacking on Matrix as we
do!
