Welcome to Synapse

This document aims to get you started with contributing to this repo! 

- [1. Who can contribute to Synapse?](#1-who-can-contribute-to-synapse-)
- [2. What do I need?](#2-what-do-i-need-)
  * [Under Unix (macOS, Linux, BSD, ...)](#under-unix--macos--linux--bsd---)
  * [Under Windows](#under-windows)
- [3. Get the source.](#3-get-the-source)
- [4. Get in touch.](#4-get-in-touch)
- [5. Pick an issue.](#5-pick-an-issue)
- [6. Turn coffee and documentation into code and documentation!](#6-turn-coffee-and-documentation-into-code-and-documentation-)
- [7. Test, test, test!](#7-test--test--test-)
  * [Run the linters.](#run-the-linters)
  * [Run the unit tests.](#run-the-unit-tests)
  * [Run the integration tests.](#run-the-integration-tests)
- [8. Submit your patch.](#8-submit-your-patch)
  * [Changelog](#changelog)
    + [How do I know what to call the changelog file before I create the PR?](#how-do-i-know-what-to-call-the-changelog-file-before-i-create-the-pr-)
    + [Debian changelog](#debian-changelog)
  * [Sign off](#sign-off)
- [9. Turn feedback into better code.](#9-turn-feedback-into-better-code)
- [10. Find a new issue.](#10-find-a-new-issue)
- [Notes for maintainers on merging PRs etc](#notes-for-maintainers-on-merging-prs-etc)
- [Conclusion](#conclusion)


# 1. Who can contribute to Synapse?

Everyone is welcome to contribute code to [matrix.org
projects](https://github.com/matrix-org), provided that they are willing to
license their contributions under the same license as the project itself. We
follow a simple 'inbound=outbound' model for contributions: the act of
submitting an 'inbound' contribution means that the contributor agrees to
license the code under the same terms as the project's overall 'outbound'
license - in our case, this is almost always Apache Software License v2 (see
[LICENSE](LICENSE)).

# 2. What do I need?

The code of Synapse is written in Python 3. To do pretty much anything, you'll need [a recent version of Python 3](https://wiki.python.org/moin/BeginnersGuide/Download).

The source code of Synapse is hosted on Github. You will also need [a recent version of git](https://github.com/git-guides/install-git).

For some tests, you will need [a recent version of Docker](https://docs.docker.com/get-docker/).

## Under Unix (macOS, Linux, BSD, ...)

Once you have installed Python 3, please open a Terminal and run:

```sh
mkdir -p ~/synapse
python3 -m venv ./env
source ./env/bin/activate
pip install -e ".[all,lint,mypy,test]"
pip install tox
```

This will install the developer dependencies for the project.

## Under Windows

TBD


# 3. Get the source.

The preferred and easiest way to contribute changes is to fork the relevant
project on github, and then [create a pull request](
https://help.github.com/articles/using-pull-requests/) to ask us to pull your
changes into our repo.

Please base your changes on the `develop` branch.

```sh
git clone git@github.com:YOUR_GITHUB_USER_NAME/synapse.git
```

# 4. Get in touch.

Join our developer community on Matrix: #synapse-dev:matrix.org !


# 5. Pick an issue.

Fix your favorite problem or perhaps find a [Good First Issue](https://github.com/matrix-org/synapse/issues?q=is%3Aopen+is%3Aissue+label%3A%22Good+First+Issue%22)
to work on.


# 6. Turn coffee and documentation into code and documentation!

Synapse's code style is documented [here](docs/code_style.md). Please follow
it, including the conventions for the [sample configuration
file](docs/code_style.md#configuration-file-format).

There is a growing amount of documentation located in the [docs](docs)
directory. This documentation is intended primarily for sysadmins running their
own Synapse instance, as well as developers interacting externally with
Synapse. [docs/dev](docs/dev) exists primarily to house documentation for
Synapse developers. [docs/admin_api](docs/admin_api) houses documentation
regarding Synapse's Admin API, which is used mostly by sysadmins and external
service developers.

If you add new files added to either of these folders, please use [Github-Flavoured
Markdown](https://guides.github.com/features/mastering-markdown/).

Some documentation also exists in [Synapse's Github
Wiki](https://github.com/matrix-org/synapse/wiki), although this is primarily
contributed to by community authors.


# 7. Test, test, test!
<a name="test-test-test"></a>

While you're developing and before submitting a patch, you'll
want to test your code.

## Run the linters.

The linters look at your code and do two things:

- ensure that your code follows the coding style adopted by the project;
- catch a number of errors in your code.

They're pretty fast, don't hesitate!

```sh
source ./env/bin/activate
./scripts-dev/lint.sh
```

Note that the linters *will modify your files* to fix styling errors.
Make sure that you have saved all your files.

If you wish to restrict the linters to only the files changed since the last commit
(much faster!), you can instead run:

```sh
source ./env/bin/activate
./scripts-dev/lint.sh -d
```

Or if you know exactly which files you wish to lint, you can instead run:

```sh
source ./env/bin/activate
./scripts-dev/lint.sh path/to/file1.py path/to/file2.py path/to/folder
```

## Run the unit tests.

The unit tests run parts of Synapse, including your changes, to see if anything
was broken. They are slower than the linters but will typically catch more errors.

```sh
source ./env/bin/activate
python -m twisted.trial tests
```

If you wish to only run *some* unit tests, you may specify
another module instead of `tests` - or a test class or a method:

```sh
source ./env/bin/activate
python -m twisted.trial tests.rest.admin.test_room tests.handlers.test_admin.ExfiltrateData.test_invite
```

If your tests fail, you may wish to look at the logs:

```sh
less _trial_temp/test.log
```

## Run the integration tests.

The integration tests run a full Synapse, including your changes, to
see if anything was broken. They are slower than the unit tests but will
typically catch more errors.

To run the entire test suite using Sqlite3, use the following command:

```sh
source ./env/bin/activate
tox -e py36
```

If you wish to only run *some* integration tests, you may
similarly specify a module, e.g.:

```sh
source ./env/bin/activate
tox -e py36 -- test.rest.admin.test_room
```



Or, to run the test suite using postgres, use the following command. You will need [Docker](https://docs.docker.com/get-docker/) installed.

```sh
source ./env/bin/activate
./test_postgresql.sh
```


# 8. Submit your patch.

Once you're happy with your patch, it's time to prepare a Pull Request.

To prepare a Pull Request, please:

1. verify that [all the tests pass](#test-test-test), including the coding style;
2. add a [changelog entry](#changelog);
3. [sign off](#sign-off) your contribution;
4. Push code to commits to your fork of Synapse:
```sh
git push origin develop
```
5. on Github, [create the Pull Request](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request);
6. on Github, request review from `matrix.org / Synapse Core`.

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

This file will become part of our [changelog](
https://github.com/matrix-org/synapse/blob/master/CHANGES.md) at the next
release, so the content of the file should be a short description of your
change in the same style as the rest of the changelog. The file can contain Markdown
formatting, and should end with a full stop (.) or an exclamation mark (!) for
consistency.

Adding credits to the changelog is encouraged, we value your
contributions and would like to have you shouted out in the release notes!

For example, a fix in PR #1234 would have its changelog entry in
`changelog.d/1234.bugfix`, and contain content like:

> The security levels of Florbs are now validated when received
> via the `/federation/florb` endpoint. Contributed by Jane Matrix.

If there are multiple pull requests involved in a single bugfix/feature/etc,
then the content for each `changelog.d` file should be the same. Towncrier will
merge the matching files together into a single changelog entry when we come to
release.

### How do I know what to call the changelog file before I create the PR?

Obviously, you don't know if you should call your newsfile
`1234.bugfix` or `5678.bugfix` until you create the PR, which leads to a
chicken-and-egg problem.

There are two options for solving this:

 1. Open the PR without a changelog file, see what number you got, and *then*
    add the changelog file to your branch (see [Updating your pull
    request](#updating-your-pull-request)), or:

 1. Look at the [list of all
    issues/PRs](https://github.com/matrix-org/synapse/issues?q=), add one to the
    highest number you see, and quickly open the PR before somebody else claims
    your number.

    [This
    script](https://github.com/richvdh/scripts/blob/master/next_github_number.sh)
    might be helpful if you find yourself doing this a lot.

Sorry, we know it's a bit fiddly, but it's *really* helpful for us when we come
to put together a release!

### Debian changelog

Changes which affect the debian packaging files (in `debian`) are an
exception to the rule that all changes require a `changelog.d` file.

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


# 9. Turn feedback into better code.

Once the Pull Request is opened, you will see a few things:

1. our automated CI (Continuous Integration) pipeline will run (again) the linters, the unit tests, the integration tests and more;
2. one or more of the developers will take a look at your Pull Request and offer feedback.

From this point, you should:

1. Look at the results of the CI pipeline.
  - If there is any error, fix the error.
2. If a developer has requested changes, make these changes.
3. Create a new commit with the changes.
  - Please [do NOT overwrite the history](docs/dev/git.md#on-keeping-the-commit-history-clean). New commits make the reviewer's life easier.
  - Push this commits to your Pull Request.
4. Back to 1.

Once both the CI and the developers are happy, the patch will be merged into Synapse and released shortly!

# 10. Find a new issue.

By now, you know the drill!

# Notes for maintainers on merging PRs etc

There are some notes for those with commit access to the project on how we
manage git [here](docs/dev/git.md).

# Conclusion

That's it! Matrix is a very open and collaborative project as you might expect
given our obsession with open communication. If we're going to successfully
matrix together all the fragmented communication technologies out there we are
reliant on contributions and collaboration from the community to do so. So
please get involved - and we hope you have as much fun hacking on Matrix as we
do!
