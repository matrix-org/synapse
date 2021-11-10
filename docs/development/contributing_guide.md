# Contributing

This document aims to get you started with contributing to Synapse!

# 1. Who can contribute to Synapse?

Everyone is welcome to contribute code to [matrix.org
projects](https://github.com/matrix-org), provided that they are willing to
license their contributions under the same license as the project itself. We
follow a simple 'inbound=outbound' model for contributions: the act of
submitting an 'inbound' contribution means that the contributor agrees to
license the code under the same terms as the project's overall 'outbound'
license - in our case, this is almost always Apache Software License v2 (see
[LICENSE](https://github.com/matrix-org/synapse/blob/develop/LICENSE)).

# 2. What do I need?

If you are running Windows, the Windows Subsystem for Linux (WSL) is strongly
recommended for development. More information about WSL can be found at
<https://docs.microsoft.com/en-us/windows/wsl/install>. Running Synapse natively
on Windows is not officially supported.

The code of Synapse is written in Python 3. To do pretty much anything, you'll need [a recent version of Python 3](https://wiki.python.org/moin/BeginnersGuide/Download).

The source code of Synapse is hosted on GitHub. You will also need [a recent version of git](https://github.com/git-guides/install-git).

For some tests, you will need [a recent version of Docker](https://docs.docker.com/get-docker/).


# 3. Get the source.

The preferred and easiest way to contribute changes is to fork the relevant
project on GitHub, and then [create a pull request](
https://help.github.com/articles/using-pull-requests/) to ask us to pull your
changes into our repo.

Please base your changes on the `develop` branch.

```sh
git clone git@github.com:YOUR_GITHUB_USER_NAME/synapse.git
git checkout develop
```

If you need help getting started with git, this is beyond the scope of the document, but you
can find many good git tutorials on the web.

# 4. Install the dependencies

Once you have installed Python 3 and added the source, please open a terminal and
setup a *virtualenv*, as follows:

```sh
cd path/where/you/have/cloned/the/repository
python3 -m venv ./env
source ./env/bin/activate
pip install -e ".[all,dev]"
pip install tox
```

This will install the developer dependencies for the project.


# 5. Get in touch.

Join our developer community on Matrix: [#synapse-dev:matrix.org](https://matrix.to/#/#synapse-dev:matrix.org)!


# 6. Pick an issue.

Fix your favorite problem or perhaps find a [Good First Issue](https://github.com/matrix-org/synapse/issues?q=is%3Aopen+is%3Aissue+label%3A%22Good+First+Issue%22)
to work on.


# 7. Turn coffee into code and documentation!

There is a growing amount of documentation located in the
[`docs`](https://github.com/matrix-org/synapse/tree/develop/docs)
directory, with a rendered version [available online](https://matrix-org.github.io/synapse).
This documentation is intended primarily for sysadmins running their
own Synapse instance, as well as developers interacting externally with
Synapse.
[`docs/development`](https://github.com/matrix-org/synapse/tree/develop/docs/development)
exists primarily to house documentation for
Synapse developers.
[`docs/admin_api`](https://github.com/matrix-org/synapse/tree/develop/docs/admin_api) houses documentation
regarding Synapse's Admin API, which is used mostly by sysadmins and external
service developers.

Synapse's code style is documented [here](../code_style.md). Please follow
it, including the conventions for the [sample configuration
file](../code_style.md#configuration-file-format).

We welcome improvements and additions to our documentation itself! When
writing new pages, please
[build `docs` to a book](https://github.com/matrix-org/synapse/tree/develop/docs#adding-to-the-documentation)
to check that your contributions render correctly. The docs are written in
[GitHub-Flavoured Markdown](https://guides.github.com/features/mastering-markdown/).

Some documentation also exists in [Synapse's GitHub
Wiki](https://github.com/matrix-org/synapse/wiki), although this is primarily
contributed to by community authors.


# 8. Test, test, test!
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

Note that this script *will modify your files* to fix styling errors.
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

## Run the unit tests (Twisted trial).

The unit tests run parts of Synapse, including your changes, to see if anything
was broken. They are slower than the linters but will typically catch more errors.

```sh
source ./env/bin/activate
trial tests
```

If you wish to only run *some* unit tests, you may specify
another module instead of `tests` - or a test class or a method:

```sh
source ./env/bin/activate
trial tests.rest.admin.test_room tests.handlers.test_admin.ExfiltrateData.test_invite
```

If your tests fail, you may wish to look at the logs (the default log level is `ERROR`):

```sh
less _trial_temp/test.log
```

To increase the log level for the tests, set `SYNAPSE_TEST_LOG_LEVEL`:

```sh
SYNAPSE_TEST_LOG_LEVEL=DEBUG trial tests
```

### Running tests under PostgreSQL

Invoking `trial` as above will use an in-memory SQLite database. This is great for
quick development and testing. However, we recommend using a PostgreSQL database
in production (and indeed, we have some code paths specific to each database).
This means that we need to run our unit tests against PostgreSQL too. Our CI does
this automatically for pull requests and release candidates, but it's sometimes
useful to reproduce this locally.

To do so, [configure Postgres](../postgres.md) and run `trial` with the
following environment variables matching your configuration:

- `SYNAPSE_POSTGRES` to anything nonempty
- `SYNAPSE_POSTGRES_HOST`
- `SYNAPSE_POSTGRES_USER`
- `SYNAPSE_POSTGRES_PASSWORD`

For example:

```shell
export SYNAPSE_POSTGRES=1
export SYNAPSE_POSTGRES_HOST=localhost
export SYNAPSE_POSTGRES_USER=postgres
export SYNAPSE_POSTGRES_PASSWORD=mydevenvpassword
trial
```

#### Prebuilt container

Since configuring PostgreSQL can be fiddly, we can make use of a pre-made
Docker container to set up PostgreSQL and run our tests for us. To do so, run

```shell
scripts-dev/test_postgresql.sh
```

Any extra arguments to the script will be passed to `tox` and then to `trial`,
so we can run a specific test in this container with e.g.

```shell
scripts-dev/test_postgresql.sh tests.replication.test_sharded_event_persister.EventPersisterShardTestCase
```

The container creates a folder in your Synapse checkout called
`.tox-pg-container` and uses this as a tox environment. The output of any
`trial` runs goes into `_trial_temp` in your synapse source directory — the same
as running `trial` directly on your host machine.

## Run the integration tests ([Sytest](https://github.com/matrix-org/sytest)).

The integration tests are a more comprehensive suite of tests. They
run a full version of Synapse, including your changes, to check if
anything was broken. They are slower than the unit tests but will
typically catch more errors.

The following command will let you run the integration test with the most common
configuration:

```sh
$ docker run --rm -it -v /path/where/you/have/cloned/the/repository\:/src:ro -v /path/to/where/you/want/logs\:/logs matrixdotorg/sytest-synapse:buster
```

This configuration should generally cover  your needs. For more details about other configurations, see [documentation in the SyTest repo](https://github.com/matrix-org/sytest/blob/develop/docker/README.md).


## Run the integration tests ([Complement](https://github.com/matrix-org/complement)).

[Complement](https://github.com/matrix-org/complement) is a suite of black box tests that can be run on any homeserver implementation. It can also be thought of as end-to-end (e2e) tests.

It's often nice to develop on Synapse and write Complement tests at the same time.
Here is how to run your local Synapse checkout against your local Complement checkout.

(checkout [`complement`](https://github.com/matrix-org/complement) alongside your `synapse` checkout)
```sh
COMPLEMENT_DIR=../complement ./scripts-dev/complement.sh
```

To run a specific test file, you can pass the test name at the end of the command. The name passed comes from the naming structure in your Complement tests. If you're unsure of the name, you can do a full run and copy it from the test output:

```sh
COMPLEMENT_DIR=../complement ./scripts-dev/complement.sh TestBackfillingHistory
```

To run a specific test, you can specify the whole name structure:

```sh
COMPLEMENT_DIR=../complement ./scripts-dev/complement.sh TestBackfillingHistory/parallel/Backfilled_historical_events_resolve_with_proper_state_in_correct_order
```


### Access database for homeserver after Complement test runs.

If you're curious what the database looks like after you run some tests, here are some steps to get you going in Synapse:

1. In your Complement test comment out `defer deployment.Destroy(t)` and replace with `defer time.Sleep(2 * time.Hour)` to keep the homeserver running after the tests complete
1. Start the Complement tests
1. Find the name of the container, `docker ps -f name=complement_` (this will filter for just the Compelement related Docker containers)
1. Access the container replacing the name with what you found in the previous step: `docker exec -it complement_1_hs_with_application_service.hs1_2 /bin/bash`
1. Install sqlite (database driver), `apt-get update && apt-get install -y sqlite3`
1. Then run `sqlite3` and open the database `.open /conf/homeserver.db` (this db path comes from the Synapse homeserver.yaml)


# 9. Submit your patch.

Once you're happy with your patch, it's time to prepare a Pull Request.

To prepare a Pull Request, please:

1. verify that [all the tests pass](#test-test-test), including the coding style;
2. [sign off](#sign-off) your contribution;
3. `git push` your commit to your fork of Synapse;
4. on GitHub, [create the Pull Request](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request);
5. add a [changelog entry](#changelog) and push it to your Pull Request;
6. for most contributors, that's all - however, if you are a member of the organization `matrix-org`, on GitHub, please request a review from `matrix.org / Synapse Core`.
7. if you need to update your PR, please avoid rebasing and just add new commits to your branch.


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


# 10. Turn feedback into better code.

Once the Pull Request is opened, you will see a few things:

1. our automated CI (Continuous Integration) pipeline will run (again) the linters, the unit tests, the integration tests and more;
2. one or more of the developers will take a look at your Pull Request and offer feedback.

From this point, you should:

1. Look at the results of the CI pipeline.
    - If there is any error, fix the error.
2. If a developer has requested changes, make these changes and let us know if it is ready for a developer to review again.
3. Create a new commit with the changes.
    - Please do NOT overwrite the history. New commits make the reviewer's life easier.
    - Push this commits to your Pull Request.
4. Back to 1.

Once both the CI and the developers are happy, the patch will be merged into Synapse and released shortly!

# 11. Find a new issue.

By now, you know the drill!

# Notes for maintainers on merging PRs etc

There are some notes for those with commit access to the project on how we
manage git [here](git.md).

# Conclusion

That's it! Matrix is a very open and collaborative project as you might expect
given our obsession with open communication. If we're going to successfully
matrix together all the fragmented communication technologies out there we are
reliant on contributions and collaboration from the community to do so. So
please get involved - and we hope you have as much fun hacking on Matrix as we
do!
