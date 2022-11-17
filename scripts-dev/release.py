#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""An interactive script for doing a release. See `cli()` below.
"""

import glob
import os
import re
import subprocess
import sys
import urllib.request
from os import path
from tempfile import TemporaryDirectory
from typing import Any, List, Optional, cast

import attr
import click
import commonmark
import git
from click.exceptions import ClickException
from github import Github
from packaging import version


def run_until_successful(
    command: str, *args: Any, **kwargs: Any
) -> subprocess.CompletedProcess:
    while True:
        completed_process = subprocess.run(command, *args, **kwargs)
        exit_code = completed_process.returncode
        if exit_code == 0:
            # successful, so nothing more to do here.
            return completed_process

        print(f"The command {command!r} failed with exit code {exit_code}.")
        print("Please try to correct the failure and then re-run.")
        click.confirm("Try again?", abort=True)


@click.group()
def cli() -> None:
    """An interactive script to walk through the parts of creating a release.

    Requires the dev dependencies be installed, which can be done via:

        pip install -e .[dev]

    Then to use:

        ./scripts-dev/release.py prepare

        # ... ask others to look at the changelog ...

        ./scripts-dev/release.py tag

        # ... wait for assets to build ...

        ./scripts-dev/release.py publish

        ./scripts-dev/release.py upload

        # Optional: generate some nice links for the announcement

        ./scripts-dev/release.py announce

    If the env var GH_TOKEN (or GITHUB_TOKEN) is set, or passed into the
    `tag`/`publish` command, then a new draft release will be created/published.
    """


@cli.command()
def prepare() -> None:
    """Do the initial stages of creating a release, including creating release
    branch, updating changelog and pushing to GitHub.
    """

    # Make sure we're in a git repo.
    repo = get_repo_and_check_clean_checkout()

    click.secho("Updating git repo...")
    repo.remote().fetch()

    # Get the current version and AST from root Synapse module.
    current_version = get_package_version()

    # Figure out what sort of release we're doing and calcuate the new version.
    rc = click.confirm("RC", default=True)
    if current_version.pre:
        # If the current version is an RC we don't need to bump any of the
        # version numbers (other than the RC number).
        if rc:
            new_version = "{}.{}.{}rc{}".format(
                current_version.major,
                current_version.minor,
                current_version.micro,
                current_version.pre[1] + 1,
            )
        else:
            new_version = "{}.{}.{}".format(
                current_version.major,
                current_version.minor,
                current_version.micro,
            )
    else:
        # If this is a new release cycle then we need to know if it's a minor
        # or a patch version bump.
        release_type = click.prompt(
            "Release type",
            type=click.Choice(("minor", "patch")),
            show_choices=True,
            default="minor",
        )

        if release_type == "minor":
            if rc:
                new_version = "{}.{}.{}rc1".format(
                    current_version.major,
                    current_version.minor + 1,
                    0,
                )
            else:
                new_version = "{}.{}.{}".format(
                    current_version.major,
                    current_version.minor + 1,
                    0,
                )
        else:
            if rc:
                new_version = "{}.{}.{}rc1".format(
                    current_version.major,
                    current_version.minor,
                    current_version.micro + 1,
                )
            else:
                new_version = "{}.{}.{}".format(
                    current_version.major,
                    current_version.minor,
                    current_version.micro + 1,
                )

    # Confirm the calculated version is OK.
    if not click.confirm(f"Create new version: {new_version}?", default=True):
        click.get_current_context().abort()

    # Switch to the release branch.
    # Cast safety: parse() won't return a version.LegacyVersion from our
    # version string format.
    parsed_new_version = cast(version.Version, version.parse(new_version))

    # We assume for debian changelogs that we only do RCs or full releases.
    assert not parsed_new_version.is_devrelease
    assert not parsed_new_version.is_postrelease

    release_branch_name = get_release_branch_name(parsed_new_version)
    release_branch = find_ref(repo, release_branch_name)
    if release_branch:
        if release_branch.is_remote():
            # If the release branch only exists on the remote we check it out
            # locally.
            repo.git.checkout(release_branch_name)
    else:
        # If a branch doesn't exist we create one. We ask which one branch it
        # should be based off, defaulting to sensible values depending on the
        # release type.
        if current_version.is_prerelease:
            default = release_branch_name
        elif release_type == "minor":
            default = "develop"
        else:
            default = "master"

        branch_name = click.prompt(
            "Which branch should the release be based on?", default=default
        )

        base_branch = find_ref(repo, branch_name)
        if not base_branch:
            print(f"Could not find base branch {branch_name}!")
            click.get_current_context().abort()

        # Check out the base branch and ensure it's up to date
        repo.head.set_reference(base_branch, "check out the base branch")
        repo.head.reset(index=True, working_tree=True)
        if not base_branch.is_remote():
            update_branch(repo)

        # Create the new release branch
        # Type ignore will no longer be needed after GitPython 3.1.28.
        # See https://github.com/gitpython-developers/GitPython/pull/1419
        repo.create_head(release_branch_name, commit=base_branch)  # type: ignore[arg-type]

    # Switch to the release branch and ensure it's up to date.
    repo.git.checkout(release_branch_name)
    update_branch(repo)

    # Update the version specified in pyproject.toml.
    subprocess.check_output(["poetry", "version", new_version])

    # Generate changelogs.
    generate_and_write_changelog(current_version, new_version)

    # Generate debian changelogs
    if parsed_new_version.pre is not None:
        # If this is an RC then we need to coerce the version string to match
        # Debian norms, e.g. 1.39.0rc2 gets converted to 1.39.0~rc2.
        base_ver = parsed_new_version.base_version
        pre_type, pre_num = parsed_new_version.pre
        debian_version = f"{base_ver}~{pre_type}{pre_num}"
    else:
        debian_version = new_version

    run_until_successful(
        f'dch -M -v {debian_version} "New Synapse release {new_version}."',
        shell=True,
    )
    run_until_successful('dch -M -r -D stable ""', shell=True)

    # Show the user the changes and ask if they want to edit the change log.
    repo.git.add("-u")
    subprocess.run("git diff --cached", shell=True)

    if click.confirm("Edit changelog?", default=False):
        click.edit(filename="CHANGES.md")

    # Commit the changes.
    repo.git.add("-u")
    repo.git.commit("-m", new_version)

    # We give the option to bail here in case the user wants to make sure things
    # are OK before pushing.
    if not click.confirm("Push branch to github?", default=True):
        print("")
        print("Run when ready to push:")
        print("")
        print(f"\tgit push -u {repo.remote().name} {repo.active_branch.name}")
        print("")
        sys.exit(0)

    # Otherwise, push and open the changelog in the browser.
    repo.git.push("-u", repo.remote().name, repo.active_branch.name)

    print("Opening the changelog in your browser...")
    print("Please ask others to give it a check.")
    click.launch(
        f"https://github.com/matrix-org/synapse/blob/{repo.active_branch.name}/CHANGES.md"
    )


@cli.command()
@click.option("--gh-token", envvar=["GH_TOKEN", "GITHUB_TOKEN"])
def tag(gh_token: Optional[str]) -> None:
    """Tags the release and generates a draft GitHub release"""

    # Make sure we're in a git repo.
    repo = get_repo_and_check_clean_checkout()

    click.secho("Updating git repo...")
    repo.remote().fetch()

    # Find out the version and tag name.
    current_version = get_package_version()
    tag_name = f"v{current_version}"

    # Check we haven't released this version.
    if tag_name in repo.tags:
        raise click.ClickException(f"Tag {tag_name} already exists!\n")

    # Check we're on the right release branch
    release_branch = get_release_branch_name(current_version)
    if repo.active_branch.name != release_branch:
        click.echo(
            f"Need to be on the release branch ({release_branch}) before tagging. "
            f"Currently on ({repo.active_branch.name})."
        )
        click.get_current_context().abort()

    # Get the appropriate changelogs and tag.
    changes = get_changes_for_version(current_version)

    click.echo_via_pager(changes)
    if click.confirm("Edit text?", default=False):
        edited_changes = click.edit(changes, require_save=False)
        # This assert is for mypy's benefit. click's docs are a little unclear, but
        # when `require_save=False`, not saving the temp file in the editor returns
        # the original string.
        assert edited_changes is not None
        changes = edited_changes

    repo.create_tag(tag_name, message=changes, sign=True)

    if not click.confirm("Push tag to GitHub?", default=True):
        print("")
        print("Run when ready to push:")
        print("")
        print(f"\tgit push {repo.remote().name} tag {current_version}")
        print("")
        return

    repo.git.push(repo.remote().name, "tag", tag_name)

    # If no token was given, we bail here
    if not gh_token:
        print("Launching the GitHub release page in your browser.")
        print("Please correct the title and create a draft.")
        if current_version.is_prerelease:
            print("As this is an RC, remember to mark it as a pre-release!")
        print("(by the way, this step can be automated by passing --gh-token,")
        print("or one of the GH_TOKEN or GITHUB_TOKEN env vars.)")
        click.launch(f"https://github.com/matrix-org/synapse/releases/edit/{tag_name}")

        print("Once done, you need to wait for the release assets to build.")
        if click.confirm("Launch the release assets actions page?", default=True):
            click.launch(
                f"https://github.com/matrix-org/synapse/actions?query=branch%3A{tag_name}"
            )
        return

    # Create a new draft release
    gh = Github(gh_token)
    gh_repo = gh.get_repo("matrix-org/synapse")
    release = gh_repo.create_git_release(
        tag=tag_name,
        name=tag_name,
        message=changes,
        draft=True,
        prerelease=current_version.is_prerelease,
    )

    # Open the release and the actions where we are building the assets.
    print("Launching the release page and the actions page.")
    click.launch(release.html_url)
    click.launch(
        f"https://github.com/matrix-org/synapse/actions?query=branch%3A{tag_name}"
    )

    click.echo("Wait for release assets to be built")


@cli.command()
@click.option("--gh-token", envvar=["GH_TOKEN", "GITHUB_TOKEN"], required=True)
def publish(gh_token: str) -> None:
    """Publish release on GitHub."""

    # Make sure we're in a git repo.
    get_repo_and_check_clean_checkout()

    current_version = get_package_version()
    tag_name = f"v{current_version}"

    if not click.confirm(f"Publish release {tag_name} on GitHub?", default=True):
        return

    # Publish the draft release
    gh = Github(gh_token)
    gh_repo = gh.get_repo("matrix-org/synapse")
    for release in gh_repo.get_releases():
        if release.title == tag_name:
            break
    else:
        raise ClickException(f"Failed to find GitHub release for {tag_name}")

    assert release.title == tag_name

    if not release.draft:
        click.echo("Release already published.")
        return

    release = release.update_release(
        name=release.title,
        message=release.body,
        tag_name=release.tag_name,
        prerelease=release.prerelease,
        draft=False,
    )


@cli.command()
def upload() -> None:
    """Upload release to pypi."""

    current_version = get_package_version()
    tag_name = f"v{current_version}"

    # Check we have the right tag checked out.
    repo = get_repo_and_check_clean_checkout()
    tag = repo.tag(f"refs/tags/{tag_name}")
    if repo.head.commit != tag.commit:
        click.echo("Tag {tag_name} (tag.commit) is not currently checked out!")
        click.get_current_context().abort()

    pypi_asset_names = [
        f"matrix_synapse-{current_version}-py3-none-any.whl",
        f"matrix-synapse-{current_version}.tar.gz",
    ]

    with TemporaryDirectory(prefix=f"synapse_upload_{tag_name}_") as tmpdir:
        for name in pypi_asset_names:
            filename = path.join(tmpdir, name)
            url = f"https://github.com/matrix-org/synapse/releases/download/{tag_name}/{name}"

            click.echo(f"Downloading {name} into {filename}")
            urllib.request.urlretrieve(url, filename=filename)

        if click.confirm("Upload to PyPI?", default=True):
            subprocess.run("twine upload *", shell=True, cwd=tmpdir)

    click.echo(
        f"Done! Remember to merge the tag {tag_name} into the appropriate branches"
    )


@cli.command()
def announce() -> None:
    """Generate markdown to announce the release."""

    current_version = get_package_version()
    tag_name = f"v{current_version}"

    click.echo(
        f"""
Hi everyone. Synapse {current_version} has just been released.

[notes](https://github.com/matrix-org/synapse/releases/tag/{tag_name}) | \
[docker](https://hub.docker.com/r/matrixdotorg/synapse/tags?name={tag_name}) | \
[debs](https://packages.matrix.org/debian/) | \
[pypi](https://pypi.org/project/matrix-synapse/{current_version}/)"""
    )

    if "rc" in tag_name:
        click.echo(
            """
Announce the RC in
- #homeowners:matrix.org (Synapse Announcements)
- #synapse-dev:matrix.org"""
        )
    else:
        click.echo(
            """
Announce the release in
- #homeowners:matrix.org (Synapse Announcements), bumping the version in the topic
- #synapse:matrix.org (Synapse Admins), bumping the version in the topic
- #synapse-dev:matrix.org
- #synapse-package-maintainers:matrix.org"""
        )


def get_package_version() -> version.Version:
    version_string = subprocess.check_output(["poetry", "version", "--short"]).decode(
        "utf-8"
    )
    return version.Version(version_string)


def get_release_branch_name(version_number: version.Version) -> str:
    return f"release-v{version_number.major}.{version_number.minor}"


def get_repo_and_check_clean_checkout() -> git.Repo:
    """Get the project repo and check it's not got any uncommitted changes."""
    try:
        repo = git.Repo()
    except git.InvalidGitRepositoryError:
        raise click.ClickException("Not in Synapse repo.")
    if repo.is_dirty():
        raise click.ClickException("Uncommitted changes exist.")
    return repo


def find_ref(repo: git.Repo, ref_name: str) -> Optional[git.HEAD]:
    """Find the branch/ref, looking first locally then in the remote."""
    if ref_name in repo.references:
        return repo.references[ref_name]
    elif ref_name in repo.remote().refs:
        return repo.remote().refs[ref_name]
    else:
        return None


def update_branch(repo: git.Repo) -> None:
    """Ensure branch is up to date if it has a remote"""
    tracking_branch = repo.active_branch.tracking_branch()
    if tracking_branch:
        repo.git.merge(tracking_branch.name)


def get_changes_for_version(wanted_version: version.Version) -> str:
    """Get the changelogs for the given version.

    If an RC then will only get the changelog for that RC version, otherwise if
    its a full release will get the changelog for the release and all its RCs.
    """

    with open("CHANGES.md") as f:
        changes = f.read()

    # First we parse the changelog so that we can split it into sections based
    # on the release headings.
    ast = commonmark.Parser().parse(changes)

    @attr.s(auto_attribs=True)
    class VersionSection:
        title: str

        # These are 0-based.
        start_line: int
        end_line: Optional[int] = None  # Is none if its the last entry

    headings: List[VersionSection] = []
    for node, _ in ast.walker():
        # We look for all text nodes that are in a level 1 heading.
        if node.t != "text":
            continue

        if node.parent.t != "heading" or node.parent.level != 1:
            continue

        # If we have a previous heading then we update its `end_line`.
        if headings:
            headings[-1].end_line = node.parent.sourcepos[0][0] - 1

        headings.append(VersionSection(node.literal, node.parent.sourcepos[0][0] - 1))

    changes_by_line = changes.split("\n")

    version_changelog = []  # The lines we want to include in the changelog

    # Go through each section and find any that match the requested version.
    regex = re.compile(r"^Synapse v?(\S+)")
    for section in headings:
        groups = regex.match(section.title)
        if not groups:
            continue

        heading_version = version.parse(groups.group(1))
        heading_base_version = version.parse(heading_version.base_version)

        # Check if heading version matches the requested version, or if its an
        # RC of the requested version.
        if wanted_version not in (heading_version, heading_base_version):
            continue

        version_changelog.extend(changes_by_line[section.start_line : section.end_line])

    return "\n".join(version_changelog)


def generate_and_write_changelog(
    current_version: version.Version, new_version: str
) -> None:
    # We do this by getting a draft so that we can edit it before writing to the
    # changelog.
    result = run_until_successful(
        f"python3 -m towncrier build --draft --version {new_version}",
        shell=True,
        capture_output=True,
    )
    new_changes = result.stdout.decode("utf-8")
    new_changes = new_changes.replace(
        "No significant changes.", f"No significant changes since {current_version}."
    )

    # Prepend changes to changelog
    with open("CHANGES.md", "r+") as f:
        existing_content = f.read()
        f.seek(0, 0)
        f.write(new_changes)
        f.write("\n")
        f.write(existing_content)

    # Remove all the news fragments
    for filename in glob.iglob("changelog.d/*.*"):
        os.remove(filename)


if __name__ == "__main__":
    cli()
