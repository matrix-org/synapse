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

import re
import subprocess
import sys
import urllib.request
from os import path
from tempfile import TemporaryDirectory
from typing import List, Optional, Tuple

import attr
import click
import commonmark
import git
import redbaron
from click.exceptions import ClickException
from github import Github
from packaging import version


@click.group()
def cli():
    """An interactive script to walk through the parts of creating a release.

    Requires the dev dependencies be installed, which can be done via:

        pip install -e .[dev]

    Then to use:

        ./scripts-dev/release.py prepare

        # ... ask others to look at the changelog ...

        ./scripts-dev/release.py tag

        # ... wait for asssets to build ...

        ./scripts-dev/release.py publish
        ./scripts-dev/release.py upload

    If the env var GH_TOKEN (or GITHUB_TOKEN) is set, or passed into the
    `tag`/`publish` command, then a new draft release will be created/published.
    """


@cli.command()
def prepare():
    """Do the initial stages of creating a release, including creating release
    branch, updating changelog and pushing to GitHub.
    """

    # Make sure we're in a git repo.
    try:
        repo = git.Repo()
    except git.InvalidGitRepositoryError:
        raise click.ClickException("Not in Synapse repo.")

    if repo.is_dirty():
        raise click.ClickException("Uncommitted changes exist.")

    click.secho("Updating git repo...")
    repo.remote().fetch()

    # Get the current version and AST from root Synapse module.
    current_version, parsed_synapse_ast, version_node = parse_version_from_module()

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
    parsed_new_version = version.parse(new_version)

    # We assume for debian changelogs that we only do RCs or full releases.
    assert not parsed_new_version.is_devrelease
    assert not parsed_new_version.is_postrelease

    release_branch_name = (
        f"release-v{parsed_new_version.major}.{parsed_new_version.minor}"
    )
    release_branch = find_ref(repo, release_branch_name)
    if release_branch:
        if release_branch.is_remote():
            # If the release branch only exists on the remote we check it out
            # locally.
            repo.git.checkout(release_branch_name)
            release_branch = repo.active_branch
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
        repo.head.reference = base_branch
        repo.head.reset(index=True, working_tree=True)
        if not base_branch.is_remote():
            update_branch(repo)

        # Create the new release branch
        release_branch = repo.create_head(release_branch_name, commit=base_branch)

    # Switch to the release branch and ensure its up to date.
    repo.git.checkout(release_branch_name)
    update_branch(repo)

    # Update the `__version__` variable and write it back to the file.
    version_node.value = '"' + new_version + '"'
    with open("synapse/__init__.py", "w") as f:
        f.write(parsed_synapse_ast.dumps())

    # Generate changelogs
    subprocess.run("python3 -m towncrier", shell=True)

    # Generate debian changelogs
    if parsed_new_version.pre is not None:
        # If this is an RC then we need to coerce the version string to match
        # Debian norms, e.g. 1.39.0rc2 gets converted to 1.39.0~rc2.
        base_ver = parsed_new_version.base_version
        pre_type, pre_num = parsed_new_version.pre
        debian_version = f"{base_ver}~{pre_type}{pre_num}"
    else:
        debian_version = new_version

    subprocess.run(
        f'dch -M -v {debian_version} "New synapse release {debian_version}."',
        shell=True,
    )
    subprocess.run('dch -M -r -D stable ""', shell=True)

    # Show the user the changes and ask if they want to edit the change log.
    repo.git.add("-u")
    subprocess.run("git diff --cached", shell=True)

    if click.confirm("Edit changelog?", default=False):
        click.edit(filename="CHANGES.md")

    # Commit the changes.
    repo.git.add("-u")
    repo.git.commit(f"-m {new_version}")

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

    click.launch(
        f"https://github.com/matrix-org/synapse/blob/{repo.active_branch.name}/CHANGES.md"
    )


@cli.command()
@click.option("--gh-token", envvar=["GH_TOKEN", "GITHUB_TOKEN"])
def tag(gh_token: Optional[str]):
    """Tags the release and generates a draft GitHub release"""

    # Make sure we're in a git repo.
    try:
        repo = git.Repo()
    except git.InvalidGitRepositoryError:
        raise click.ClickException("Not in Synapse repo.")

    if repo.is_dirty():
        raise click.ClickException("Uncommitted changes exist.")

    click.secho("Updating git repo...")
    repo.remote().fetch()

    # Find out the version and tag name.
    current_version, _, _ = parse_version_from_module()
    tag_name = f"v{current_version}"

    # Check we haven't released this version.
    if tag_name in repo.tags:
        raise click.ClickException(f"Tag {tag_name} already exists!\n")

    # Get the appropriate changelogs and tag.
    changes = get_changes_for_version(current_version)

    click.echo_via_pager(changes)
    if click.confirm("Edit text?", default=False):
        changes = click.edit(changes, require_save=False)

    repo.create_tag(tag_name, message=changes)

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
        click.launch(f"https://github.com/matrix-org/synapse/releases/edit/{tag_name}")
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
    click.launch(release.html_url)
    click.launch(
        f"https://github.com/matrix-org/synapse/actions?query=branch%3A{tag_name}"
    )

    click.echo("Wait for release assets to be built")


@cli.command()
@click.option("--gh-token", envvar=["GH_TOKEN", "GITHUB_TOKEN"], required=True)
def publish(gh_token: str):
    """Publish release."""

    # Make sure we're in a git repo.
    try:
        repo = git.Repo()
    except git.InvalidGitRepositoryError:
        raise click.ClickException("Not in Synapse repo.")

    if repo.is_dirty():
        raise click.ClickException("Uncommitted changes exist.")

    current_version, _, _ = parse_version_from_module()
    tag_name = f"v{current_version}"

    if not click.confirm(f"Publish {tag_name}?", default=True):
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
def upload():
    """Upload release to pypi."""

    current_version, _, _ = parse_version_from_module()
    tag_name = f"v{current_version}"

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


def parse_version_from_module() -> Tuple[
    version.Version, redbaron.RedBaron, redbaron.Node
]:
    # Parse the AST and load the `__version__` node so that we can edit it
    # later.
    with open("synapse/__init__.py") as f:
        red = redbaron.RedBaron(f.read())

    version_node = None
    for node in red:
        if node.type != "assignment":
            continue

        if node.target.type != "name":
            continue

        if node.target.value != "__version__":
            continue

        version_node = node
        break

    if not version_node:
        print("Failed to find '__version__' definition in synapse/__init__.py")
        sys.exit(1)

    # Parse the current version.
    current_version = version.parse(version_node.value.value.strip('"'))
    assert isinstance(current_version, version.Version)

    return current_version, red, version_node


def find_ref(repo: git.Repo, ref_name: str) -> Optional[git.HEAD]:
    """Find the branch/ref, looking first locally then in the remote."""
    if ref_name in repo.refs:
        return repo.refs[ref_name]
    elif ref_name in repo.remote().refs:
        return repo.remote().refs[ref_name]
    else:
        return None


def update_branch(repo: git.Repo):
    """Ensure branch is up to date if it has a remote"""
    if repo.active_branch.tracking_branch():
        repo.git.merge(repo.active_branch.tracking_branch().name)


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


if __name__ == "__main__":
    cli()
