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

"""An interactive script for doing a release. See `run()` below.
"""

import subprocess
import sys
from typing import Optional

import click
import git
from packaging import version
from redbaron import RedBaron


@click.command()
def run():
    """An interactive script to walk through the initial stages of creating a
    release, including creating release branch, updating changelog and pushing to
    GitHub.

    Requires the dev dependencies be installed, which can be done via:

        pip install -e .[dev]

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

    # Parse the AST and load the `__version__` node so that we can edit it
    # later.
    with open("synapse/__init__.py") as f:
        red = RedBaron(f.read())

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
        f.write(red.dumps())

    # Generate changelogs
    subprocess.run("python3 -m towncrier", shell=True)

    # Generate debian changelogs if its not an RC.
    if not rc:
        subprocess.run(
            f'dch -M -v {new_version} "New synapse release {new_version}."', shell=True
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


if __name__ == "__main__":
    run()
