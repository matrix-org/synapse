#!/usr/bin/env python3

# Check that no schema deltas have been added to the wrong version.

import re
from typing import Any, Dict, List

import click
import git

SCHEMA_FILE_REGEX = re.compile(r"^synapse/storage/schema/(.*)/delta/(.*)/(.*)$")


@click.command()
@click.option(
    "--force-colors",
    is_flag=True,
    flag_value=True,
    default=None,
    help="Always output ANSI colours",
)
def main(force_colors: bool) -> None:
    click.secho(
        "+++ Checking schema deltas are in the right folder",
        fg="green",
        bold=True,
        color=force_colors,
    )

    click.secho("Updating repo...")

    repo = git.Repo()
    repo.remote().fetch()

    click.secho("Getting current schema version...")

    r = repo.git.show("origin/develop:synapse/storage/schema/__init__.py")

    locals: Dict[str, Any] = {}
    exec(r, locals)
    current_schema_version = locals["SCHEMA_VERSION"]

    diffs: List[git.Diff] = repo.remote().refs.develop.commit.diff(None)

    # Get the schema version of the local file to check against current schema on develop
    with open("synapse/storage/schema/__init__.py") as file:
        local_schema = file.read()
    new_locals: Dict[str, Any] = {}
    exec(local_schema, new_locals)
    local_schema_version = new_locals["SCHEMA_VERSION"]

    if local_schema_version != current_schema_version:
        # local schema version must be +/-1 the current schema version on develop
        if abs(local_schema_version - current_schema_version) != 1:
            click.secho(
                "The proposed schema version has diverged more than one version from develop, please fix!",
                fg="red",
                bold=True,
                color=force_colors,
            )
            click.get_current_context().exit(1)

        # right, we've changed the schema version within the allowable tolerance so
        # let's now use the local version as the canonical version
        current_schema_version = local_schema_version

    click.secho(f"Current schema version: {current_schema_version}")

    seen_deltas = False
    bad_files = []
    for diff in diffs:
        if not diff.new_file or diff.b_path is None:
            continue

        match = SCHEMA_FILE_REGEX.match(diff.b_path)
        if not match:
            continue

        seen_deltas = True

        _, delta_version, _ = match.groups()

        if delta_version != str(current_schema_version):
            bad_files.append(diff.b_path)

    if not seen_deltas:
        click.secho(
            "No deltas found.",
            fg="green",
            bold=True,
            color=force_colors,
        )
        return

    if not bad_files:
        click.secho(
            f"All deltas are in the correct folder: {current_schema_version}!",
            fg="green",
            bold=True,
            color=force_colors,
        )
        return

    bad_files.sort()

    click.secho(
        "Found deltas in the wrong folder!",
        fg="red",
        bold=True,
        color=force_colors,
    )

    for f in bad_files:
        click.secho(
            f"\t{f}",
            fg="red",
            bold=True,
            color=force_colors,
        )

    click.secho()
    click.secho(
        f"Please move these files to delta/{current_schema_version}/",
        fg="red",
        bold=True,
        color=force_colors,
    )

    click.get_current_context().exit(1)


if __name__ == "__main__":
    main()
