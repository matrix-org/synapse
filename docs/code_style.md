# Code Style

## Formatting tools

The Synapse codebase uses a number of code formatting tools in order to
quickly and automatically check for formatting (and sometimes logical)
errors in code.

The necessary tools are detailed below.

-   **black**

    The Synapse codebase uses [black](https://pypi.org/project/black/)
    as an opinionated code formatter, ensuring all comitted code is
    properly formatted.

    First install `black` with:

        pip install --upgrade black

    Have `black` auto-format your code (it shouldn't change any
    functionality) with:

        black . --exclude="\.tox|build|env"

-   **flake8**

    `flake8` is a code checking tool. We require code to pass `flake8`
    before being merged into the codebase.

    Install `flake8` with:

        pip install --upgrade flake8 flake8-comprehensions

    Check all application and test code with:

        flake8 synapse tests

-   **isort**

    `isort` ensures imports are nicely formatted, and can suggest and
    auto-fix issues such as double-importing.

    Install `isort` with:

        pip install --upgrade isort

    Auto-fix imports with:

        isort -rc synapse tests

    `-rc` means to recursively search the given directories.

It's worth noting that modern IDEs and text editors can run these tools
automatically on save. It may be worth looking into whether this
functionality is supported in your editor for a more convenient
development workflow. It is not, however, recommended to run `flake8` on
save as it takes a while and is very resource intensive.

## General rules

-   **Naming**:
    -   Use camel case for class and type names
    -   Use underscores for functions and variables.
-   **Docstrings**: should follow the [google code
    style](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings).
    See the
    [examples](http://sphinxcontrib-napoleon.readthedocs.io/en/latest/example_google.html)
    in the sphinx documentation.
-   **Imports**:
    -   Imports should be sorted by `isort` as described above.
    -   Prefer to import classes and functions rather than packages or
        modules.

        Example:

            from synapse.types import UserID
            ...
            user_id = UserID(local, server)

        is preferred over:

            from synapse import types
            ...
            user_id = types.UserID(local, server)

        (or any other variant).

        This goes against the advice in the Google style guide, but it
        means that errors in the name are caught early (at import time).

    -   Avoid wildcard imports (`from synapse.types import *`) and
        relative imports (`from .types import UserID`).

## Configuration file format

The [sample configuration file](./sample_config.yaml) acts as a
reference to Synapse's configuration options for server administrators.
Remember that many readers will be unfamiliar with YAML and server
administration in general, so that it is important that the file be as
easy to understand as possible, which includes following a consistent
format.

Some guidelines follow:

-   Sections should be separated with a heading consisting of a single
    line prefixed and suffixed with `##`. There should be **two** blank
    lines before the section header, and **one** after.
-   Each option should be listed in the file with the following format:
    -   A comment describing the setting. Each line of this comment
        should be prefixed with a hash (`#`) and a space.

        The comment should describe the default behaviour (ie, what
        happens if the setting is omitted), as well as what the effect
        will be if the setting is changed.

        Often, the comment end with something like "uncomment the
        following to <do action>".

    -   A line consisting of only `#`.
    -   A commented-out example setting, prefixed with only `#`.

        For boolean (on/off) options, convention is that this example
        should be the *opposite* to the default (so the comment will end
        with "Uncomment the following to enable [or disable]
        <feature>." For other options, the example should give some
        non-default value which is likely to be useful to the reader.

-   There should be a blank line between each option.
-   Where several settings are grouped into a single dict, *avoid* the
    convention where the whole block is commented out, resulting in
    comment lines starting `# #`, as this is hard to read and confusing
    to edit. Instead, leave the top-level config option uncommented, and
    follow the conventions above for sub-options. Ensure that your code
    correctly handles the top-level option being set to `None` (as it
    will be if no sub-options are enabled).
-   Lines should be wrapped at 80 characters.
-   Use two-space indents.

Example:

    ## Frobnication ##

    # The frobnicator will ensure that all requests are fully frobnicated.
    # To enable it, uncomment the following.
    #
    #frobnicator_enabled: true

    # By default, the frobnicator will frobnicate with the default frobber.
    # The following will make it use an alternative frobber.
    #
    #frobincator_frobber: special_frobber

    # Settings for the frobber
    #
    frobber:
      # frobbing speed. Defaults to 1.
      #
      #speed: 10

      # frobbing distance. Defaults to 1000.
      #
      #distance: 100

Note that the sample configuration is generated from the synapse code
and is maintained by a script, `scripts-dev/generate_sample_config`.
Making sure that the output from this script matches the desired format
is left as an exercise for the reader!
