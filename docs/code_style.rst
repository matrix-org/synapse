# Code Style

The Synapse codebase uses a number of code formatting tools in order to
quickly and automatically check for formatting (and sometimes logical) errors
in code.

The necessary tools are detailed below.

## Formatting tools

The Synapse codebase uses [black](https://pypi.org/project/black/) as an
opinionated code formatter, ensuring all comitted code is properly
formatted.

First install ``black`` with::

  pip install --upgrade black

Have ``black`` auto-format your code (it shouldn't change any
functionality) with::

  black . --exclude="\.tox|build|env"

- **flake8**

  ``flake8`` is a code checking tool. We require code to pass ``flake8`` before being merged into the codebase.

  Install ``flake8`` with::

    pip install --upgrade flake8

  Check all application and test code with::

    flake8 synapse tests

- **isort**

  ``isort`` ensures imports are nicely formatted, and can suggest and
  auto-fix issues such as double-importing.

  Install ``isort`` with::

    pip install --upgrade isort

  Auto-fix imports with::

    isort -rc synapse tests

  ``-rc`` means to recursively search the given directories.

It's worth noting that modern IDEs and text editors can run these tools
automatically on save. It may be worth looking into whether this
functionality is supported in your editor for a more convenient development
workflow. It is not, however, recommended to run ``flake8`` on save as it
takes a while and is very resource intensive.

## General rules

- **Naming**:

  - Use camel case for class and type names
  - Use underscores for functions and variables.

- Use double quotes ``"foo"`` rather than single quotes ``'foo'``.

- **Comments**: should follow the `google code style
  <http://google.github.io/styleguide/pyguide.html?showone=Comments#Comments>`_.
  This is so that we can generate documentation with `sphinx
  <http://sphinxcontrib-napoleon.readthedocs.org/en/latest/>`_. See the
  `examples
  <http://sphinxcontrib-napoleon.readthedocs.io/en/latest/example_google.html>`_
  in the sphinx documentation.

- **Imports**:

  - Prefer to import classes and functions rather than packages or modules.

    Example::

      from synapse.types import UserID
      ...
      user_id = UserID(local, server)

    is preferred over::

      from synapse import types
      ...
      user_id = types.UserID(local, server)

    (or any other variant).

    This goes against the advice in the Google style guide, but it means that
    errors in the name are caught early (at import time).

  - Multiple imports from the same package can be combined onto one line::

      from synapse.types import GroupID, RoomID, UserID

    An effort should be made to keep the individual imports in alphabetical
    order.

    If the list becomes long, wrap it with parentheses and split it over
    multiple lines.

  - As per `PEP-8 <https://www.python.org/dev/peps/pep-0008/#imports>`_,
    imports should be grouped in the following order, with a blank line between
    each group:

    1. standard library imports
    2. related third party imports
    3. local application/library specific imports

  - Imports within each group should be sorted alphabetically by module name.

  - Avoid wildcard imports (``from synapse.types import *``) and relative
    imports (``from .types import UserID``).
