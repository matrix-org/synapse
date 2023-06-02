# Code Style

## Formatting tools

The Synapse codebase uses a number of code formatting tools in order to
quickly and automatically check for formatting (and sometimes logical)
errors in code.

The necessary tools are:

- [black](https://black.readthedocs.io/en/stable/), a source code formatter;
- [isort](https://pycqa.github.io/isort/), which organises each file's imports;
- [ruff](https://github.com/charliermarsh/ruff), which can spot common errors; and
- [mypy](https://mypy.readthedocs.io/en/stable/), a type checker.

See [the contributing guide](development/contributing_guide.md#run-the-linters) for instructions
on how to install the above tools and run the linters.

It's worth noting that modern IDEs and text editors can run these tools
automatically on save. It may be worth looking into whether this
functionality is supported in your editor for a more convenient
development workflow. It is not, however, recommended to run `mypy`
on save as it takes a while and can be very resource intensive.

## General rules

-   **Naming**:
    -   Use `CamelCase` for class and type names
    -   Use underscores for `function_names` and `variable_names`.
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

        ```python
        from synapse.types import UserID
        ...
        user_id = UserID(local, server)
        ```

        is preferred over:

        ```python
        from synapse import types
        ...
        user_id = types.UserID(local, server)
        ```

        (or any other variant).

        This goes against the advice in the Google style guide, but it
        means that errors in the name are caught early (at import time).

    -   Avoid wildcard imports (`from synapse.types import *`) and
        relative imports (`from .types import UserID`).

## Configuration code and documentation format

When adding a configuration option to the code, if several settings are grouped into a single dict, ensure that your code
correctly handles the top-level option being set to `None` (as it will be if no sub-options are enabled).

The [configuration manual](usage/configuration/config_documentation.md) acts as a
reference to Synapse's configuration options for server administrators.
Remember that many readers will be unfamiliar with YAML and server
administration in general, so it is important that when you add
a configuration option the documentation be as easy to understand as possible, which 
includes following a consistent format.

Some guidelines follow:

- Each option should be listed in the config manual with the following format:
      
    - The name of the option, prefixed by `###`. 

    - A comment which describes the default behaviour (i.e. what
        happens if the setting is omitted), as well as what the effect
        will be if the setting is changed.
    - An example setting, using backticks to define the code block

        For boolean (on/off) options, convention is that this example
        should be the *opposite* to the default. For other options, the example should give
        some non-default value which is likely to be useful to the reader.

- There should be a horizontal rule between each option, which can be achieved by adding `---` before and
  after the option.
- `true` and `false` are spelt thus (as opposed to `True`, etc.)

Example:

---
### `modules`

Use the `module` sub-option to add a module under `modules` to extend functionality. 
The `module` setting then has a sub-option, `config`, which can be used to define some configuration
for the `module`.

Defaults to none.

Example configuration:
```yaml
modules:
  - module: my_super_module.MySuperClass
    config:
      do_thing: true
  - module: my_other_super_module.SomeClass
    config: {}
```
---

Note that the sample configuration is generated from the synapse code
and is maintained by a script, `scripts-dev/generate_sample_config.sh`.
Making sure that the output from this script matches the desired format
is left as an exercise for the reader!

