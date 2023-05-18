# Synapse Documentation

**The documentation is currently hosted [here](https://matrix-org.github.io/synapse).**
Please update any links to point to the new website instead.

## About

This directory currently holds a series of markdown files documenting how to install, use
and develop Synapse. The documentation is readable directly from this repository, but it is 
recommended to instead browse through the [website](https://matrix-org.github.io/synapse) for 
easier discoverability.

## Adding to the documentation

Most of the documentation currently exists as top-level files, as when organising them into
a structured website, these files were kept in place so that existing links would not break.
The rest of the documentation is stored in folders, such as `setup`, `usage`, and `development`
etc. **All new documentation files should be placed in structured folders.** For example:

To create a new user-facing documentation page about a new Single Sign-On protocol named
"MyCoolProtocol", one should create a new file with a relevant name, such as "my_cool_protocol.md".
This file might fit into the documentation structure at:

- Usage
  - Configuration
    - User Authentication
      - Single Sign-On
        - **My Cool Protocol**

Given that, one would place the new file under
`usage/configuration/user_authentication/single_sign_on/my_cool_protocol.md`.

Note that the structure of the documentation (and thus the left sidebar on the website) is determined
by the list in [SUMMARY.md](SUMMARY.md). The final thing to do when adding a new page is to add a new
line linking to the new documentation file:

```markdown
- [My Cool Protocol](usage/configuration/user_authentication/single_sign_on/my_cool_protocol.md)
```

## Building the documentation

The documentation is built with [mdbook](https://rust-lang.github.io/mdBook/), and the outline of the
documentation is determined by the structure of [SUMMARY.md](SUMMARY.md).

First, [get mdbook](https://github.com/rust-lang/mdBook#installation). Then, **from the root of the repository**,
build the documentation with:

```sh
mdbook build
```

The rendered contents will be outputted to a new `book/` directory at the root of the repository. Please note that 
index.html is not built by default, it is created by copying over the file `welcome_and_overview.html` to `index.html`
during deployment. Thus, when running `mdbook serve` locally the book will initially show a 404 in place of the index
due to the above. Do not be alarmed!

You can also have mdbook host the docs on a local webserver with hot-reload functionality via:

```sh
mdbook serve
```

The URL at which the docs can be viewed at will be logged.

## Configuration and theming

The look and behaviour of the website is configured by the [book.toml](../book.toml) file
at the root of the repository. See
[mdbook's documentation on configuration](https://rust-lang.github.io/mdBook/format/config.html)
for available options.

The site can be themed and additionally extended with extra UI and features. See
[website_files/README.md](website_files/README.md) for details.
