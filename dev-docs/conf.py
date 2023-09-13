# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "Synapse development"
copyright = "2023, The Matrix.org Foundation C.I.C."
author = "The Synapse Maintainers and Community"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "autodoc2",
    "myst_parser",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]


# -- Options for Autodoc2 ----------------------------------------------------

autodoc2_docstring_parser_regexes = [
    # this will render all docstrings as 'MyST' Markdown
    (r".*", "myst"),
]

autodoc2_packages = [
    {
        "path": "../synapse",
        # Don't render documentation for everything as a matter of course
        "auto_mode": False,
    },
]


# -- Options for MyST (Markdown) ---------------------------------------------

# myst_heading_anchors = 2


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "furo"
html_static_path = ["_static"]
