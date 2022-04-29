# A build script for poetry that adds the rust extension.

import os

from setuptools_rust import Binding, RustExtension


def build(setup_kwargs):
    original_project_dir = os.path.dirname(os.path.realpath(__file__))
    cargo_toml_path = os.path.join(original_project_dir, "rust", "Cargo.toml")

    extension = RustExtension(
        target="synapse.synapse_rust", path=cargo_toml_path, binding=Binding.PyO3
    )
    setup_kwargs.setdefault("rust_extensions", []).append(extension)
    setup_kwargs["zip_safe"] = False
