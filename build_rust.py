# A build script for poetry that adds the rust extension.

import os
from typing import Any, Dict

from setuptools_rust import Binding, RustExtension


def build(setup_kwargs: Dict[str, Any]) -> None:
    original_project_dir = os.path.dirname(os.path.realpath(__file__))
    cargo_toml_path = os.path.join(original_project_dir, "rust", "Cargo.toml")

    extension = RustExtension(
        target="synapse.synapse_rust",
        path=cargo_toml_path,
        binding=Binding.PyO3,
        py_limited_api=True,
        # We force always building in release mode, as we can't tell the
        # difference between using `poetry` in development vs production.
        debug=False,
    )
    setup_kwargs.setdefault("rust_extensions", []).append(extension)
    setup_kwargs["zip_safe"] = False
