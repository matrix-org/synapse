use pyo3::prelude::*;

pub mod push;

/// Returns the hash of all the rust source files at the time it was compiled.
///
/// Used by python to detect if the rust library is outdated.
#[pyfunction]
fn get_rust_file_digest() -> &'static str {
    env!("SYNAPSE_RUST_DIGEST")
}

/// Formats the sum of two numbers as string.
#[pyfunction]
#[pyo3(text_signature = "(a, b, /)")]
fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
    Ok((a + b).to_string())
}

/// The entry point for defining the Python module.
#[pymodule]
fn synapse_rust(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    pyo3_log::init();

    m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    m.add_function(wrap_pyfunction!(get_rust_file_digest, m)?)?;

    push::register_module(py, m)?;

    Ok(())
}
