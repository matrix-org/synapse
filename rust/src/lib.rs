use pyo3::prelude::*;

/// Formats the sum of two numbers as string.
#[pyfunction]
#[pyo3(text_signature = "(a, b, /)")]
fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
    Ok((a + b).to_string())
}

/// The entry point for defining the Python module.
#[pymodule]
fn synapse_rust(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;

    Ok(())
}
