use std::collections::HashMap;

use anyhow::Error;
use http::Request;
use hyper::Body;
use log::info;
use pyo3::{
    pyclass, pymethods,
    types::{PyBytes, PyModule},
    IntoPy, PyAny, PyObject, PyResult, Python, ToPyObject,
};

use self::resolver::{MatrixConnector, MatrixResolver};

mod resolver;

/// Called when registering modules with python.
pub fn register_module(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    let child_module = PyModule::new(py, "http")?;
    child_module.add_class::<HttpClient>()?;
    child_module.add_class::<MatrixResponse>()?;

    m.add_submodule(child_module)?;

    // We need to manually add the module to sys.modules to make `from
    // synapse.synapse_rust import push` work.
    py.import("sys")?
        .getattr("modules")?
        .set_item("synapse.synapse_rust.http", child_module)?;

    Ok(())
}

#[derive(Clone)]
struct Bytes(Vec<u8>);

impl ToPyObject for Bytes {
    fn to_object(&self, py: Python<'_>) -> pyo3::PyObject {
        PyBytes::new(py, &self.0).into_py(py)
    }
}

impl IntoPy<PyObject> for Bytes {
    fn into_py(self, py: Python<'_>) -> PyObject {
        self.to_object(py)
    }
}

#[pyclass]
pub struct MatrixResponse {
    #[pyo3(get)]
    code: u16,
    #[pyo3(get)]
    phrase: &'static str,
    #[pyo3(get)]
    content: Bytes,
    #[pyo3(get)]
    headers: HashMap<String, Bytes>,
}

#[pyclass]
#[derive(Clone)]
pub struct HttpClient {
    client: hyper::Client<MatrixConnector>,
}

impl HttpClient {
    pub fn new() -> Result<Self, Error> {
        let resolver = MatrixResolver::new()?;

        let client = hyper::Client::builder().build(MatrixConnector::with_resolver(resolver));

        Ok(HttpClient { client })
    }

    pub async fn async_request(
        &self,
        url: String,
        method: String,
        headers: HashMap<Vec<u8>, Vec<Vec<u8>>>,
        body: Option<Vec<u8>>,
    ) -> Result<MatrixResponse, Error> {
        let mut builder = Request::builder().method(&*method).uri(url);

        for (key, values) in headers {
            for value in values {
                builder = builder.header(key.clone(), value);
            }
        }

        let request = if let Some(body) = body {
            builder.body(Body::from(body))?
        } else {
            builder.body(Body::empty())?
        };

        let response = self.client.request(request).await?;

        let code = response.status().as_u16();
        let phrase = response.status().canonical_reason().unwrap_or_default();

        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), Bytes(v.as_bytes().to_owned())))
            .collect();

        let body = response.into_body();

        let bytes = hyper::body::to_bytes(body).await?;
        let content = Bytes(bytes.to_vec());

        info!("DONE");

        Ok(MatrixResponse {
            code,
            phrase,
            content,
            headers,
        })
    }
}

#[pymethods]
impl HttpClient {
    #[new]
    fn py_new() -> Result<Self, Error> {
        Self::new()
    }

    fn request<'a>(
        &'a self,
        py: Python<'a>,
        url: String,
        method: String,
        headers: HashMap<Vec<u8>, Vec<Vec<u8>>>,
        body: Option<Vec<u8>>,
    ) -> PyResult<&'a PyAny> {
        pyo3::prepare_freethreaded_python();
        info!("REQUEST");

        let client = self.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let resp = client.async_request(url, method, headers, body).await?;
            Ok(resp)
        })
    }
}
