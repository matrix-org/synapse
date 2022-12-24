use std::hash::Hash;

use anyhow::Error;
use pyo3::{
    pyclass, pymethods,
    types::{PyIterator, PyModule},
    IntoPy, PyAny, PyObject, PyResult, Python, ToPyObject,
};

use super::TreeCache;

pub fn register_module(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    let child_module = PyModule::new(py, "tree_cache")?;
    child_module.add_class::<PythonTreeCache>()?;
    child_module.add_class::<StringTreeCache>()?;

    m.add_submodule(child_module)?;

    // We need to manually add the module to sys.modules to make `from
    // synapse.synapse_rust import push` work.
    py.import("sys")?
        .getattr("modules")?
        .set_item("synapse.synapse_rust.tree_cache", child_module)?;

    Ok(())
}

struct HashablePyObject {
    obj: PyObject,
    hash: isize,
}

impl HashablePyObject {
    pub fn new(obj: &PyAny) -> Result<Self, Error> {
        let hash = obj.hash()?;

        Ok(HashablePyObject {
            obj: obj.to_object(obj.py()),
            hash,
        })
    }
}

impl IntoPy<PyObject> for &HashablePyObject {
    fn into_py(self, _: Python<'_>) -> PyObject {
        self.obj.clone()
    }
}

impl Hash for HashablePyObject {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

impl PartialEq for HashablePyObject {
    fn eq(&self, other: &Self) -> bool {
        let equal = Python::with_gil(|py| {
            let result = self.obj.as_ref(py).eq(other.obj.as_ref(py));
            result.unwrap_or(false)
        });

        equal
    }
}

impl Eq for HashablePyObject {}

#[pyclass]
struct PythonTreeCache(TreeCache<HashablePyObject, PyObject>);

#[pymethods]
impl PythonTreeCache {
    #[new]
    fn new() -> Self {
        PythonTreeCache(Default::default())
    }

    pub fn set(&mut self, key: &PyAny, value: PyObject) -> Result<(), Error> {
        let v: Vec<HashablePyObject> = key
            .iter()?
            .map(|obj| HashablePyObject::new(obj?))
            .collect::<Result<_, _>>()?;

        self.0.set(v, value)?;

        Ok(())
    }

    // pub fn get_node(&self, key: &PyAny) -> Result<Option<&TreeCacheNode<K, PyObject>>, Error> {
    //     todo!()
    // }

    pub fn get(&self, key: &PyAny) -> Result<Option<&PyObject>, Error> {
        let v: Vec<HashablePyObject> = key
            .iter()?
            .map(|obj| HashablePyObject::new(obj?))
            .collect::<Result<_, _>>()?;

        Ok(self.0.get(&v)?)
    }

    // pub fn pop_node(&mut self, key: &PyAny) -> Result<Option<TreeCacheNode<K, PyObject>>, Error> {
    //     todo!()
    // }

    pub fn pop(&mut self, key: &PyAny) -> Result<Option<PyObject>, Error> {
        let v: Vec<HashablePyObject> = key
            .iter()?
            .map(|obj| HashablePyObject::new(obj?))
            .collect::<Result<_, _>>()?;

        Ok(self.0.pop(&v)?)
    }

    pub fn clear(&mut self) {
        self.0.clear()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn values(&self) -> Vec<&PyObject> {
        self.0.values().collect()
    }

    pub fn items(&self) -> Vec<(Vec<&HashablePyObject>, &PyObject)> {
        todo!()
    }
}

#[pyclass]
struct StringTreeCache(TreeCache<String, String>);

#[pymethods]
impl StringTreeCache {
    #[new]
    fn new() -> Self {
        StringTreeCache(Default::default())
    }

    pub fn set(&mut self, key: &PyAny, value: String) -> Result<(), Error> {
        let key = key
            .iter()?
            .map(|o| o.expect("iter failed").extract().expect("not a string"));

        self.0.set(key, value)?;

        Ok(())
    }

    // pub fn get_node(&self, key: &PyAny) -> Result<Option<&TreeCacheNode<K, PyObject>>, Error> {
    //     todo!()
    // }

    pub fn get(&self, key: &PyAny) -> Result<Option<&String>, Error> {
        let key = key.iter()?.map(|o| {
            o.expect("iter failed")
                .extract::<String>()
                .expect("not a string")
        });

        Ok(self.0.get(key)?)
    }

    // pub fn pop_node(&mut self, key: &PyAny) -> Result<Option<TreeCacheNode<K, PyObject>>, Error> {
    //     todo!()
    // }

    pub fn pop(&mut self, key: Vec<String>) -> Result<Option<String>, Error> {
        Ok(self.0.pop(&key)?)
    }

    pub fn clear(&mut self) {
        self.0.clear()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn values(&self) -> Vec<&String> {
        self.0.values().collect()
    }

    pub fn items(&self) -> Vec<(Vec<&HashablePyObject>, &PyObject)> {
        todo!()
    }
}
