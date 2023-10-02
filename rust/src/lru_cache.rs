use std::sync::{Arc, Mutex};

use intrusive_collections::{intrusive_adapter, LinkedListAtomicLink};
use intrusive_collections::{LinkedList, LinkedListLink};
use lazy_static::lazy_static;
use log::error;
use pyo3::prelude::*;
use pyo3::types::PySet;

/// Called when registering modules with python.
pub fn register_module(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    let child_module = PyModule::new(py, "push")?;
    child_module.add_class::<LruCacheNode>()?;
    child_module.add_class::<PerCacheLinkedList>()?;
    child_module.add_function(wrap_pyfunction!(get_global_list, m)?)?;

    m.add_submodule(child_module)?;

    // We need to manually add the module to sys.modules to make `from
    // synapse.synapse_rust import push` work.
    py.import("sys")?
        .getattr("modules")?
        .set_item("synapse.synapse_rust.lru_cache", child_module)?;

    Ok(())
}

#[pyclass]
#[derive(Clone)]
struct PerCacheLinkedList(Arc<Mutex<LinkedList<LruCacheNodeAdapterPerCache>>>);

#[pymethods]
impl PerCacheLinkedList {
    #[new]
    fn new() -> PerCacheLinkedList {
        PerCacheLinkedList(Default::default())
    }

    fn get_back(&self) -> Option<LruCacheNode> {
        let list = self.0.lock().expect("poisoned");
        list.back().clone_pointer().map(|n| LruCacheNode(n))
    }
}

struct LruCacheNodeInner {
    per_cache_link: LinkedListAtomicLink,
    global_list_link: LinkedListAtomicLink,
    per_cache_list: Arc<Mutex<LinkedList<LruCacheNodeAdapterPerCache>>>,
    cache: Mutex<Option<PyObject>>,
    key: PyObject,
    value: Arc<Mutex<PyObject>>,
    callbacks: Py<PySet>,
    memory: usize,
    last_access_ts_secs: usize,
}

impl LruCacheNodeInner {
    fn update_last_access(&mut self, ts_secs: usize) {
        self.last_access_ts_secs = ts_secs;
    }
}

#[pyclass]
struct LruCacheNode(Arc<LruCacheNodeInner>);

#[pymethods]
impl LruCacheNode {
    #[new]
    fn py_new(
        cache: PyObject,
        cache_list: PerCacheLinkedList,
        key: PyObject,
        value: PyObject,
        callbacks: Py<PySet>,
        memory: usize,
        ts_secs: usize,
    ) -> Self {
        let node = Arc::new(LruCacheNodeInner {
            per_cache_link: Default::default(),
            global_list_link: Default::default(),
            per_cache_list: cache_list.0,
            cache: Mutex::new(Some(cache)),
            key,
            value: Arc::new(Mutex::new(value)),
            callbacks,
            memory,
            last_access_ts_secs: ts_secs,
        });

        GLOBAL_LIST
            .lock()
            .expect("posioned")
            .push_front(node.clone());

        node.per_cache_list
            .lock()
            .expect("posioned")
            .push_front(node.clone());

        LruCacheNode(node)
    }

    fn add_callbacks(&self, py: Python<'_>, new_callbacks: &PyAny) -> PyResult<()> {
        if new_callbacks.len()? == 0 {
            return Ok(());
        }

        let current_callbacks = self.0.callbacks.as_ref(py);

        for cb in new_callbacks.iter()? {
            current_callbacks.add(cb?)?;
        }

        Ok(())
    }

    fn run_and_clear_callbacks(&self, py: Python<'_>) {
        let callbacks = self.0.callbacks.as_ref(py);

        if callbacks.is_empty() {
            return;
        }

        for callback in callbacks {
            if let Err(err) = callback.call0() {
                error!("LruCacheNode callback errored: {err}");
            }
        }

        callbacks.clear();
    }

    fn drop_from_cache(&self) -> PyResult<()> {
        let cache = self.0.cache.lock().expect("poisoned").take();

        if let Some(cache) = cache {
            Python::with_gil(|py| cache.call_method1(py, "pop", (&self.0.key, None::<()>)))?;
        }

        self.drop_from_lists();

        Ok(())
    }

    fn drop_from_lists(&self) {
        if self.0.global_list_link.is_linked() {
            let mut glboal_list = GLOBAL_LIST.lock().expect("poisoned");

            let mut curor_mut = unsafe {
                // Getting the cursor is unsafe as we need to ensure the list link
                // belongs to the given list.
                glboal_list.cursor_mut_from_ptr(Arc::into_raw(self.0.clone()))
            };

            curor_mut.remove();
        }

        if self.0.per_cache_link.is_linked() {
            let mut per_cache_list = self.0.per_cache_list.lock().expect("poisoned");

            let mut curor_mut = unsafe {
                // Getting the cursor is unsafe as we need to ensure the list link
                // belongs to the given list.
                per_cache_list.cursor_mut_from_ptr(Arc::into_raw(self.0.clone()))
            };

            curor_mut.remove();
        }
    }

    fn move_to_front(&self, ts_secs: usize) {
        if self.0.global_list_link.is_linked() {
            let mut global_list = GLOBAL_LIST.lock().expect("poisoned");

            let mut curor_mut = unsafe {
                // Getting the cursor is unsafe as we need to ensure the list link
                // belongs to the given list.
                global_list.cursor_mut_from_ptr(Arc::into_raw(self.0.clone()))
            };
            curor_mut.remove();

            global_list.push_front(self.0.clone());

            // TODO Update self.0.last_access_ts_secs
        }

        if self.0.per_cache_link.is_linked() {
            let mut per_cache_list = self.0.per_cache_list.lock().expect("poisoned");

            let mut curor_mut = unsafe {
                // Getting the cursor is unsafe as we need to ensure the list link
                // belongs to the given list.
                per_cache_list.cursor_mut_from_ptr(Arc::into_raw(self.0.clone()))
            };

            curor_mut.remove();

            per_cache_list.push_front(self.0.clone());
        }
    }

    #[getter]
    fn key(&self) -> &PyObject {
        &self.0.key
    }

    #[getter]
    fn value(&self) -> PyObject {
        self.0.value.lock().expect("poisoned").clone()
    }

    #[setter]
    fn set_value(&self, value: PyObject) {
        *self.0.value.lock().expect("poisoned") = value
    }

    #[getter]
    fn memory(&self) -> usize {
        self.0.memory
    }

    #[getter]
    fn last_access_ts_secs(&self) -> usize { self.0.last_access_ts_secs }
}

#[pyfunction]
fn get_global_list() -> Vec<LruCacheNode> {
    let list = GLOBAL_LIST.lock().expect("poisoned");

    let mut vec = Vec::new();

    let mut cursor = list.front();

    while let Some(n) = cursor.clone_pointer() {
        vec.push(LruCacheNode(n));

        cursor.move_next();
    }

    vec
}

intrusive_adapter!(LruCacheNodeAdapterPerCache = Arc<LruCacheNodeInner>: LruCacheNodeInner { per_cache_link: LinkedListLink });
intrusive_adapter!(LruCacheNodeAdapterGlobal = Arc<LruCacheNodeInner>: LruCacheNodeInner { global_list_link: LinkedListLink });

lazy_static! {
    static ref GLOBAL_LIST_ADAPTER: LruCacheNodeAdapterGlobal = LruCacheNodeAdapterGlobal::new();
    static ref GLOBAL_LIST: Arc<Mutex<LinkedList<LruCacheNodeAdapterGlobal>>> =
        Arc::new(Mutex::new(LinkedList::new(GLOBAL_LIST_ADAPTER.clone())));
}
