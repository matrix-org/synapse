use std::collections::BTreeMap;

use anyhow::Context;
use base64::URL_SAFE_NO_PAD;
use pyo3::exceptions::PyAttributeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pythonize::pythonize;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use signed_json::Signed;

/*

depth: DictProperty[int] = DictProperty("depth")
    content: DictProperty[JsonDict] = DictProperty("content")
    hashes: DictProperty[Dict[str, str]] = DictProperty("hashes")
    origin: DictProperty[str] = DictProperty("origin")
    origin_server_ts: DictProperty[int] = DictProperty("origin_server_ts")
    redacts: DefaultDictProperty[Optional[str]] = DefaultDictProperty("redacts", None)
    room_id: DictProperty[str] = DictProperty("room_id")
    sender: DictProperty[str] = DictProperty("sender")
    # TODO state_key should be Optional[str]. This is generally asserted in Synapse
    # by calling is_state() first (which ensures it is not None), but it is hard (not possible?)
    # to properly annotate that calling is_state() asserts that state_key exists
    # and is non-None. It would be better to replace such direct references with
    # get_state_key() (and a check for None).
    state_key: DictProperty[str] = DictProperty("state_key")
    type: DictProperty[str] = DictProperty("type")
    user_id: DictProperty[str] = DictProperty("sender")

*/

// FYI origin is not included here

#[derive(Debug, Clone, Deserialize)]

struct EventInner {
    room_id: String,
    depth: u64,
    hashes: BTreeMap<String, String>,
    origin_server_ts: u64,
    redacts: Option<String>,
    sender: String,
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default)]
    state_key: Option<String>,

    content: BTreeMap<String, Value>,
}

#[pyclass]
#[derive(Debug, Clone, Deserialize)]
struct Event {
    #[pyo3(get)]
    event_id: String,
    #[serde(flatten)]
    inner: Signed<EventInner>,
}

#[pymethods]
impl Event {
    #[getter]
    fn room_id(&self) -> &str {
        &self.inner.room_id
    }

    fn get_pdu_json(&self) -> PyResult<String> {
        // TODO: Do all the other things `get_pdu_json` does.
        Ok(serde_json::to_string(&self.inner).context("bah")?)
    }

    #[getter]
    fn content(&self, py: Python) -> PyResult<PyObject> {
        Ok(pythonize(py, &self.inner.content)?)
    }

    #[getter]
    fn state_key(&self) -> PyResult<&str> {
        if let Some(state_key) = &self.inner.state_key {
            Ok(state_key)
        } else {
            Err(PyAttributeError::new_err("state_key"))
        }
    }
}

#[pyfunction]
fn from_bytes(bytes: &PyBytes) -> PyResult<Event> {
    let b = bytes.as_bytes();

    let inner: Signed<EventInner> = serde_json::from_slice(b).context("parsing event")?;

    let mut redacted: BTreeMap<String, Value> = redact(&inner).context("redacting")?;
    redacted.remove("signatures");
    redacted.remove("unsigned");
    let redacted_json = serde_json::to_vec(&redacted).context("BAH")?;

    let event_id = base64::encode_config(Sha256::digest(&redacted_json), URL_SAFE_NO_PAD);

    let event = Event { event_id, inner };

    Ok(event)
}

#[pymodule]
fn synapse_events(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(from_bytes, m)?)?;
    Ok(())
}

fn redact<E: serde::de::DeserializeOwned>(
    event: &Signed<EventInner>,
) -> Result<E, serde_json::Error> {
    let etype = event.event_type.to_string();
    let mut content = event.as_ref().content.clone();

    let val = serde_json::to_value(event)?;

    let allowed_keys = [
        "event_id",
        "sender",
        "room_id",
        "hashes",
        "signatures",
        "content",
        "type",
        "state_key",
        "depth",
        "prev_events",
        "prev_state",
        "auth_events",
        "origin",
        "origin_server_ts",
        "membership",
    ];

    let val = match val {
        serde_json::Value::Object(obj) => obj,
        _ => unreachable!(), // Events always serialize to an object
    };

    let mut val: serde_json::Map<_, _> = val
        .into_iter()
        .filter(|(k, _)| allowed_keys.contains(&(k as &str)))
        .collect();

    let mut new_content = serde_json::Map::new();

    let mut copy_content = |key: &str| {
        if let Some(v) = content.remove(key) {
            new_content.insert(key.to_string(), v);
        }
    };

    match &etype[..] {
        "m.room.member" => copy_content("membership"),
        "m.room.create" => copy_content("creator"),
        "m.room.join_rules" => copy_content("join_rule"),
        "m.room.aliases" => copy_content("aliases"),
        "m.room.history_visibility" => copy_content("history_visibility"),
        "m.room.power_levels" => {
            for key in &[
                "ban",
                "events",
                "events_default",
                "kick",
                "redact",
                "state_default",
                "users",
                "users_default",
            ] {
                copy_content(key);
            }
        }
        _ => {}
    }

    val.insert(
        "content".to_string(),
        serde_json::Value::Object(new_content),
    );

    serde_json::from_value(serde_json::Value::Object(val))
}
