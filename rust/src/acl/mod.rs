// Copyright 2023 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! An implementation of Matrix server ACL rules.

use crate::push::utils::{glob_to_regex, GlobMatchType};
use anyhow::Error;
use pyo3::prelude::*;
use regex::Regex;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// Called when registering modules with python.
pub fn register_module(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    let child_module = PyModule::new(py, "acl")?;
    child_module.add_class::<ServerAclEvaluator>()?;

    m.add_submodule(child_module)?;

    // We need to manually add the module to sys.modules to make `from
    // synapse.synapse_rust import acl` work.
    py.import("sys")?
        .getattr("modules")?
        .set_item("synapse.synapse_rust.acl", child_module)?;

    Ok(())
}

#[derive(Debug, Clone)]
#[pyclass(frozen)]
pub struct ServerAclEvaluator {
    allow_ip_literals: bool,
    allow: Vec<Regex>,
    deny: Vec<Regex>,
}

#[pymethods]
impl ServerAclEvaluator {
    #[new]
    pub fn py_new(
        allow_ip_literals: bool,
        allow: Vec<String>,
        deny: Vec<String>,
    ) -> Result<Self, Error> {
        let allow = allow
            .iter()
            .map(|s| glob_to_regex(s, GlobMatchType::Whole).unwrap())
            .collect();
        let deny = deny
            .iter()
            .map(|s| glob_to_regex(s, GlobMatchType::Whole).unwrap())
            .collect();

        Ok(ServerAclEvaluator {
            allow_ip_literals,
            allow,
            deny,
        })
    }

    pub fn server_matches_acl_event(&self, server_name: &str) -> bool {
        // first of all, check if literal IPs are blocked, and if so, whether the
        // server name is a literal IP
        if !self.allow_ip_literals {
            // check for ipv6 literals. These start with '['.
            if server_name.starts_with("[") {
                return false;
            }

            // check for ipv4 literals. We can just lift the routine from std::net.
            if let Ok(_) = Ipv4Addr::from_str(server_name) {
                return false;
            }
        }

        // next,  check the deny list
        if self.deny.iter().any(|e| e.is_match(server_name)) {
            return false;
        }

        // then the allow list.
        if self.allow.iter().any(|e| e.is_match(server_name)) {
            return true;
        }

        // everything else should be rejected.
        false
    }
}
