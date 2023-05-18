//! This build script calculates the hash of all files in the `src/`
//! directory and adds it as an environment variable during build time.
//!
//! This is used so that the python code can detect when the built native module
//! does not match the source in-tree, helping to detect the case where the
//! source has been updated but the library hasn't been rebuilt.

use std::path::PathBuf;

use blake2::{Blake2b512, Digest};

fn main() -> Result<(), std::io::Error> {
    let mut dirs = vec![PathBuf::from("src")];

    let mut paths = Vec::new();
    while let Some(path) = dirs.pop() {
        let mut entries = std::fs::read_dir(path)?
            .map(|res| res.map(|e| e.path()))
            .collect::<Result<Vec<_>, std::io::Error>>()?;

        entries.sort();

        for entry in entries {
            if entry.is_dir() {
                dirs.push(entry);
            } else {
                paths.push(entry.to_str().expect("valid rust paths").to_string());
            }
        }
    }

    paths.sort();

    let mut hasher = Blake2b512::new();

    for path in paths {
        let bytes = std::fs::read(path)?;
        hasher.update(bytes);
    }

    let hex_digest = hex::encode(hasher.finalize());
    println!("cargo:rustc-env=SYNAPSE_RUST_DIGEST={hex_digest}");

    Ok(())
}
