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

        let mut new_dirs = Vec::new();

        for entry in entries {
            if entry.is_dir() {
                new_dirs.push(entry);
            } else {
                paths.push(entry.to_str().expect("valid rust paths").to_string());
            }
        }

        dirs.append(&mut new_dirs);
    }

    let mut hasher = Blake2b512::new();

    paths.sort();

    for path in paths {
        let bytes = std::fs::read(path)?;
        hasher.update(bytes);
    }

    let hex_digest = hex::encode(hasher.finalize());
    println!("cargo:warning={hex_digest}");
    println!("cargo:rustc-env=SYNAPSE_RUST_DIGEST={hex_digest}");

    Ok(())
}
