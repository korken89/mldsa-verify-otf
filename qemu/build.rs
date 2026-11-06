//! Puts `memory.x` on the linker path and writes a Wycheproof test vector to `OUT_DIR`.

use std::{env, fs, path::PathBuf};

const VECTORS: &str = "../tests/data/wycheproof_mldsa_65_verify.json";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::copy("memory.x", out.join("memory.x")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed={VECTORS}");

    let groups: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(VECTORS).unwrap()).unwrap();
    let group = &groups[0];
    let case = group["tests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["valid"] == true && case["ctx"] == "")
        .unwrap();
    for (name, hex) in [
        ("pk", &group["pk"]),
        ("msg", &case["msg"]),
        ("sig", &case["sig"]),
    ] {
        let bytes = hex::decode(hex.as_str().unwrap()).unwrap();
        fs::write(out.join(format!("{name}.bin")), bytes).unwrap();
    }
}
