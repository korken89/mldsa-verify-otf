//! Puts `memory.x` on the linker path and writes a Wycheproof test vector for each parameter set
//! to `OUT_DIR`.

use std::{env, fs, path::PathBuf};

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::copy("memory.x", out.join("memory.x")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");

    for set in [44, 65, 87] {
        let vectors = format!("../tests/data/wycheproof_mldsa_{set}_verify.json");
        println!("cargo:rerun-if-changed={vectors}");
        let groups: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(vectors).unwrap()).unwrap();
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
            fs::write(out.join(format!("{name}_{set}.bin")), bytes).unwrap();
        }
    }
}
