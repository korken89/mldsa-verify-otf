//! Puts the `memory.x` of the QEMU machine on the linker path, names the core for the binary in
//! `CORE` and writes a Wycheproof test vector for each parameter set to `OUT_DIR`.

use std::{env, fs, path::PathBuf};

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let (core, memory) = match env::var("TARGET").unwrap().as_str() {
        "thumbv7m-none-eabi" => ("Cortex-M3", "memory-an385.x"),
        "thumbv8m.main-none-eabihf" => ("Cortex-M33", "memory-an505.x"),
        target => panic!("no QEMU machine for {target}"),
    };
    fs::copy(memory, out.join("memory.x")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed={memory}");
    println!("cargo:rustc-env=CORE={core}");

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
