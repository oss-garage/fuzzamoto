use std::{path::Path, process::Command};

// Hypervisor cap on one feedback buffer (`VMCALL_FEEDBACK_BUFFER_MAX_SIZE`).
const FEEDBACK_BUFFER_MAX_SIZE: u32 = 256 * 4096;

// Get the afl coverage map size of the given binary.
fn get_map_size(binary: &Path) -> Option<String> {
    let output = String::from_utf8_lossy(
        &Command::new(binary)
            .env("AFL_DUMP_MAP_SIZE", "1")
            .output()
            .unwrap_or_else(|_| panic!("Failed to execute {:?}", binary.display()))
            .stdout,
    )
    .trim()
    .to_string();

    (!output.is_empty()).then_some(output)
}

fn main() {
    let mut build = cc::Build::new();
    build.file("src/bedrock-agent.c").include("src");

    if let Ok(path) = std::env::var("BITCOIND_PATH") {
        let path = Path::new(&path);
        if let Some(size) = get_map_size(path) {
            let parsed: u32 = size
                .parse()
                .unwrap_or_else(|e| panic!("AFL_DUMP_MAP_SIZE printed {size:?}, not a size: {e}"));
            assert!(
                parsed <= FEEDBACK_BUFFER_MAX_SIZE,
                "{}'s AFL++ coverage map is {parsed} bytes, over the hypervisor's \
                 {FEEDBACK_BUFFER_MAX_SIZE} byte feedback buffer cap.",
                path.display()
            );
            build.define("TARGET_MAP_SIZE", &*size);
        }
        println!("cargo:rerun-if-changed={}", path.display());
    }

    build.compile("bedrock_agent");

    println!("cargo:rerun-if-changed=src/bedrock-agent.c");
    println!("cargo:rerun-if-changed=src/libvmcall.h");
    println!("cargo:rerun-if-env-changed=BITCOIND_PATH");
}
