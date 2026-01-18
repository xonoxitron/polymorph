// WASM-specific tests

use std::fs;
use std::io::Write;

#[test]
fn test_wasm_magic_detection() {
    let temp_file = "test_wasm.wasm";
    let mut file = fs::File::create(temp_file).expect("Failed to create test file");
    
    // WASM magic: \0asm version 1
    file.write_all(&[0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00])
        .expect("Failed to write");
    
    let output = std::process::Command::new("cargo")
        .args(&["run", "--release", "--", temp_file])
        .output()
        .expect("Failed to execute");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Wasm") || stdout.contains("WebAssembly"));
    
    fs::remove_file(temp_file).ok();
}

#[test]
fn test_wasm_cryptominer_detection() {
    let temp_file = "test_miner.wasm";
    let mut file = fs::File::create(temp_file).expect("Failed to create test file");
    
    // WASM header + cryptomining indicators
    file.write_all(&[0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00])
        .expect("Failed to write");
    file.write_all(b"cryptonight keccak WebGL Worker")
        .expect("Failed to write");
    
    let output = std::process::Command::new("cargo")
        .args(&["run", "--release", "--", temp_file])
        .output()
        .expect("Failed to execute");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("crypto") || stdout.contains("mining"));
    
    fs::remove_file(temp_file).ok();
}
