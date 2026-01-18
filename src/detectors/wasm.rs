use super::{Detection, DetectionCategory, Severity, find_pattern};

const WASM_MAGIC: &[u8] = &[0x00, 0x61, 0x73, 0x6D];
const WASM_VERSION_1: &[u8] = &[0x01, 0x00, 0x00, 0x00];

const SUSPICIOUS_IMPORTS: &[&str] = &[
    "crypto.subtle", "crypto.getRandomValues", 
    "WebGL", "gpu", "WebGPU",
    "Worker", "SharedArrayBuffer",
    "fetch", "XMLHttpRequest", "WebSocket",
    "navigator.sendBeacon",
    "document.createElement", "eval", "Function",
    "document.write", "innerHTML",
    "FileReader", "Blob", "File",
    "coinhive", "cryptonight", "monero", "xmrig",
    "authedmine", "crypto-loot", "coinimp",
];

const CRYPTOMINER_PATTERNS: &[&str] = &[
    "keccak", "sha3", "blake2", "groestl", "jh", "skein",
    "cryptonight", "cn/r", "cn/half", "cn/2",
];

const OBFUSCATION_INDICATORS: &[&str] = &[
    "_0x", "0x", "$_", "$$", "__", "eval", "atob", "btoa",
];

pub fn scan_wasm_format(data: &[u8], detections: &mut Vec<Detection>) {
    if data.len() >= 8 && &data[0..4] == WASM_MAGIC {
        detections.push(Detection {
            category: DetectionCategory::WasmBinary,
            severity: Severity::Low,
            description: "WebAssembly binary detected".to_string(),
            offset: Some(0),
        });
        
        if &data[4..8] == WASM_VERSION_1 {
            detections.push(Detection {
                category: DetectionCategory::WasmBinary,
                severity: Severity::Low,
                description: "WASM version 1 (mvp)".to_string(),
                offset: Some(4),
            });
        }
        
        scan_wasm_sections(data, detections);
    }
}

pub fn scan_wasm_threats(data: &[u8], detections: &mut Vec<Detection>) {
    if data.len() < 8 || &data[0..4] != WASM_MAGIC {
        return;
    }
    
    scan_cryptomining_indicators(data, detections);
    scan_suspicious_imports(data, detections);
    scan_obfuscation(data, detections);
    scan_large_sections(data, detections);
}

fn scan_wasm_sections(data: &[u8], detections: &mut Vec<Detection>) {
    let mut offset = 8;
    let mut code_size = 0;
    let mut data_size = 0;
    
    while offset < data.len().saturating_sub(5) {
        let section_id = data[offset];
        offset += 1;
        
        let size = data[offset] as usize;
        offset += 1;
        
        if section_id == 10 { code_size += size; }
        if section_id == 11 { data_size += size; }
        
        offset += size;
        if offset >= data.len() {
            break;
        }
    }
    
    if code_size > 100_000 {
        detections.push(Detection {
            category: DetectionCategory::WasmThreat,
            severity: Severity::Medium,
            description: format!("Large WASM code section ({}KB), possible cryptominer",
                code_size / 1024),
            offset: None,
        });
    }
    
    if data_size > 50_000 {
        detections.push(Detection {
            category: DetectionCategory::WasmThreat,
            severity: Severity::Medium,
            description: format!("Large WASM data section ({}KB), possible payload",
                data_size / 1024),
            offset: None,
        });
    }
}

fn scan_cryptomining_indicators(data: &[u8], detections: &mut Vec<Detection>) {
    let mut miner_indicators = 0;
    
    for pattern in CRYPTOMINER_PATTERNS {
        if let Some(offset) = find_pattern(data, pattern.as_bytes()) {
            miner_indicators += 1;
            detections.push(Detection {
                category: DetectionCategory::WasmThreat,
                severity: Severity::High,
                description: format!("Cryptomining indicator: '{}'", pattern),
                offset: Some(offset),
            });
        }
    }
    
    if find_pattern(data, b"WebGL").is_some() || 
       find_pattern(data, b"WebGPU").is_some() {
        detections.push(Detection {
            category: DetectionCategory::WasmThreat,
            severity: Severity::High,
            description: "GPU API usage, possible GPU-based cryptomining".to_string(),
            offset: None,
        });
    }
    
    if find_pattern(data, b"SharedArrayBuffer").is_some() {
        detections.push(Detection {
            category: DetectionCategory::WasmThreat,
            severity: Severity::Medium,
            description: "SharedArrayBuffer, possible multi-threaded mining".to_string(),
            offset: None,
        });
    }
    
    if miner_indicators >= 3 {
        detections.push(Detection {
            category: DetectionCategory::WasmThreat,
            severity: Severity::Critical,
            description: format!("Multiple cryptomining indicators ({}), likely miner",
                miner_indicators),
            offset: None,
        });
    }
}

fn scan_suspicious_imports(data: &[u8], detections: &mut Vec<Detection>) {
    let mut found_imports = Vec::new();
    
    for import in SUSPICIOUS_IMPORTS {
        if find_pattern(data, import.as_bytes()).is_some() {
            found_imports.push(*import);
            
            let severity = if import.contains("eval") || import.contains("Function") {
                Severity::High
            } else {
                Severity::Medium
            };
            
            detections.push(Detection {
                category: DetectionCategory::WasmThreat,
                severity,
                description: format!("Suspicious import: '{}'", import),
                offset: None,
            });
        }
    }
    
    let has_network = found_imports.iter().any(|i| 
        i.contains("fetch") || i.contains("XMLHttpRequest") || i.contains("WebSocket")
    );
    let has_crypto = found_imports.iter().any(|i| i.contains("crypto"));
    
    if has_network && has_crypto {
        detections.push(Detection {
            category: DetectionCategory::WasmThreat,
            severity: Severity::Critical,
            description: "Network + crypto APIs: possible exfiltration".to_string(),
            offset: None,
        });
    }
}

fn scan_obfuscation(data: &[u8], detections: &mut Vec<Detection>) {
    let mut obfuscation_score = 0;
    
    for indicator in OBFUSCATION_INDICATORS {
        if find_pattern(data, indicator.as_bytes()).is_some() {
            obfuscation_score += 1;
        }
    }
    
    let short_names = count_short_identifiers(data);
    if short_names > 20 {
        obfuscation_score += 2;
        detections.push(Detection {
            category: DetectionCategory::WasmThreat,
            severity: Severity::Medium,
            description: format!("Many short identifiers ({}), likely obfuscated", short_names),
            offset: None,
        });
    }
    
    if obfuscation_score >= 3 {
        detections.push(Detection {
            category: DetectionCategory::WasmThreat,
            severity: Severity::High,
            description: format!("Strong obfuscation indicators (score: {})", obfuscation_score),
            offset: None,
        });
    }
}

fn scan_large_sections(data: &[u8], detections: &mut Vec<Detection>) {
    if data.len() > 1_000_000 {
        detections.push(Detection {
            category: DetectionCategory::WasmThreat,
            severity: Severity::Medium,
            description: format!("Very large WASM binary ({:.2}MB)",
                data.len() as f64 / 1_048_576.0),
            offset: None,
        });
    }
}

fn count_short_identifiers(data: &[u8]) -> usize {
    let patterns: &[&[u8]] = &[b"_0x", b"_0X", b"$_", b"$$", b"__"];
    
    patterns.iter()
        .map(|&pattern| {
            data.windows(pattern.len())
                .filter(|window| window == &pattern)
                .count()
        })
        .sum()
}
