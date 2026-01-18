# WebAssembly Malware Detection

## Overview

PolyMorph detects WASM-based threats including cryptominers and obfuscated malware.

## Detection Capabilities

- Binary format validation
- Cryptomining indicators (hash functions, GPU APIs)
- Suspicious imports (network, crypto, DOM)
- Obfuscation patterns
- Size anomalies

## Examples

```bash
# Scan WASM file
polymorph cryptominer.wasm

# Detect Coinhive
polymorph coinhive.wasm
```

## Known Threats

- Coinhive, CryptoLoot, CoinIMP
- XMRig-based miners
- CryptoNight variants
