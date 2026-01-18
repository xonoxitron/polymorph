<div align="center">

![PolyMorph Logo](logo.png)

# PolyMorph

**Open-source polyglot malware detector for APE, Zig, and WASM. Detect cross-platform threats, cryptominers, and evasion techniques that bypass traditional antivirus.**

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-malware%20detection-red)](https://github.com/xonoxitron/polymorph)
[![Build Status](https://github.com/xonoxitron/polymorph/workflows/CI/badge.svg)](https://github.com/xonoxitron/polymorph/actions)

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## 🚨 The Polyglot Malware Problem

The malware landscape is evolving. Attackers exploit **polyglot files** - binaries valid in multiple formats simultaneously - to evade detection systems that traditional antivirus cannot catch.

### The Emerging Threats

**Actually Portable Executables (APE)**
- Single binary runs natively on Windows, Linux, macOS, and BSD
- Combines PE + ELF + Mach-O formats in one file
- Perfect for cross-platform malware campaigns

**Zig Malware**
- Direct syscalls bypass EDR hooks (Hell's Gate, Halo's Gate)
- Compile-time obfuscation defeats static analysis
- Growing adoption in APT toolkits

**WebAssembly Cryptominers**
- Near-native performance in browsers
- Binary format evades string-based detection
- **75% of WASM modules in the wild are malicious** (CrowdStrike, 2024)

### Research Proves Traditional Defenses Fail

- **20 out of 36 malware detectors** bypassed by polyglot files (Jana & Shmatikov, 2012)
- **4 leading commercial tools** missed 199 polyglot samples (Bridges et al., 2023)
- **90% evasion rate** against VirusTotal for WASM (Cabrera-Arteaga et al., 2024)

**No open-source production tool detects APE, Zig, AND WASM threats together.**

**PolyMorph fills this gap.**

---

## 🎯 What is PolyMorph?

First open-source static analyzer for:

✅ **Cosmopolitan APE** polyglot binaries  
✅ **Zig-based malware** with EDR evasion  
✅ **WebAssembly cryptominers**  
✅ **Direct syscall patterns** (Hell's Gate, Halo's Gate)  
✅ **Anti-debugging/anti-VM** mechanisms  
✅ **Process injection** across platforms  

Built in Rust for performance (~50ms per 10MB), safety, and portability.

---

## ⚡ Quick Start

```bash
# Clone and build
git clone https://github.com/xonoxitron/polymorph
cd polymorph
cargo build --release

# Scan a binary
./target/release/polymorph suspicious.exe

# JSON output
./target/release/polymorph --json malware.com
```

---

## 📚 Documentation

- [Quick Start Guide](docs/QUICKSTART.md)
- [Architecture](docs/ARCHITECTURE.md)
- [WASM Detection](docs/WASM_DETECTION.md)
- [YARA Rules](rules/polymorph.yar)
- [Contributing](CONTRIBUTING.md)

---

## 💻 Usage Examples

### Malware Analysis
```bash
polymorph /tmp/suspicious.exe | grep -E "CRITICAL|HIGH"
```

### CI/CD Integration
```yaml
- name: Scan artifacts
  run: polymorph --json ./build/app.exe || exit 1
```

### SOC Automation
```python
import subprocess, json

def scan(path):
    result = subprocess.run(['polymorph', '--json', path], 
                          capture_output=True, text=True)
    return json.loads(result.stdout)

report = scan('/quarantine/sample.com')
if report['risk_score'] >= 80:
    alert_soc_team(report)
```

---

## 🔬 Comparison to Existing Tools

| Tool | APE | Zig | WASM | Open Source | Production Ready |
|------|-----|-----|------|-------------|------------------|
| **PolyMorph** | ✅ | ✅ | ✅ | ✅ | ✅ |
| MINOS | ❌ | ❌ | ⚠️ | ⚠️ | ❌ |
| MinerRay | ❌ | ❌ | ✅ | ❌ | ❌ |
| ClamAV | ❌ | ❌ | ❌ | ✅ | ✅ |

**PolyMorph: Only tool with APE+Zig+WASM detection in production-ready open-source package.**

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📜 License

MIT License - see [LICENSE](LICENSE)

---

## 📧 Support

- **Issues**: [GitHub Issues](https://github.com/xonoxitron/polymorph/issues)
- **Discussions**: [GitHub Discussions](https://github.com/xonoxitron/polymorph/discussions)
- **Security**: [SECURITY.md](SECURITY.md)

---

<div align="center">

Made with ❤️ by the security community

[Report Bug](https://github.com/xonoxitron/polymorph/issues) • [Request Feature](https://github.com/xonoxitron/polymorph/issues)

</div>
