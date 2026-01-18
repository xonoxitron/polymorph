# Quick Start Guide

## Installation

```bash
git clone https://github.com/xonoxitron/polymorph
cd polymorph
cargo build --release
```

## Basic Usage

```bash
# Scan a binary
polymorph suspicious.exe

# JSON output
polymorph --json malware.com

# Verbose with offsets
polymorph -v --offsets binary.elf
```

## Understanding Output

- **0-40**: Low risk
- **40-60**: Medium risk
- **60-80**: High risk
- **80-100**: Critical threat

## Exit Codes

- `0`: Clean
- `1`: Low
- `2`: Medium
- `3`: High
- `4`: Critical
- `5`: Error
