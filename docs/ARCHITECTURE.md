# Architecture

## Overview

PolyMorph uses static analysis to detect polyglot malware patterns.

## Components

- **Scanner**: Orchestrates detection modules
- **Detectors**: APE, Zig, WASM, evasion analysis
- **Report**: Human and JSON output
- **Utils**: Helper functions

## Detection Flow

1. Read binary file
2. Run format-specific detectors
3. Analyze evasion techniques
4. Calculate risk score
5. Generate report

## Risk Scoring

```
Risk = Σ(severity_points) + binary_type_bonus
Severity: Low=5, Medium=15, High=25, Critical=40
Binary bonus: Cosmopolitan=+10, Hybrid=+20
```
