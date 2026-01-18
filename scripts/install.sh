#!/bin/bash
set -e

echo "Installing PolyMorph..."
cargo build --release
sudo cp target/release/polymorph /usr/local/bin/
echo "✓ Installed to /usr/local/bin/polymorph"
