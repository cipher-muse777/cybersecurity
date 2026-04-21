```
"""
verify.py — Standalone Verification Tool

Run this at any time to check the integrity of your logs.

Usage:
    python verify.py            → Verify the chain
    python verify.py --show     → Show all entries first, then verify
"""

import sys
from logger import verify_chain, print_chain

print("\n=== Tamper-Evident Log Verifier ===\n")

# If user passed --show flag, print the chain first
if "--show" in sys.argv:
    print_chain()

# Run the verification
intact = verify_chain()

# Return exit code 0 (success) or 1 (tampered) so it works in scripts/CI too
sys.exit(0 if intact else 1)
```
