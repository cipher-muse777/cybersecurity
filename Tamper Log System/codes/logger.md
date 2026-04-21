```
"""
logger.py — Tamper-Evident Log System (Core Engine)

This file handles:
  - Creating new log entries
  - Linking each entry to the previous one using SHA-256 hashing
  - Saving the chain to a JSON file
  - Verifying the chain for any tampering

How the chain works:
  Entry 1: hash("entry1 data" + "0000...genesis")
  Entry 2: hash("entry2 data" + entry1_hash)
  Entry 3: hash("entry3 data" + entry2_hash)
  ...and so on. Changing ANY entry breaks every hash after it.
"""

import hashlib       # Python's built-in cryptography library
import json          # For saving/loading log data as JSON
import os            # For checking if the log file exists
from datetime import datetime  # For timestamps

# CONFIGURATION

# Where the log chain will be stored on disk
LOG_FILE = "logs/logchain.json"

# The very first entry has no "previous hash" — we use this as a placeholder
GENESIS_HASH = "0" * 64   # 64 zeros, like Bitcoin's genesis block idea

# CORE FUNCTION 1: Compute a hash

def compute_hash(data: dict) -> str:
    """
    Takes a dictionary (log entry data) and returns its SHA-256 fingerprint.

    SHA-256 is a one-way function: given the same input, you always get
    the same 64-character hex string. Change even one character of input
    and the output completely changes. This is what makes tampering detectable.

    Example:
        compute_hash({"event": "login"}) → "a3f7c9..."
    """
    # Convert the dictionary to a JSON string, sorted so order doesn't matter
    raw_string = json.dumps(data, sort_keys=True)

    # Encode to bytes, then run SHA-256 on it
    hash_bytes = hashlib.sha256(raw_string.encode('utf-8'))

    # Return the hex digest (64 lowercase hex characters)
    return hash_bytes.hexdigest()

# CORE FUNCTION 2: Load the existing chain

def load_chain() -> list:
    """
    Loads all existing log entries from the JSON file.
    If the file doesn't exist yet, returns an empty list.
    """
    if not os.path.exists(LOG_FILE):
        return []

    with open(LOG_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            # File exists but is corrupted/empty — start fresh
            print("[WARNING] Log file is corrupted or empty. Starting fresh.")
            return []


# CORE FUNCTION 3: Save chain to disk

def save_chain(chain: list):
    """
    Saves the entire log chain back to the JSON file.
    Creates the 'logs/' folder if it doesn't exist.
    """
    # Make sure the logs directory exists
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    with open(LOG_FILE, "w") as f:
        json.dump(chain, f, indent=2)


# CORE FUNCTION 4: Add a new log entry

def add_log(event_type: str, description: str, user: str = "system"):
    """
    Adds a new log entry to the chain.

    Each entry stores:
      - index        : Position in the chain (0, 1, 2, ...)
      - timestamp    : When the event happened
      - event_type   : Category of event (e.g., "LOGIN", "FILE_ACCESS")
      - description  : Human-readable description
      - user         : Who triggered the event
      - prev_hash    : The hash of the PREVIOUS entry (the link)
      - current_hash : This entry's own hash (computed from all the above)

    Args:
        event_type  : Short category label, e.g. "LOGIN_ATTEMPT"
        description : Full description of what happened
        user        : Username or source of the event
    """
    # Load whatever chain already exists
    chain = load_chain()

    # Figure out what the previous hash is
    if len(chain) == 0:
        # This is the very first entry — use the genesis placeholder
        prev_hash = GENESIS_HASH
        index = 0
    else:
        # Get the hash stored in the last entry
        prev_hash = chain[-1]["current_hash"]
        index = len(chain)

    # Build the entry (without the current_hash yet — we'll compute that below)
    entry_data = {
        "index"       : index,
        "timestamp"   : datetime.utcnow().isoformat() + "Z",  # UTC time, ISO format
        "event_type"  : event_type.upper(),
        "description" : description,
        "user"        : user,
        "prev_hash"   : prev_hash,
    }

    # Now compute this entry's own hash based on all its data + previous hash
    # This is the "seal" that makes it tamper-evident
    entry_data["current_hash"] = compute_hash(entry_data)

    # Append to the chain and save
    chain.append(entry_data)
    save_chain(chain)

    # Give the user confirmation
    print(f"[LOG ADDED] #{index} | {event_type.upper()} | {entry_data['timestamp']}")
    print(f"            Hash: {entry_data['current_hash'][:16]}...")

    return entry_data


# CORE FUNCTION 5: Verify chain integrity

def verify_chain() -> bool:
    """
    Walks through every entry in the chain and checks two things:
      1. Is this entry's stored hash still correct?
         (Re-computes the hash and compares — catches modifications)
      2. Does this entry's prev_hash match the actual previous entry's hash?
         (Catches deletions and re-ordering)

    Returns True if chain is intact, False if tampering is detected.
    Prints a detailed report showing exactly where any problem is.
    """
    chain = load_chain()

    if len(chain) == 0:
        print("[INFO] Log chain is empty. Nothing to verify.")
        return True

    print(f"\n{'='*55}")
    print(f"  INTEGRITY VERIFICATION REPORT")
    print(f"  Checking {len(chain)} entries...")
    print(f"{'='*55}")

    all_good = True

    for i, entry in enumerate(chain):
        # ── Step A: Re-compute hash (exclude the stored current_hash field) ──
        # We need to hash everything EXCEPT the 'current_hash' itself,
        # because that field wasn't there when the original hash was computed.
        entry_without_hash = {k: v for k, v in entry.items() if k != "current_hash"}
        recomputed_hash = compute_hash(entry_without_hash)

        stored_hash = entry.get("current_hash", "")
        hash_ok = (recomputed_hash == stored_hash)

        # ── Step B: Check that prev_hash matches the actual previous entry ──
        if i == 0:
            # First entry should point to GENESIS_HASH
            chain_link_ok = (entry.get("prev_hash") == GENESIS_HASH)
        else:
            expected_prev = chain[i - 1]["current_hash"]
            chain_link_ok = (entry.get("prev_hash") == expected_prev)

        # ── Report ──
        status = "✓ OK" if (hash_ok and chain_link_ok) else "✗ TAMPERED"
        print(f"\n  Entry #{i} [{status}]")
        print(f"    Time     : {entry.get('timestamp', 'N/A')}")
        print(f"    Event    : {entry.get('event_type', 'N/A')}")
        print(f"    User     : {entry.get('user', 'N/A')}")

        if not hash_ok:
            print(f"    [!] DATA MODIFIED  — stored hash doesn't match re-computed hash")
            print(f"        Stored   : {stored_hash[:32]}...")
            print(f"        Expected : {recomputed_hash[:32]}...")
            all_good = False

        if not chain_link_ok:
            print(f"    [!] CHAIN BROKEN   — prev_hash link is wrong (entry deleted or reordered?)")
            all_good = False

    print(f"\n{'='*55}")
    if all_good:
        print("  RESULT: Chain is INTACT. No tampering detected.")
    else:
        print("  RESULT: TAMPERING DETECTED. See details above.")
    print(f"{'='*55}\n")

    return all_good


# CORE FUNCTION 6: Print the full chain

def print_chain():
    """
    Displays all log entries in a readable format.
    Useful for showing the log to a human or in a demo.
    """
    chain = load_chain()

    if len(chain) == 0:
        print("[INFO] No log entries yet.")
        return

    print(f"\n{'='*55}")
    print(f"  FULL LOG CHAIN ({len(chain)} entries)")
    print(f"{'='*55}")

    for entry in chain:
        print(f"\n  #{entry['index']} | {entry['event_type']} | {entry['timestamp']}")
        print(f"  User       : {entry['user']}")
        print(f"  Description: {entry['description']}")
        print(f"  Prev Hash  : {entry['prev_hash'][:24]}...")
        print(f"  Own Hash   : {entry['current_hash'][:24]}...")

    print(f"\n{'='*55}\n")
```
