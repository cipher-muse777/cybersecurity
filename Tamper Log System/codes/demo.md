```
"""
demo.py — Demonstration Script
Run this file to see the full system in action.

It will:
  1. Add several realistic log entries
  2. Verify the chain is intact
  3. Simulate TAMPERING (directly editing an entry)
  4. Verify again — showing the tamper is detected
  5. Simulate DELETION of an entry
  6. Verify again — showing the deletion is detected

To run:
    python demo.py

Expected output: A clear demonstration of the system catching tampering.
"""

import json
import os
import time

# Import our logger module
from logger import add_log, verify_chain, print_chain, load_chain, save_chain, LOG_FILE


def clear_logs():
    """Removes the log file so we start fresh for each demo run."""
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
        print("[SETUP] Old log file removed. Starting fresh.\n")


def section(title):
    """Prints a clear section header for demo readability."""
    print(f"\n{'#'*55}")
    print(f"  {title}")
    print(f"{'#'*55}\n")


# DEMO SECTION 1 — Add realistic log entries

section("SECTION 1: Adding Log Entries")

# Remove old log file so we're starting fresh
clear_logs()

# Simulate events you'd see in a real system
add_log("LOGIN_ATTEMPT",  "User logged in successfully",               user="alice")
time.sleep(0.01)   # tiny delay so timestamps are slightly different
add_log("FILE_ACCESS",    "Read /etc/config.txt",                      user="alice")
time.sleep(0.01)
add_log("PERMISSION_CHANGE", "Alice granted admin rights",             user="root")
time.sleep(0.01)
add_log("FILE_DELETE",    "Deleted file /var/log/old_backup.log",      user="alice")
time.sleep(0.01)
add_log("LOGIN_ATTEMPT",  "User bob failed password 3 times — locked", user="bob")
time.sleep(0.01)
add_log("LOGOUT",         "Alice logged out normally",                  user="alice")

# Show what the chain looks like
print_chain()

# DEMO SECTION 2 — Verify intact chain

section("SECTION 2: Verifying Intact Chain")
result = verify_chain()
assert result == True, "Chain should be intact here!"

# DEMO SECTION 3 — Simulate TAMPERING (entry edit)

section("SECTION 3: Simulating Tampering (Editing Entry #2)")

# Load the raw chain directly and manually change a value
# This is what an attacker might do — go into the file and edit it
chain = load_chain()

print(f"[BEFORE] Entry #2 description: '{chain[2]['description']}'")
chain[2]['description'] = "Alice had her admin rights REMOVED"   # ← attacker edits this
print(f"[AFTER]  Entry #2 description: '{chain[2]['description']}'")
print("[ACTION] Saved tampered chain to disk...\n")

# Save it back WITHOUT recomputing hashes (attacker can't easily do this)
save_chain(chain)

# Now verify — system should catch the change
section("SECTION 3b: Verifying After Tampering")
result = verify_chain()
assert result == False, "System should detect tampering!"

# DEMO SECTION 4 — Simulate DELETION of an entry

section("SECTION 4: Simulating Deletion (Removing Entry #3)")

# Reload the original (we'll rebuild from scratch)
clear_logs()
add_log("LOGIN_ATTEMPT",  "User logged in successfully",  user="alice")
add_log("FILE_ACCESS",    "Read /etc/config.txt",         user="alice")
add_log("PERMISSION_CHANGE", "Alice granted admin rights", user="root")
add_log("FILE_DELETE",    "Deleted /var/log/old.log",     user="alice")
add_log("LOGOUT",         "Alice logged out",             user="alice")

# Now simulate deleting entry #2 from the middle
chain = load_chain()
print(f"[BEFORE] Chain has {len(chain)} entries.")
deleted = chain.pop(2)   # Remove entry at index 2
print(f"[ACTION] Deleted entry: '{deleted['description']}'")
print(f"[AFTER]  Chain now has {len(chain)} entries.\n")

save_chain(chain)

section("SECTION 4b: Verifying After Deletion")
result = verify_chain()
assert result == False, "System should detect deletion!"

# DEMO SECTION 5 — Simulate RE-ORDERING

section("SECTION 5: Simulating Re-ordering (Swapping Entries #1 and #2)")

# Rebuild fresh chain
clear_logs()
add_log("LOGIN_ATTEMPT",  "User logged in",        user="alice")
add_log("FILE_ACCESS",    "Read config file",      user="alice")
add_log("PERMISSION_CHANGE", "Admin rights given", user="root")
add_log("LOGOUT",         "Alice logged out",      user="alice")

chain = load_chain()
print(f"[BEFORE] Entry #1: '{chain[1]['description']}'")
print(f"[BEFORE] Entry #2: '{chain[2]['description']}'")

# Swap entries 1 and 2
chain[1], chain[2] = chain[2], chain[1]
print(f"[AFTER]  Entry #1: '{chain[1]['description']}' (was #2)")
print(f"[AFTER]  Entry #2: '{chain[2]['description']}' (was #1)\n")

save_chain(chain)

section("SECTION 5b: Verifying After Re-ordering")
result = verify_chain()
assert result == False, "System should detect re-ordering!"

print("\n✓ ALL DEMO TESTS PASSED — System is working correctly!\n")
```
