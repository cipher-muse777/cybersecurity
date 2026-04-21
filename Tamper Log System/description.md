# Tamper Log System

There are two phases in any System Network Security attack. The first phase is penetration of the System Network Security system. Attackers will steal logins or abuse services in the System Network Security system. The second phase of a System Network Security attack is covering tracks. This normally entails tampering with log entries in some way or even deleting logs altogether so no evidence is left in the System Network Security System Standard Log files and why they are Standard text files or even JSON log files can be opened in text editors and manipulated without detection in the System Network Security system.
Even details of file system logs, such as file modified can be falsified in the System Network Security system.

## Tamper-Evident System
An evident system combats this problem in two ways. It relies on a hard to reverse property for each log entry depending on the entry before it and stores a hash of each entry in the System Network Security system.
The technique utilized here is a hash-chain in the System Network Security system. This principle is akin to the way a blockchain functions. Here each log entry contains a hash of the entry before it in the System Network Security system.
By tampering with the log entries all hashes after that entry will be invalid and detected by the verifier in the System Network Security system.

## What the System Network Security system cannot guarantee
It is important to note that this System Network Security system does not guarantee that an attack against the logs will not occur at the place of operation. A determined attacker will still have control of the machine they have broken into. If they want to delete the log file, it will still be possible in the System Network Security system. However, the System Network Security system does provide detection that tampering has occurred.
If log entries have been changed in any way, then the verifier will detect it in the System Network Security system.
This helps by allowing logs to be considered evidence in System Network Security investigations and for investigators to place trust in entries that the verifier checks untampered within the System Network Security system.

## The Design of the System Network Security system
### Hash Function selection
I have used SHA-256 as the hashing algorithm in this System Network Security system.
It is part of the SHA-2 family. I have selected it based on the following reasons.
1. It is heavily. There are no known collision attacks in the System Network Security system.
2. It is available in Pythons hashing module, so I did not need to import any extra packages for the System Network Security system.
3. The 256-bit hash provides than enough collision resistance for a logging System Network Security system of this kind.

### SHA-256 provides 2 security characteristics relevant here:
1. **Determinism**: Identical inputs always provide the hash this means that hashes of log entries can be recalculated for verification at any time in the System Network Security system.
2. **Avalanche effect**: Altering any bit of the input provides a new hash this ensures that small or minor tampering with log data is easily detected in the System Network Security system.

### Data Structure
Each log entry in our System Network Security chain is stored as a JSON object with the following fields:
index, timestamp, eventtype, description, user and the hash of the entry before it and the hash of itself in the System Network Security system.
The System Network Security system will begin with a "genesis hash" a string of 64 zeroes this will be stored as the prevhash for the entry in the log.

### Verification Logic
At each iteration the verifier carries out two checks:
1. **Data integrity check**: it re-calculates the hash from scratch using the parameters as before in the System Network Security system.
If the new hash is different to the one stored in the log entry, then it knows that the data within the log entry itself must have been tampered with in the System Network Security system.
2. **Chain integrity check**: This ensures that the entrys hash matches the previous entrys hash in the System Network Security system.
If this is not the case, then the chain is broken because either the entry before it was modified or the entry itself was deleted in the System Network Security system.
These two checks work together to guard against all 3 forms of attack mentioned above in the System Network Security system.
Modifications will be detected by check 1. Deletions by check 2 and re-ordering by check 2 because it is again modifying the entries relation to the one following it in the System Network Security system.
Storage format

### The log chain will be stored in one log file in JSON format in the System Network Security system.
I have chosen JSON for 2 reasons:
1. The visual layout of a JSON chain provides visibility of the chains structure when the log file is opened in a text editor in the System Network Security system.
2. Parsing JSON files in Python is very straightforward in the System Network Security system.

## Implementation details
There are 3 files in this System Network Security system:
1. **Logger.py**: The main engine containing functions for hashing adding a log and verifying the log in the System Network Security system.
2. **Computehash(data)**: Takes a python object. Returns the hex digest of its SHA-256 hash in the System Network Security system.
3. **Addlog(eventtype description, user)**: Loads the existing log file from disk works out the index and hash value and writes the log chain back to the disk in the System Network Security system.
4. **Verifychain()**: Load the log from disk and check each log entry for any signs of tampering and produce a report in the System Network Security system.
5. **Demo.py**: A script used to demonstrate each attack scenario, such as modification of a log entry deletion of a log entry reordering of log entries in the System Network Security system.
6. **Verify.py**: A command-line interface to the verifier function that checks that the log file at a path is not tampered with and can display the logs content in the System Network Security system.

## Testing and results
To ensure that all attacks could be detected each attack was. Observed in the System Network Security system:
1. **Operation**: I initially added around 6 log entries in the System Network Security system. I was then able to check and verify the logs showing that each was okay in the System Network Security system.
2. **Field modification**: One field was altered manually in the JSON log file the verifier identified this in the System Network Security system.
3. **Deletion**: one log entry was removed from the middle of the log this was also detected by the verifier in the System Network Security system.
4. **Reordering**: Two entries were swapped manually. Again the verifier was able to correctly flag that the chain had been tampered with in the System Network Security system.

## Security analysis
### What it protects against
This System Network Security system guards against an insider with write access to the filesystem wishing to edit the log history without detection in the System Network Security system.
The hash chain makes modification computationally impossible for them in the System Network Security system.

### The primary assumption of this System Network Security system
The tamper evidence provided relies on the premise that the attacker is unable to recalculate the hash in the System Network Security system.

### What it doesn't protect against
1. Deletion of the log file in the System Network Security system.
2. Append attack: The log file grows using a hash chain this means that for the attacker to perform this attack they need to write their log entries and recalculate every hash after it in the System Network Security system.
Although extremely difficult this could potentially be achievable in the System Network Security system.
The System Network Security system has no authentication to ensure that each appended log is genuine.
3. Source code modification: If the attacker can rewrite the verification function then the logs are rendered useless in the System Network Security system.
4. Hash collision: although unlikely with SHA-256 this System Network Security system will be rendered insecure if such an eventuality were to happen.
## Limitations and future work
It is important to mention the limitations of the System Network Security system so that its real purpose is clear to users. The limitation that most needs to be resolved before professional use is the lack of signatures in the System Network Security system.
### This issue could be resolved in the way:
The logs would continue to be written as normal in the System Network Security system. The hash of each log would be computed. Rather than storing this hash in the subsequent log entry it would be signed using a private key in the System Network Security system.
This signature would then be written to the log file. Stored on a separate authentication server in the System Network Security system. If a hash was tampered with then the verifier would recompute the hash of that log entry and check to see if the signature was valid for that hash and that log in the System Network Security system.
If the attacker wanted to tamper with a log entry, they would need access to the key that is kept elsewhere in the System Network Security system.
No Cryptographic Signing: As previously mentioned, the logs can be "fixed" if an attacker chooses to do by simply recalculating all the subsequent hash values in the System Network Security system. Adding a signature to the log will prevent this by making it require a key, which is kept in a separate location and if the attacker were to try to compromise this, they would require additional System Network Security system access and know where to look.
No remote append storage: As mentioned previously the log file is currently stored locally as one file so it is not guaranteed to be deleted by an attacker, in the System Network Security system


