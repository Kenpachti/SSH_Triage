# ssh_triage.py

A lightweight Python script that triages SSH authentication logs (`sshd`) and flags suspicious activity, so an analyst doesn't have to read every line by hand.

## Why

A single SSH-facing server can generate thousands of authentication log lines a day. No human can read all of them, which means a real attack — someone quietly brute-forcing their way in — can sit buried in the noise until it's too late. This script scans the log and surfaces only the lines worth a human's attention.

## What it detects

The script classifies source IPs into three separate alerts:

**Breach** — an IP with **2 or more failed logins** that *also* has an accepted login.
The threshold is deliberately low. A failed-then-successful login means someone may now be *inside*, which is high-priority on its own — especially when there's no surrounding context (location, device, time of day) to confirm it was legitimate. A low threshold means the occasional false alarm on a clumsy user, but that costs 30 seconds to check, whereas a missed breach is a live intruder. The alert is tuned sensitive on purpose.

**Brute force in progress** — an IP with **3 or more failed logins** and *no* accepted login.
The threshold is higher because the stakes are lower: these attempts failed, nobody got in, and this pattern is more common noise. We can afford to wait for more evidence before alerting. (Note how the two rules interlock: if an IP had fewer than 3 failures but *did* get in, it's caught by the breach rule instead.)

**Enumeration** — any attempt against an **invalid (non-existent) user**.
`sshd` logs these as `Failed password for invalid user <name>`. This is its own signal because a real employee forgets their password, not their username. Attempts against usernames that don't exist — `oracle`, `postgres`, `jenkins` — are the fingerprint of an automated scan running a list of common accounts, not a confused human.

## Usage

```bash
python3 ssh_triage.py
```

The script reads a log file (`big_auth.log`) in the same folder and prints an alert line for each detection.

### Example output

```
Alert: (8.8.8.8) had a possible breach, please review.
Alert: (91.200.12.9) looks to have multiple entry tries.
Alert: (172.16.0.5) had a possible breach, please review.
Alert: (45.33.22.11) looks to have multiple entry tries.
Alert: (91.200.12.9) had invalid usernames (git,jenkins,oracle,postgres), please review.
Alert: (172.16.0.5) had invalid usernames (ubuntu,test), please review.
```

## How it works

For each log line, the script splits it into words, skips any line too short to be a real login event (a guard against malformed or unrelated log entries), and pulls the source IP and username by their fixed position from the end of the line. It counts failed, accepted, and invalid-user attempts per IP into three dictionaries, then applies the three rules above.

## Known limitations

- **Hardcoded log strings.** Detection is coupled to OpenSSH's exact wording — `Failed password`, `Accepted password`, `invalid user`. A different SSH daemon, OS, or locale that logs `Incorrect password` (or anything else) would slip through undetected. Making the match patterns configurable is the next step toward this being format-agnostic.
- **Single file, hardcoded filename.** The log path is fixed in the script rather than passed as an argument.
- **No timestamps in the logic.** The rules count events but ignore *when* they happened — a burst of 50 failures in one second and 50 spread over a week are treated the same, though they mean very different things.

## Notes

This is a learning / portfolio project built to demonstrate log parsing and detection logic in plain Python, with no external libraries.
