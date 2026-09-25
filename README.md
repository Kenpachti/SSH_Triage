# ssh_triage.py

A lightweight Python script that triages SSH authentication logs (`sshd`) and flags suspicious activity, so an analyst doesn't have to read every line by hand.

## Why

A single SSH-facing server can generate thousands of authentication log lines a day. No human can read all of them, which means a real attack, such as someone quietly brute-forcing their way in, can sit buried in the noise until it's too late. This script scans the log and surfaces only the source IPs worth a human's attention.

## What it detects

Every source IP in the log gets a verdict. One IP can receive **more than one** finding at the same time (for example, a breach *and* enumeration), because real attackers often do several things at once.

**Breach**: an IP with **3 or more failed logins** that *also* has an accepted login.
The threshold is deliberately low. A run of failures followed by a success means someone may now be *inside*. The successful login is itself the strongest evidence, and missing a real breach is far more costly than checking a false alarm. A clumsy user who mistypes once and then gets in does not trigger this (see Review).

**Brute force**: an IP with **5 or more failed logins** and *no* accepted login.
The threshold is higher because the stakes are lower: nobody got in, and failed attempts are common background noise. The script can afford to wait for more evidence before alerting.

**Enumeration**: any failed attempt against an **invalid (non-existent) user**.
`sshd` logs these as `Failed password for invalid user <name>`. A real employee forgets their password, not their username. Attempts against usernames that don't exist (`oracle`, `postgres`, `jenkins`) are the fingerprint of an automated scan working through a list of common accounts.

**Safe**: an IP with only successful logins and no failures.

**Review**: an IP with some failures that doesn't meet any rule above (for example, one failure followed by a success). Nothing is silently dropped; anything ambiguous is handed to a human.

### Why count per IP, not per username

Counting failures per source IP catches an attacker who spreads guesses across many usernames from one machine. Counting per username would split those attempts up and let each one stay under the threshold.

## Usage

```bash
python3 ssh_triage.py
```

The script reads `big_auth.log` (a sample log included in this repo) from the same folder and prints the findings for each source IP.

### Example output (on the included sample log)

```
['Breach for -> 8.8.8.8']
['Enumeration -> 91.200.12.9']
['Breach for -> 172.16.0.5', 'Enumeration -> 172.16.0.5']
['Brute-force -> 45.33.22.11']
['Review 10.0.0.9']
['Safe -> 10.0.0.5']
```

Note `172.16.0.5`: it got in after 3 failures *and* tried non-existent usernames, so it receives both findings. `10.0.0.9` failed once and then logged in, which looks like a typo, so it goes to Review instead of raising a breach.

## How it works

1. **Parse**: split each line into words. Only lines containing `from` (a source IP) are processed, which skips malformed lines and unrelated events such as session or server messages.
2. **Count**: record failed, accepted, and invalid-user attempts per IP in three dictionaries. The IP and username are read by fixed position from the end of the line.
3. **Evaluate**: combine the three dictionaries' keys so each IP is visited exactly once, then apply every rule independently (separate `if` checks, not `elif`), collecting all findings for that IP into a list.
4. **Fallback**: if no rule matched, the IP is marked Review.

## Known limitations

- **Credential stuffing is invisible by design.** An attacker using a correct, stolen password on the first try produces no failures, so the IP is marked Safe. Catching this needs context the log line doesn't have (location, device, time of day).
- **Thresholds come from behavioural reasoning, not measured data.** They are set by the cost of a miss versus a false alarm, not calibrated against a real server's baseline.
- **Hardcoded log strings.** Detection depends on OpenSSH's exact wording (`Failed password`, `Accepted password`, `invalid user`). A different SSH daemon or locale would slip through.
- **Positional parsing.** The IP and username are read by position from the end of the line, which assumes OpenSSH's standard `... from <ip> port <n> ssh2` ending.
- **No time window.** Events are counted without timestamps, so 50 failures in one second and 50 spread over a week are treated the same.
- **Single hardcoded file.** The log path is fixed in the script rather than passed as an argument.

## Notes

A learning and portfolio project demonstrating log parsing and detection logic in plain Python, with no external libraries. V2 was rebuilt from a blank file to replace the original V1 rules.