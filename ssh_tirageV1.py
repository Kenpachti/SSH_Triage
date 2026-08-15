# ssh_triage.py — SSH auth log triage
# Scans an sshd log and flags three things:
#   Breach: 2+ failed logins from an IP that also has an accepted login
#   Brute force in progress: 3+ failed logins, never accepted
#   Enumeration: any attempt against an invalid (non-existent) user
# Usage: python3 ssh_triage.py   (reads big_auth.log in the same folder)

FailedLoginsList = {}
AcceptedLoginsList = {}
SuspiciousLoginsList = {}


with open("big_auth.log") as file:
    for line in file:
        parts = line.split()
        if len(parts) < 12:
            continue

        if "Failed password" in line:
            ip = parts[-4]
            username = parts[-6]
            FailedLoginsList[ip] = FailedLoginsList.get(ip, []) + [username]

        elif "Accepted password" in line:
            ip = parts[-4]
            username = parts[-6]
            AcceptedLoginsList[ip] = AcceptedLoginsList.get(ip, []) + [username]

        if "invalid user" in line:
            ip = parts[-4]
            username = parts[-6]
            SuspiciousLoginsList[ip] = SuspiciousLoginsList.get(ip, []) + [username]


for k,v in FailedLoginsList.items():
    if k in AcceptedLoginsList and len(FailedLoginsList[k]) >= 2:
        print("Alert: (" + k + ") had a possible breach, please review.")
    elif k not in AcceptedLoginsList and len(FailedLoginsList[k]) >=3:
        print("Alert: (" + k + ") looks to have multiple entry tries.")

for k,v in SuspiciousLoginsList.items():
        names = (",").join(v)
        print("Alert: (" + k + ") had invalid usernames (" + names + "), please review.")
