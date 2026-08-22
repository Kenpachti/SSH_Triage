# Third attempt at writing the ssh_triage script, not from memory
failedLogins = {}
successfulLogins = {}
suspiciousLogins = {}

with open("big_auth.log") as file:
    for line in file:
        parts = line.split()
        if "from" in parts:
            if "Failed password" in line:
                ip = parts[-4]
                username = parts[-6]
                failedLogins[ip] = failedLogins.get(ip, []) + [username]
                if "invalid user" in line:
                    suspiciousLogins[ip] = suspiciousLogins.get(ip, []) + [username]
                                
            elif "Accepted password" in line:
                ip = parts[-4]
                username = parts[-6]
                successfulLogins[ip] = successfulLogins.get(ip, []) + [username]


listOfIps = failedLogins | successfulLogins | suspiciousLogins

for ip in listOfIps:
    findings = []

    if ip in failedLogins and ip in successfulLogins and len(failedLogins[ip]) >= 3:
        findings.append("Breach for -> " + ip)

    if ip in failedLogins and ip not in successfulLogins and len(failedLogins[ip]) >= 5:
        findings.append("Brute-force -> " + ip)

    if ip in failedLogins and ip in suspiciousLogins:
        findings.append("Enumeration -> " + ip)

    if ip not in failedLogins and ip not in suspiciousLogins:
        findings.append("Safe -> " + ip)

    if not findings:
         findings.append("Review "+ ip)

    print(findings)
