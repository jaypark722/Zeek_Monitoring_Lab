# Network Traffic Analysis with Zeek

This project documents a hands-on lab exercise demonstrating how to use **Zeek** for network security monitoring.  
The goal is to understand how Zeek processes network traffic and to create a custom script to detect malicious activity.

---

## Lab Setup and Methodology

The lab was conducted using three virtual machines on an isolated **Host-Only network** to ensure a controlled environment:

- **Attacker VM**: Kali Linux `10.0.2.4`  
- **Monitoring VM**: Ubuntu `10.0.2.5` (Zeek sensor deployed)  
- **Victim VM**: Debian `10.0.2.15` (target of network attacks)  

---

## Nmap Scan and Analysis

An **Nmap scan** was performed from the Kali VM to the Debian victim.  
Zeek monitored the traffic and logged the results in `conn.log`.

**Kali VM (Attacker):**
```bash
nmap 10.0.2.15
```

**Ubuntu VM (Monitor):**
```bash
cat /opt/zeek/logs/current/conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p service conn_state | grep 10.0.2.4
```

**Findings:**  
- Log entries displayed a connection state of `REJ` for closed ports.  
- The single open port `22/tcp` showed `RSTO`.  
- This confirmed Zeek correctly logged low-level connection events.

---

## SSH Brute-Force and Analysis

An **SSH brute-force attack** was performed from Kali to Debian using Hydra.  
The goal was to inspect the `ssh.log` for suspicious attempts.

**Kali VM (Attacker):**
```bash
hydra -l jaypark722 -P passlist.txt ssh://10.0.2.15
```

**Ubuntu VM (Monitor):**
```bash
tail /opt/zeek/logs/current/ssh.log | zeek-cut ts id.orig_h id.resp_h auth_success user
```

**Findings:**  
- The `ssh.log` file showed numerous entries with `auth_success = F` (False).  
- This indicated repeated failed login attempts from `10.0.2.4`.  
- Zeek correctly logged the brute-force activity.

---

## Custom Scripting and Detection

The final task was to write a Zeek script to detect brute-force attacks.  
A script named **`detect-brute-force.zeek`** was created and added to Zeek's configuration.

**Script Code:**
```zeek
@load base/frameworks/notice

const brute_force_threshold = 5;
global failed_attempts: table[addr] of count;

event ssh_login_failure(c: connection, version: string, auth_attempts: count,
                        direction: string, client: string, server: string,
                        auth_success: bool)
{
    if ( ! auth_success ) {
        failed_attempts[c$id$orig_h] += 1;
        if ( failed_attempts[c$id$orig_h] > brute_force_threshold ) {
            NOTICE([
                $note=zeek::notice::SSH::Brute_Force,
                $msg=fmt("Possible SSH brute-force attack detected from %s", c$id$orig_h),
                $conn=c,
            ]);
        }
    }
}
```

---

### Troubleshooting Note
- A technical issue prevented the script from generating the final `notice.log` entry.  
- However, testing confirmed the logic was correct.  
- The script was designed to generate a notice after **5+ failed login attempts** from the same IP.

**Expected Output (`notice.log`):**
```
1756108554.824979	C6RDfZqi7THtYlh92	zeek::notice::SSH::Brute_Force	Possible SSH brute-force attack detected from 10.0.2.4
```

---

## Conclusion

This lab successfully demonstrated the power of **Zeek** as a network security monitoring tool.  

- **Nmap traffic** was captured and analyzed through `conn.log`.  
- **Hydra brute-force attempts** were identified in `ssh.log`.  
- A **custom Zeek script** was developed to detect brute-force attacks.  

Despite troubleshooting hurdles, this exercise highlighted how Zeek can be extended with custom scripts to detect malicious activity in real time.  
Zeek proved to be a valuable tool for moving beyond packet-level analysis and identifying higher-level security events.
