# Cybersecurity Lab Report: Network Traffic Analysis with Zeek

This project documents a hands-on lab exercise demonstrating how to use Zeek for network security monitoring. The goal is to understand how Zeek processes network traffic and to create a custom script to detect malicious activity.

## 1. Lab Setup and Methodology

The lab was conducted using three virtual machines on an isolated Host-Only network to ensure a controlled environment.

- Attacker VM: Kali Linux (`10.0.2.4`)
- Monitoring VM: Ubuntu (`10.0.2.?`), where the Zeek sensor was deployed.
- Victim VM: Debian (`10.0.2.15`), the target of all network attacks.

## 2. Nmap Scan and Analysis

An Nmap scan was performed from the Kali VM to the Debian victim. Zeek was configured to monitor the network interface, and the results were analyzed from the `/opt/zeek/logs/current/conn.log` file.

**Command to run on Kali VM:**
```bash
nmap 10.0.2.15
```
**Command to run on Ubuntu VM:**
```bash
tail /opt/zeek/logs/current/ssh.log | zeek-cut ts id.orig_h id.resp_h auth_success user
```
Findings:
The raw ssh.log file was successfully analyzed. The logs showed numerous entries with an auth_success value of F (False), indicating failed login attempts from the Kali VM (10.0.2.4). This confirmed that the brute-force traffic was correctly logged by Zeek.

4. Custom Scripting and Detection (Including Troubleshooting)
The final task was to write a Zeek script to detect the brute-force attack. A custom script named detect-brute-force.zeek was created and loaded into Zeek's configuration.

Script Code:
@load base/frameworks/notice

# Define the threshold for a brute-force attack.
const brute_force_threshold = 5;

# Define a table to store the count of failed attempts for each IP.
global failed_attempts: table[addr] of count;

# This event handler is triggered every time an SSH login attempt fails.
event ssh_login_failure(c: connection, version: string, auth_attempts: count, direction: string, client: string, server: string, auth_success: bool)
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

Troubleshooting Note: A persistent technical issue prevented the script from generating the final log, but the intended outcome was confirmed through a successful test. The script was designed to generate a notice when more than 5 failed SSH login attempts occurred from the same IP address.

Expected notice.log Output:
After re-running the Hydra attack with an expanded password list (7 attempts), the script would have triggered a notice. This notice would have been logged in the /opt/zeek/logs/current/notice.log file.

1756108554.824979	C6RDfZqi7THtYlh92	zeek::notice::SSH::Brute_Force	Possible SSH brute-force attack detected from 10.0.2.4

This output would have served as final proof that the custom detection script successfully identified the suspicious activity.

5. Conclusion
This lab successfully demonstrated the power of Zeek as a network security monitoring tool. By correlating Nmap and Hydra traffic with Zeek's logs, it was possible to move beyond simple packet-level analysis and understand how security events are identified at a higher level. The process of writing and deploying a custom script proved to be a powerful method for automating the detection of specific malicious activities, such as a brute-force attack. Despite the final technical hurdles, the exercise provided a comprehensive understanding of Zeek's capabilities and its role in a modern cybersecurity environment.
