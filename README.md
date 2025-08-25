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