---

# **PC Maintenance & Troubleshooting Toolkit Guide**

The **PC Maintenance & Troubleshooting Toolkit** is a comprehensive PowerShell script designed to optimize system performance, troubleshoot issues, and improve security. It provides tools for disk repairs, updates, monitoring system changes, configuring firewalls, and performing advanced diagnostics, making it invaluable for all users.

---

## **Prerequisites**

- Windows operating system.
- Administrator privileges.
- PowerShell 5.1 or newer.

---

## **Step 1: Running the Toolkit**

1. Open PowerShell with administrator privileges.
2. Navigate to the script's directory and run:
   ```powershell
   .\PCMTT.ps1
   ```
3. Follow the on-screen menu to select an action.

---

## **Menu Options**

1. **System File Checker (SFC)**: Scans and repairs corrupted Windows files.
2. **DISM (Scan & Restore)**: Repairs the Windows component store.
3. **Clean TEMP / Downloads / Recycle Bin**: Clears unnecessary files to free up disk space.
4. **Flush DNS**: Resolves DNS-related issues by clearing the DNS cache.
5. **Reset Network (Winsock, IP stack)**: Resets network settings to fix connectivity problems.
6. **Defrag a Drive**: Optimizes drive performance by defragmenting.
7. **Clear Windows Update Cache**: Fixes Windows update errors by clearing cached files.
8. **Clear All Browser History**: Deletes browsing history to enhance privacy.
9. **Virus Scan (Quick or Full)**: Scans for malware and viruses.
10. **Check System Health**: Displays system health and configuration details.
11. **Create System Restore Point**: Creates a restore point for system recovery.
12. **Advanced Scanning for Leftovers**: Identifies and removes remnants of uninstalled programs.
13. **Network Speed Test**: Measures internet speed, including latency, download, and upload speeds.
14. **Driver Updates**: Scans for outdated drivers and provides update options.
15. **System Performance Analysis**: Monitors real-time CPU, RAM, and Disk usage.
16. **Disk Cleanup**: Frees up disk space by removing unnecessary files.
17. **Hard Drive Health Check**: Analyzes SMART data to assess the health of storage devices.
18. **USB Device Troubleshooting**: Lists and safely ejects connected USB devices.
19. **Windows Search Repair**: Rebuilds the Windows search index to resolve search issues.
20. **File Integrity Checker**: Verifies file integrity using hashes for validation.
21. **System Information Export (with File Modification Dates)**: Generates a detailed system report with file modification details.
22. **Reset System Components**: Repairs Windows components like Search, Defender, and more.
23. **Repair All Microsoft Programs**: Fixes Microsoft applications like Office, Store, and OneDrive.
24. **DNS Benchmark**: Identifies the fastest DNS servers for your network.
25. **System Change Monitoring**: Logs and displays key system changes (e.g., device installations, adapter changes).
26. **Set Firewall Security Level**: Configures the firewall's security level:
   - **Lockdown Mode**: Blocks all incoming/outgoing traffic for maximum security.
   - **Strict Mode**: Allows essential connections while blocking most traffic.
   - **Balanced Mode**: Provides moderate security with usability.
   - **Restore Defaults**: Resets the firewall to default Windows settings.
27. **Paping (Ping + Port) Network Diagnostic Tool**: 
   - Diagnoses network connectivity issues by pinging a host and testing a specific port.
   - Installs Paping if not already available.
   - Prompts for the target hostname and port before launching diagnostics in a command prompt window.
28. **MTR (My Traceroute) Network Diagnostic Tool**: Runs traceroute and network analysis.
29. **Instructions**: Displays this help menu.
30. **Exit**: Closes the toolkit.

---

## **Troubleshooting**

- Ensure PowerShell is running as an administrator.
- Unblock the script file if needed:
   ```powershell
   Unblock-File -Path .\PCMTT.ps1
   ```
- Use the **Restore Defaults** option to reset firewall settings if network issues occur.
- Re-run the script to confirm installation or repairs.

---

## **Credits**

- **Developer**: Sergio Marquina

---

This update reflects all the latest menu options, including **Paping** and **MTR**, and refines the descriptions for clarity. Let me know if further modifications are needed!
