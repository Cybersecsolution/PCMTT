---

# **PC Maintenance & Troubleshooting Toolkit Guide**

The PC Maintenance & Troubleshooting Toolkit is a simple PowerShell script to optimize system performance, troubleshoot issues, and improve security. It helps with disk repairs, updates, monitoring system changes, and configuring firewalls, making it useful for all users.

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
3. Follow the menu to choose an action.

---

## **Menu Options**

1. **Repair Disk Errors**: Fixes disk issues.
2. **Update Windows**: Installs Windows updates.
3. **Clean TEMP Files**: Clears unnecessary files.
4. **Flush DNS**: Resolves DNS issues.
5. **Reset Network**: Fixes network problems.
6. **Defrag Drive**: Optimizes drive performance.
7. **Clear Update Cache**: Fixes Windows update issues.
8. **Clear Browser History**: Ensures privacy.
9. **Virus Scan**: Scans for malware.
10. **System Health Check**: Analyzes PC health.
11. **Create Restore Point**: Creates a system backup.
12. **Advanced Cleanup**: Finds leftover files.
13. **Speed Test**: Tests internet speed.
14. **Update Drivers**: Keeps drivers up-to-date.
15. **Performance Analysis**: Improves performance.
16. **Disk Cleanup**: Removes unnecessary files.
17. **Hard Drive Health**: Checks disk health.
18. **USB Troubleshooting**: Fixes USB issues.
19. **Search Repair**: Fixes Windows search.
20. **File Integrity Check**: Verifies file health.
21. **Export System Info**: Saves system details.
22. **Reset Components**: Repairs system parts.
23. **Repair Microsoft Programs**: Fixes MS applications.
24. **DNS Benchmark**: Finds the fastest DNS.
25. **Monitor Changes**: Tracks recent changes.
26. **Firewall Security**: Configures firewall settings to control inbound and outbound network traffic, ensuring system security. 
   - **Lockdown Mode**: Blocks all incoming and outgoing traffic, including applications and services. This is ideal for securing the system entirely during critical situations, but network functionality will be completely disabled.
   - **Strict Mode**: Blocks most incoming and outgoing traffic while allowing essential connections, such as secure HTTPS traffic. This mode balances security and basic functionality.
   - **Balanced Mode**: Allows standard traffic for most applications and services, providing moderate security while maintaining usability.
   - **Restore Defaults**: Resets the firewall to Windows' default settings, which are generally secure for regular use and troubleshooting.

   Each mode is designed for specific scenarios, giving users the flexibility to adjust their firewall security according to their needs.
27. **Instructions**: Help using the toolkit.
28. **Exit**: Closes the toolkit.

---

## **Troubleshooting**

- Run PowerShell as an administrator.
- Unblock the script file if needed.
- Use the `Restore Defaults` option for firewall issues.

---

## **Credits**

- **Developer**: Sergio Marquina

---

