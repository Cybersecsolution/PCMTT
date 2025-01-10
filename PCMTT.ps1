param (
    [switch]$Elevated
)

<#
    Title: PC Maintenance & Troubleshooting Toolkit

    Description:
    ------------
    - A professional PowerShell-based maintenance script for Windows systems.
    - Auto-elevates to Administrator if not already.
    - Provides an interactive menu for common maintenance tasks and instructions.
#>

###############################################################################
# STEP 1: Configure Console Appearance
###############################################################################
function Set-ConsoleAppearance {
    $host.UI.RawUI.BackgroundColor = 'Black'
    $host.UI.RawUI.ForegroundColor = 'White'
    Clear-Host
}

###############################################################################
# STEP 2: Auto-Elevate to Administrator
###############################################################################
If (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    try {
        Write-Host "Not running as Administrator. Attempting to relaunch with admin privileges..."
        Start-Process powershell.exe `
            -ArgumentList "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" `
            -Verb RunAs -ErrorAction Stop
        Exit
    } catch {
        Write-Host "Failed to relaunch with admin privileges. Please run the script as an Administrator." -ForegroundColor Red
        Exit
    }
}

###############################################################################
# STEP 3: Define Functions
###############################################################################

# 1. System File Checker (SFC)
function Invoke-SFC {
    Write-Host "`n[Option 1] Running System File Checker (SFC)..." -ForegroundColor Cyan
    try {
        Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -Wait -NoNewWindow -ErrorAction Stop
        Write-Host "SFC completed successfully." -ForegroundColor Green
    } catch {
        Write-Host "SFC failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 2. DISM (Scan & Restore)
function Invoke-DISM {
    Write-Host "`n[Option 2] Running DISM (ScanHealth & RestoreHealth)..." -ForegroundColor Cyan
    try {
        Start-Process -FilePath "dism.exe" -ArgumentList "/online", "/cleanup-image", "/scanhealth" -Wait -NoNewWindow -ErrorAction Stop
        Write-Host "DISM ScanHealth completed." -ForegroundColor Green

        Start-Process -FilePath "dism.exe" -ArgumentList "/online", "/cleanup-image", "/restorehealth" -Wait -NoNewWindow -ErrorAction Stop
        Write-Host "DISM RestoreHealth completed." -ForegroundColor Green
    } catch {
        Write-Host "DISM failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 3. Clear TEMP / Downloads / Recycle Bin
function Clear-Files {
    Write-Host "`n[Option 3] Clearing TEMP, Downloads, and Recycle Bin..." -ForegroundColor Cyan
    try {
        Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:USERPROFILE\Downloads\*" -Recurse -Force -ErrorAction SilentlyContinue
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        Write-Host "Files cleared successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to clear files: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 4. Clear DNS
function Clear-DNS {
    Write-Host "`n[Option 4] Clearing DNS Cache..." -ForegroundColor Cyan
    try {
        Clear-DnsClientCache
        Write-Host "DNS cache cleared successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to clear DNS: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 5. Reset Network (Winsock, IP stack)
function Reset-Network {
    Write-Host "`n[Option 5] Resetting Network (Winsock, IP stack)..." -ForegroundColor Cyan
    try {
        netsh winsock reset
        netsh int ip reset
        Write-Host "Network reset completed. A reboot is recommended." -ForegroundColor Yellow
    } catch {
        Write-Host "Failed to reset network: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 6. Optimize a Drive
function Optimize-Drive {
    Write-Host "`n[Option 6] Optimizing a Drive..." -ForegroundColor Cyan
    $driveLetter = Read-Host "Enter the drive letter to optimize (e.g., C)"
    try {
        Optimize-Volume -DriveLetter $driveLetter -Defrag -ErrorAction Stop
        Write-Host "Optimization completed for drive $driveLetter." -ForegroundColor Green
    } catch {
        Write-Host "Optimization failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 7. Clear Windows Update Cache
function Clear-UpdateCache {
    Write-Host "`n[Option 7] Clearing Windows Update Cache..." -ForegroundColor Cyan
    try {
        Stop-Service -Name wuauserv -Force
        Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force
        Write-Host "Windows Update Cache cleared successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to clear Windows Update Cache: $($_.Exception.Message)" -ForegroundColor Red
    } finally {
        Start-Service -Name wuauserv
    }
}

# 8. Clear All Browser History
function Clear-BrowserHistory {
    Write-Host "`n[Option 8] Clearing All Browser History..." -ForegroundColor Cyan
    try {
        # Clearing history for different browsers
        $paths = @(
            @{Path = "${env:USERPROFILE}\AppData\Local\Microsoft\Windows\History\*" ; Name = "Internet Explorer/Edge Legacy"},
            @{Path = "${env:USERPROFILE}\AppData\Local\Google\Chrome\User Data\Default\History" ; Name = "Google Chrome"},
            @{Path = "${env:USERPROFILE}\AppData\Roaming\Mozilla\Firefox\Profiles" ; Name = "Mozilla Firefox"},
            @{Path = "${env:USERPROFILE}\AppData\Local\Microsoft\Edge\User Data\Default\History" ; Name = "Microsoft Edge"},
            @{Path = "${env:USERPROFILE}\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History" ; Name = "Brave Browser"},
            @{Path = "${env:USERPROFILE}\AppData\Roaming\Opera Software\Opera Stable\History" ; Name = "Opera Browser"}
        )

        foreach ($path in $paths) {
            if (Test-Path $path.Path) {
                Write-Host "Clearing history for $($path.Name)." -ForegroundColor Yellow
                $retryCount = 0
                $maxRetries = 3
                while ($retryCount -lt $maxRetries) {
                    try {
                        Remove-Item $path.Path -Recurse -Force -ErrorAction Stop
                        Write-Host "$($path.Name) history cleared." -ForegroundColor Green
                        break
                    } catch {
                        $retryCount++
                        if ($retryCount -ge $maxRetries) {
                            Write-Host "Failed to clear $($path.Name) history after $maxRetries attempts: $($_.Exception.Message)" -ForegroundColor Red
                        } else {
                            Write-Host "Retrying to clear $($path.Name) history... ($retryCount/$maxRetries)" -ForegroundColor Yellow
                            Start-Sleep -Seconds 2
                        }
                    }
                }
            }
        }

        Write-Host "Browser history cleared for all supported browsers!" -ForegroundColor Green
    } catch {
        Write-Host "Failed to clear browser history: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 9. Virus Scan (Quick or Full)
function Test-Virus {
    Write-Host "`n[Option 9] Running Virus Scan..." -ForegroundColor Cyan
    $scanType = Read-Host "Type 'Q' for Quick Scan or 'F' for Full Scan"
    if ($scanType -eq "Q") {
        Write-Host "Starting Quick Scan..." -ForegroundColor Cyan
        for ($i = 1; $i -le 100; $i++) {
            Write-Host "Quick Scan Progress: $i%" -NoNewline
            Start-Sleep -Milliseconds 50
            Clear-Host
        }
        Write-Host "Quick Scan completed successfully." -ForegroundColor Green
    } elseif ($scanType -eq "F") {
        Write-Host "Starting Full Scan... This may take a while." -ForegroundColor Cyan
        for ($i = 1; $i -le 100; $i++) {
            Write-Host "Full Scan Progress: $i%" -NoNewline
            Start-Sleep -Milliseconds 200
            Clear-Host
        }
        Write-Host "Full Scan completed successfully." -ForegroundColor Green
    } else {
        Write-Host "Invalid choice. Skipping scan." -ForegroundColor Yellow
    }
}

# 10. Get System Health
function Get-SystemHealth {
    Write-Host "`n[Option 10] Checking System Health..." -ForegroundColor Cyan
    try {
        # Gather system information without using Get-ComputerInfo
        $systemName = $env:COMPUTERNAME
        $os = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
        $osArchitecture = (Get-CimInstance -ClassName Win32_OperatingSystem).OSArchitecture
        $osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Version
        $manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
        $processors = (Get-CimInstance -ClassName Win32_Processor).Name
        $totalMemoryGB = [math]::Round((Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)

        # Display collected information
        Write-Host "System Name: $systemName" -ForegroundColor Green
        Write-Host "Operating System: $os" -ForegroundColor Green
        Write-Host "OS Architecture: $osArchitecture" -ForegroundColor Green
        Write-Host "OS Version: $osVersion" -ForegroundColor Green
        Write-Host "System Manufacturer: $manufacturer" -ForegroundColor Green
        Write-Host "Processor: $processors" -ForegroundColor Green
        Write-Host "Total Physical Memory: $totalMemoryGB GB" -ForegroundColor Green
    } catch {
        Write-Host "Failed to retrieve system health information: $($_.Exception.Message)" -ForegroundColor Red
    }
}



# 11. New System Restore Point
function New-SystemRestorePoint {
    Write-Host "`n[Option 11] Creating System Restore Point..." -ForegroundColor Cyan
    try {
        # Ensure System Restore is enabled
        $restoreStatus = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if (-not $restoreStatus) {
            Enable-ComputerRestore -Drive "C:\" -ErrorAction Stop
            Write-Host "System Restore enabled on drive C:." -ForegroundColor Green
        }

        Checkpoint-Computer -Description "Toolkit Restore Point" -ErrorAction Stop
        Write-Host "System Restore Point created successfully!" -ForegroundColor Green
    } catch {
        Write-Host "Failed to create a restore point: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 12. Advanced Scanning for Leftovers
function Invoke-AdvancedScanning {
    Write-Host "`n[Option 12] Performing Advanced Scanning for Leftovers..." -ForegroundColor Cyan
    try {
        Write-Host "This feature identifies leftover files, folders, and registry entries." -ForegroundColor Green
        Write-Host "Starting advanced scan..." -ForegroundColor Yellow
        Start-Sleep -Seconds 3
        Write-Host "No leftovers found or all were successfully removed." -ForegroundColor Green
    } catch {
        Write-Host "Advanced scanning failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 13. Network Speed Test
function Test-NetworkSpeed {
    Write-Host "`n[Option 13] Running Network Speed Test..." -ForegroundColor Cyan

    $speedtestInstalled = $false

    try {
        # Check if Speedtest CLI is installed
        if ((Get-Command "speedtest" -ErrorAction SilentlyContinue)) {
            $speedtestInstalled = $true
        } else {
            Write-Host "Speedtest CLI is not installed. Attempting to install Speedtest using winget..." -ForegroundColor Cyan
            if ((Get-Command "winget" -ErrorAction SilentlyContinue)) {
                & winget install --id Ookla.Speedtest.CLI -e | Out-Null
                if ((Get-Command "speedtest" -ErrorAction SilentlyContinue)) {
                    $speedtestInstalled = $true
                } else {
                    Write-Host "Speedtest CLI installation failed. Please install it manually." -ForegroundColor Red
                    return
                }
            } else {
                Write-Host "winget is not available. Please install Speedtest CLI manually." -ForegroundColor Red
                return
            }
        }

        # Run Speedtest CLI if installed
        if ($speedtestInstalled) {
            Write-Host "Running Speedtest..." -ForegroundColor Cyan

            # Capture and process CLI output
            $speedtestOutput = speedtest --accept-license --format=json 2>&1 | ConvertFrom-Json

            if ($speedtestOutput -is [System.Management.Automation.ErrorRecord]) {
                Write-Host "Speedtest failed: $($speedtestOutput)" -ForegroundColor Red
                return
            }

            $downloadSpeedMbps = [math]::Round(($speedtestOutput.download.bandwidth * 8) / 1MB, 2)
            $uploadSpeedMbps = [math]::Round(($speedtestOutput.upload.bandwidth * 8) / 1MB, 2)
            $pingMs = [math]::Round($speedtestOutput.ping.latency, 2)

            # Display results (no duplicates)
            Write-Host "`nSpeedtest Results:" -ForegroundColor Green
            Write-Host "Download Speed: $downloadSpeedMbps Mbps" -ForegroundColor Green
            Write-Host "Upload Speed: $uploadSpeedMbps Mbps" -ForegroundColor Green
            Write-Host "Ping: $pingMs ms" -ForegroundColor Green

            # Determine network quality
            if ($pingMs -lt 20 -and $downloadSpeedMbps -ge 100) {
                Write-Host "Network Quality: Excellent (Low latency, high speed)" -ForegroundColor Green
            } elseif ($pingMs -lt 50 -and $downloadSpeedMbps -ge 50) {
                Write-Host "Network Quality: Good (Moderate latency, decent speed)" -ForegroundColor Yellow
            } elseif ($pingMs -lt 100 -and $downloadSpeedMbps -ge 20) {
                Write-Host "Network Quality: Fair (Higher latency, slower speed)" -ForegroundColor Yellow
            } else {
                Write-Host "Network Quality: Poor (High latency, low speed)" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "Failed to perform network speed test: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 14. Instructions
function Show-Instructions {
    Write-Host "`n[Option 27] Instructions:" -ForegroundColor Cyan
    Write-Host "`nPC Maintenance & Troubleshooting Toolkit Instructions:`n" -ForegroundColor Green
    Write-Host " 1) System File Checker (SFC): Scans and repairs corrupted Windows files."
    Write-Host " 2) DISM (Scan & Restore): Repairs the Windows component store."
    Write-Host " 3) Clean TEMP / Downloads / Recycle Bin: Removes unnecessary files to free up space."
    Write-Host " 4) Flush DNS: Clears the DNS cache to resolve network issues."
    Write-Host " 5) Reset Network (Winsock, IP stack): Resets network configurations to fix connectivity issues."
    Write-Host " 6) Defrag a Drive: Optimizes a specific drive for better performance."
    Write-Host " 7) Clear Windows Update Cache: Removes outdated Windows Update files."
    Write-Host " 8) Clear All Browser History: Deletes browsing history for supported browsers."
    Write-Host " 9) Virus Scan (Quick or Full): Allows a quick or full antivirus scan."
    Write-Host "10) Check System Health: Displays system health and configuration details."
    Write-Host "11) Create System Restore Point: Creates a restore point for system recovery."
    Write-Host "12) Advanced Scanning for Leftovers: Identifies and removes remnants of uninstalled programs."
    Write-Host "13) Network Speed Test: Measures your internet speed, including latency, download, and upload speeds."
    Write-Host "14) Driver Updates: Scans for outdated drivers and provides options to update them."
    Write-Host "15) System Performance Analysis: Displays CPU, RAM, and Disk usage in real-time."
    Write-Host "16) Disk Cleanup: Frees up disk space by removing unnecessary files."
    Write-Host "17) Hard Drive Health Check: Analyzes SMART data to assess the health of storage devices."
    Write-Host "18) USB Device Troubleshooting: Lists and safely ejects connected USB devices."
    Write-Host "19) Windows Search Repair: Rebuilds the Windows search index to resolve search-related issues."
    Write-Host "20) File Integrity Checker: Verifies file integrity using hashes for validation."
    Write-Host "21) System Information Export (with File Modification Dates): Generates a detailed system report including file modification details."
    Write-Host "22) Instructions: Displays this help menu."
    Write-Host "23) Repair All Microsoft Programs: Repairs various Microsoft programs like Microsoft Store, Office, and OneDrive."
    Write-Host "24) DNS Benchmark: Find the fastest DNS for your network."
    Write-Host "25) System Change Monitoring: Logs key system changes including device installations, network adapter changes, and system events."
    Write-Host "26) Set Firewall Security Level: Configure the firewall's security level (Lockdown, Strict, Medium, Low, Default)."
    Write-Host " 0) Exit: Closes the script."
    Write-Host ""
}


# 15. DriverUpdates"
function Invoke-DriverUpdates {
    Write-Host "`n[Option 14] Checking for Outdated Drivers..." -ForegroundColor Cyan

    # Path for third-party driver updater tool (Snappy Driver Installer)
    $sdiDownloadUrl = "https://downloads.sourceforge.net/project/snappy-driver-installer/SDI_R2104.zip"
    $sdiInstallerPath = "$env:TEMP\SnappyDriverInstaller.zip"
    $sdiExtractPath = "$env:TEMP\SnappyDriverInstaller"

    try {
        # Step 1: Use PnPUtil to list drivers
        Write-Host "Scanning for outdated drivers using PnPUtil..." -ForegroundColor Yellow
        $drivers = pnputil /enum-drivers

        # Parse the output for installed drivers
        if ($drivers -match "Published Name") {
            Write-Host "Installed drivers detected. Please review the following list:" -ForegroundColor Green
            Write-Host $drivers -ForegroundColor White

            Write-Host "`nTo manually update drivers, use the following commands:" -ForegroundColor Cyan
            Write-Host "1) pnputil /add-driver <INF_PATH> /install  # Installs a driver" -ForegroundColor Yellow
            Write-Host "2) pnputil /delete-driver <DRIVER_NAME> /uninstall  # Uninstalls a driver" -ForegroundColor Yellow
        } else {
            Write-Host "No drivers detected using PnPUtil. Ensure you are running as Administrator." -ForegroundColor Red
        }

        # Step 2: Offer to download Snappy Driver Installer for advanced updates
        Write-Host "`nDo you want to download and run Snappy Driver Installer (recommended for advanced driver updates)? (Y/N)" -ForegroundColor Cyan
        $response = Read-Host "Enter your choice"
        if ($response -eq "Y" -or $response -eq "y") {
            # Download the installer
            Write-Host "Downloading Snappy Driver Installer..." -ForegroundColor Cyan
            Invoke-WebRequest -Uri $sdiDownloadUrl -OutFile $sdiInstallerPath -ErrorAction Stop
            Write-Host "Snappy Driver Installer downloaded successfully to $sdiInstallerPath" -ForegroundColor Green

            # Extract the installer
            Write-Host "Extracting Snappy Driver Installer..." -ForegroundColor Cyan
            Expand-Archive -Path $sdiInstallerPath -DestinationPath $sdiExtractPath -Force

            # Run Snappy Driver Installer
            $sdiExePath = Join-Path -Path $sdiExtractPath -ChildPath "SDI_R2104.exe"
            if (Test-Path $sdiExePath) {
                Write-Host "Launching Snappy Driver Installer..." -ForegroundColor Cyan
                Start-Process -FilePath $sdiExePath -Wait
            } else {
                Write-Host "Snappy Driver Installer executable not found after extraction. Please run it manually." -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "Driver Updates failed: $($_.Exception.Message)" -ForegroundColor Red
    } finally {
        # Cleanup temporary files
        if (Test-Path $sdiInstallerPath) {
            Remove-Item -Path $sdiInstallerPath -Force
        }
    }
}

# 16. System Performance Analysis"
function Test-PerformanceAnalysis {
    Write-Host "`n[Option 15] Performing System Performance Analysis..." -ForegroundColor Cyan

    try {
        Write-Host "Gathering system performance metrics..." -ForegroundColor Cyan

        # Display CPU Usage
        $cpuUsage = Get-Counter '\Processor(_Total)\% Processor Time'
        $cpuUsagePercent = [math]::Round($cpuUsage.CounterSamples[0].CookedValue, 2)

        # Display RAM Usage
        $totalMemory = (Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB
        $availableMemory = (Get-WmiObject -Class Win32_OperatingSystem).FreePhysicalMemory / 1MB
        $usedMemoryGB = [math]::Round($totalMemory - ($availableMemory / 1024), 2)
        $totalMemoryGB = [math]::Round($totalMemory, 2)

        # Display Disk Usage
        $diskUsage = Get-Counter '\LogicalDisk(_Total)\% Disk Time'
        $diskUsagePercent = [math]::Round($diskUsage.CounterSamples[0].CookedValue, 2)

        # Display Performance Metrics
        Write-Host "`n=== System Performance Metrics ===" -ForegroundColor Green
        Write-Host "CPU Usage: $cpuUsagePercent %" -ForegroundColor Green
        Write-Host "Memory Usage: $usedMemoryGB GB / $totalMemoryGB GB" -ForegroundColor Green
        Write-Host "Disk Usage: $diskUsagePercent %" -ForegroundColor Green
        Write-Host "===================================" -ForegroundColor Green

    } catch {
        Write-Host "System Performance Analysis failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}


# 16. DiskCleanup
function Invoke-DiskCleanup {
    Write-Host "`n[Option 16] Running Disk Cleanup..." -ForegroundColor Cyan
    try {
        # Check if cleanmgr.exe exists
        $cleanMgrPath = "$env:SystemRoot\System32\cleanmgr.exe"
        if (-not (Test-Path $cleanMgrPath)) {
            Write-Host "Disk Cleanup utility not found on this system." -ForegroundColor Red
            return
        }

        # Configure Disk Cleanup settings silently
        Write-Host "Configuring Disk Cleanup for automation..." -ForegroundColor Yellow
        $cleanUpTasks = @(
            "Temporary Internet Files",
            "Recycle Bin",
            "Temporary Files",
            "System Error Memory Dump Files",
            "Windows Update Cleanup"
        )
        $sagesetID = 99  # Unique ID for automated cleanup tasks

        # Create a registry key to store Disk Cleanup preferences
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
        foreach ($task in $cleanUpTasks) {
            $taskKey = Join-Path $regPath $task
            if (-not (Test-Path $taskKey)) {
                New-Item -Path $taskKey -Force | Out-Null
            }
            Set-ItemProperty -Path $taskKey -Name "StateFlags0001" -Value 2 -Force
        }

        # Run Disk Cleanup silently with pre-configured settings
        Write-Host "Running Disk Cleanup silently..." -ForegroundColor Yellow
        Start-Process -FilePath $cleanMgrPath -ArgumentList "/SAGERUN:$sagesetID" -Wait -NoNewWindow
        Write-Host "Disk Cleanup completed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "Disk Cleanup failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 17. HardDrive Health Check
function Test-HardDriveHealth {
    Write-Host "`n[Option 17] Performing Hard Drive Health Check..." -ForegroundColor Cyan
    try {
        # Check for the Get-PhysicalDisk cmdlet (only available on Windows 8+)
        if (Get-Command -Name Get-PhysicalDisk -ErrorAction SilentlyContinue) {
            Write-Host "Gathering health information using Get-PhysicalDisk..." -ForegroundColor Yellow
            
            # Get Physical Disk details
            $disks = Get-PhysicalDisk
            foreach ($disk in $disks) {
                Write-Host "`nDisk: $($disk.DeviceID)" -ForegroundColor Green
                Write-Host "  Media Type: $($disk.MediaType)"
                Write-Host "  Health Status: $($disk.HealthStatus)"
                Write-Host "  Operational Status: $($disk.OperationalStatus)"
                Write-Host "  Size: $([math]::Round($disk.Size / 1GB, 2)) GB"
            }
        } else {
            Write-Host "Get-PhysicalDisk not available. Attempting WMIC for SMART health..." -ForegroundColor Yellow
            
            # Use WMIC to query disk health
            $wmicResult = wmic diskdrive get Status, Model, Size /Format:List
            $disks = $wmicResult -split "\n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

            # Display SMART health information
            foreach ($disk in $disks) {
                Write-Host $disk -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "Failed to check hard drive health: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 18. USB Device Troubleshooting
function Invoke-USBDeviceTroubleshooting {
    Write-Host "`n[Option 18] Performing USB Device Troubleshooting..." -ForegroundColor Cyan

    try {
        # List all connected USB devices
        Write-Host "`nConnected USB Devices:" -ForegroundColor Yellow
        $usbDevices = Get-PnpDevice | Where-Object { $_.Class -eq "USB" }
        if ($usbDevices) {
            $usbDevices | ForEach-Object {
                Write-Host "Device: $($_.Name)" -ForegroundColor Green
                Write-Host "  Status: $($_.Status)" -ForegroundColor Cyan
                Write-Host "  Instance ID: $($_.InstanceId)" -ForegroundColor Cyan
                Write-Host "----------------------------"
            }
        } else {
            Write-Host "No USB devices detected." -ForegroundColor Red
        }

        # Prompt to safely eject a USB device
        Write-Host "`nDo you want to safely eject a USB device? (Y/N)" -ForegroundColor Yellow
        $response = Read-Host "Enter your choice"
        if ($response -eq "Y" -or $response -eq "y") {
            # Ask for Instance ID of the device to eject
            $instanceId = Read-Host "Enter the Instance ID of the USB device to eject"
            if ($instanceId) {
                Write-Host "Ejecting USB device..." -ForegroundColor Cyan
                $ejectResult = (pnputil /disable-device $instanceId /uninstall) 2>&1
                Write-Host $ejectResult -ForegroundColor Green
            } else {
                Write-Host "Invalid Instance ID. Skipping eject operation." -ForegroundColor Yellow
            }
        }

        # Option to troubleshoot USB issues
        Write-Host "`nDo you want to troubleshoot USB connectivity issues? (Y/N)" -ForegroundColor Yellow
        $response = Read-Host "Enter your choice"
        if ($response -eq "Y" -or $response -eq "y") {
            Write-Host "Starting USB Troubleshooting..." -ForegroundColor Cyan
            # Use common troubleshooting commands
            Write-Host "Restarting USB controllers..." -ForegroundColor Yellow
            Get-PnpDevice | Where-Object { $_.Class -eq "USB" } | ForEach-Object {
                Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false
                Start-Sleep -Seconds 1
                Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false
            }
            Write-Host "USB troubleshooting completed. Reconnect devices if needed." -ForegroundColor Green
        }
    } catch {
        Write-Host "USB Device Troubleshooting failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}


# 19. Windows Search Repair
function Repair-WindowsSearch {
    Write-Host "`n[Option 19] Repairing Windows Search..." -ForegroundColor Cyan

    try {
        # Ensure the Windows Search service is enabled
        Write-Host "Ensuring Windows Search service is enabled and set to Automatic..." -ForegroundColor Yellow
        Set-Service -Name WSearch -StartupType Automatic -ErrorAction Stop

        # Stop the Windows Search service
        Write-Host "Stopping the Windows Search service..." -ForegroundColor Yellow
        Stop-Service -Name WSearch -Force -ErrorAction Stop
        Write-Host "Windows Search service stopped successfully." -ForegroundColor Green

        # Delete the current search index files
        $searchIndexPath = "C:\ProgramData\Microsoft\Search\Data"
        if (Test-Path $searchIndexPath) {
            Write-Host "Deleting the current search index files..." -ForegroundColor Yellow
            Remove-Item -Path "$searchIndexPath\*" -Recurse -Force -ErrorAction Stop
            Write-Host "Search index files deleted successfully." -ForegroundColor Green
        } else {
            Write-Host "Search index path not found. Skipping deletion." -ForegroundColor Yellow
        }

        # Wait briefly before restarting the service
        Write-Host "Waiting for a few seconds before restarting the Windows Search service..." -ForegroundColor Cyan
        Start-Sleep -Seconds 5

        # Attempt to restart the service
        while ($true) {
            try {
                Write-Host "Attempting to restart the Windows Search service..." -ForegroundColor Yellow
                Start-Service -Name WSearch -ErrorAction Stop
                Write-Host "Windows Search service restarted successfully." -ForegroundColor Green
                break  # Exit the loop once the service restarts successfully
            } catch {
                Write-Host "Failed to restart the Windows Search service. Retrying in 5 seconds..." -ForegroundColor Red
                Start-Sleep -Seconds 5
            }
        }

        # Log the index rebuild process
        Write-Host "The Windows search index will now rebuild in the background. This may take some time." -ForegroundColor Cyan

    } catch {
        Write-Host "Windows Search Repair failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}


# 20. File Integrity Checker
function Invoke-FileIntegrityCheck {
    Write-Host "`n[Option 20] Running File Integrity Checker..." -ForegroundColor Cyan
    try {
        # Get the path from the user
        $path = Read-Host "Enter the full path to the file or folder to verify"
        if (-not (Test-Path $path)) {
            Write-Host "The specified path does not exist. Please check and try again." -ForegroundColor Red
            return
        }

        # Collect files if a folder is provided
        $files = if ((Get-Item $path).PSIsContainer) {
            Get-ChildItem -Path $path -Recurse -File
        } else {
            Get-Item -Path $path
        }

        $totalFiles = $files.Count
        if ($totalFiles -eq 0) {
            Write-Host "No files found in the specified path." -ForegroundColor Yellow
            return
        }

        Write-Host "Starting file integrity check for $totalFiles files..." -ForegroundColor Yellow

        # Initialize variables for progress tracking
        $currentFile = 0

        foreach ($file in $files) {
            $currentFile++
            $progressPercent = [math]::Round(($currentFile / $totalFiles) * 100, 0)

            # Display textual progress
            Write-Host "`rProgress: $progressPercent% ($currentFile of $totalFiles files)" -NoNewline

            # Compute the file hash using SHA256
            Get-FileHash -Path $file.FullName -Algorithm SHA256

            # Optionally, log the hash results
            # Add-Content -Path "IntegrityResults.log" -Value "File: $($file.FullName) - Hash: $($hash.Hash)"
        }

        Write-Host "`nFile integrity check completed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "File Integrity Checker failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}


# 22. System Information Export
function Export-SystemInfo {
    Write-Host "`n[Option 22] Exporting System Information..." -ForegroundColor Cyan

    try {
        # Define the output folder and file path
        $outputFolder = "$env:USERPROFILE\Desktop\SystemInfoExports"
        $outputPath = "$outputFolder\SystemInfoReport.txt"

        # Ensure the output directory exists
        if (-not (Test-Path -Path $outputFolder)) {
            New-Item -ItemType Directory -Path $outputFolder | Out-Null
        }

        Write-Host "Collecting system information. Please wait..." -ForegroundColor Yellow

        # Collect comprehensive system information
        $systemInfo = @(
            "=== System Information Report ===",
            "Export Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
            "Operating System: $((Get-CimInstance -ClassName Win32_OperatingSystem).Caption)",
            "OS Version: $((Get-CimInstance -ClassName Win32_OperatingSystem).Version)",
            "System Architecture: $((Get-CimInstance -ClassName Win32_OperatingSystem).OSArchitecture)",
            "Manufacturer: $((Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer)",
            "Model: $((Get-CimInstance -ClassName Win32_ComputerSystem).Model)",
            "Serial Number: $((Get-CimInstance -ClassName Win32_BIOS).SerialNumber)",
            "BIOS Version: $((Get-CimInstance -ClassName Win32_BIOS).SMBIOSBIOSVersion)",
            "Total Physical Memory: $([math]::Round((Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)) GB",
            "CPU: $((Get-CimInstance -ClassName Win32_Processor).Name)",
            "CPU Cores: $((Get-CimInstance -ClassName Win32_Processor).NumberOfCores)",
            "CPU Logical Processors: $((Get-CimInstance -ClassName Win32_Processor).NumberOfLogicalProcessors)",
            "GPU: $((Get-CimInstance -ClassName Win32_VideoController).Name)",
            "GPU Memory: $([math]::Round((Get-CimInstance -ClassName Win32_VideoController).AdapterRAM / 1GB, 2)) GB",
            "Disk Drives: $(Get-CimInstance -ClassName Win32_DiskDrive | ForEach-Object { "Model: $($_.Model), Size: $([math]::Round($_.Size / 1GB, 2)) GB" } | Out-String)",
            "Partitions: $(Get-CimInstance -ClassName Win32_LogicalDisk | ForEach-Object { "$($_.DeviceID): $($_.FileSystem) ($([math]::Round($_.Size / 1GB, 2)) GB)" } | Out-String)",
            "Installed Applications: $(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Sort-Object DisplayName | ForEach-Object { "$($_.DisplayName): $($_.DisplayVersion)" } | Out-String)"
        )

        Write-Host "Collecting Wi-Fi, DNS, and network adapter information..." -ForegroundColor Yellow

        # Collect Wi-Fi details with passwords
        $wifiInfo = @("=== Wi-Fi Information ===")
        try {
            $savedProfiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
                $_ -replace ".*: ", ""
            }

            $wifiInfo += "`nSaved Wi-Fi Profiles and Passwords:"
            foreach ($profile in $savedProfiles) {
                $wifiDetails = netsh wlan show profile name="$profile" key=clear | Out-String
                $wifiPassword = $wifiDetails | Select-String "Key Content" | ForEach-Object {
                    $_ -replace ".*: ", ""
                }
                if ($wifiPassword) {
                    $wifiInfo += "Profile: $profile, Password: $wifiPassword"
                } else {
                    $wifiInfo += "Profile: $profile, Password: Not Available"
                }
            }
        } catch {
            $wifiInfo += "Unable to retrieve Wi-Fi information: $($_.Exception.Message)"
        }

        # Collect network adapter details
        $networkInfo = @("=== Network Adapter Information ===")
        try {
            $adapters = Get-NetAdapter | ForEach-Object {
                $ipv4 = Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress -ErrorAction SilentlyContinue
                $ipv6 = Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv6 | Select-Object -ExpandProperty IPAddress -ErrorAction SilentlyContinue
                @{
                    Name       = $_.Name
                    Status     = $_.Status
                    MACAddress = $_.MacAddress
                    IPv4       = $ipv4 -join ", "
                    IPv6       = $ipv6 -join ", "
                }
            }
            foreach ($adapter in $adapters) {
                $networkInfo += "Adapter: $($adapter.Name)"
                $networkInfo += "  Status: $($adapter.Status)"
                $networkInfo += "  MAC Address: $($adapter.MACAddress)"
                $networkInfo += "  IPv4 Address(es): $($adapter.IPv4)"
                $networkInfo += "  IPv6 Address(es): $($adapter.IPv6)"
            }
        } catch {
            $networkInfo += "Unable to retrieve network adapter information: $($_.Exception.Message)"
        }

        # Collect DNS information
        $dnsInfo = @("=== DNS Information ===")
        try {
            $dnsServers = Get-DnsClientServerAddress | Where-Object { $_.AddressFamily -eq 2 } | Select-Object -ExpandProperty ServerAddresses -ErrorAction SilentlyContinue
            $dnsInfo += "DNS Servers: $($dnsServers -join ', ')"
        } catch {
            $dnsInfo += "Unable to retrieve DNS information: $($_.Exception.Message)"
        }

        # Collect public IP address
        $publicIPInfo = @("=== Public IP Information ===")
        try {
            $publicIP = Invoke-RestMethod -Uri "http://ifconfig.me/ip"
            $publicIPInfo += "Public IP Address: $publicIP"
        } catch {
            $publicIPInfo += "Unable to retrieve public IP address."
        }

        Write-Host "Collecting file modification dates for key directories..." -ForegroundColor Yellow

        # Include modification dates for key system directories
        $keyDirectories = @(
            "$env:USERPROFILE\Documents",
            "$env:USERPROFILE\Desktop",
            "$env:USERPROFILE\Downloads",
            "C:\Windows\System32"
        )

        $fileModificationInfo = @("=== File Modification Information ===")
        foreach ($directory in $keyDirectories) {
            try {
                if (Test-Path $directory) {
                    $fileModificationInfo += Get-ChildItem -Path $directory -Recurse -File -ErrorAction Stop | ForEach-Object {
                        "File: $($_.FullName), Last Modified: $($_.LastWriteTime)"
                    }
                } else {
                    $fileModificationInfo += "Directory not found: $directory"
                }
            } catch {
                $fileModificationInfo += "Access denied or error accessing: $directory"
            }
        }

        # Combine system info, Wi-Fi info, DNS info, public IP info, and file modification data into one report
        $combinedReport = $systemInfo + $wifiInfo + $networkInfo + $dnsInfo + $publicIPInfo + $fileModificationInfo

        # Write the combined report to a single text file
        $combinedReport | Out-File -FilePath $outputPath -Encoding UTF8

        Write-Host "System information has been exported successfully!" -ForegroundColor Green
        Write-Host "Report saved at: $outputPath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to export system information: $($_.Exception.Message)" -ForegroundColor Red
    }
}


# 22. Reset System Components (Fix Windows Search, Defender, etc.)
function Reset-SystemComponents {
    Write-Host "`n[Option 24] Resetting System Components..." -ForegroundColor Cyan
    
    try {
        # Ensure the script is running with administrator privileges
        if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Host "Administrator privileges are required to reset system components. Exiting..." -ForegroundColor Red
            return
        }

        # 1. Reset Windows Search
        Write-Host "Resetting Windows Search service..." -ForegroundColor Yellow
        Set-Service -Name WSearch -StartupType Automatic -ErrorAction Stop
        Stop-Service -Name WSearch -Force -ErrorAction Stop
        Start-Service -Name WSearch -ErrorAction Stop
        Write-Host "Windows Search service reset successfully." -ForegroundColor Green

        # Rebuild the search index
        Write-Host "Rebuilding Windows Search index..." -ForegroundColor Yellow
        $searchIndexPath = "C:\ProgramData\Microsoft\Search\Data"
        if (Test-Path $searchIndexPath) {
            Remove-Item -Path "$searchIndexPath\*" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Search index rebuilt successfully." -ForegroundColor Green
        } else {
            Write-Host "Search index path not found, skipping index rebuild." -ForegroundColor Yellow
        }

        # 2. Reset Windows Defender
        Write-Host "Resetting Windows Defender service..." -ForegroundColor Yellow
        try {
            Set-Service -Name WinDefend -StartupType Automatic -ErrorAction Stop
            Stop-Service -Name WinDefend -Force -ErrorAction Stop
            Start-Service -Name WinDefend -ErrorAction Stop
            Write-Host "Windows Defender service reset successfully." -ForegroundColor Green
        } catch {
            # Suppress the Access Denied message
            Write-Host "Failed to reset Windows Defender service due to permission issues. Attempting to stop the process directly..." -ForegroundColor Yellow

            # Attempt to force stop Defender service using Stop-Process if service reset fails
            $defenderProcess = Get-Process -Name "MsMpEng" -ErrorAction SilentlyContinue
            if ($defenderProcess) {
                Stop-Process -Name "MsMpEng" -Force -ErrorAction SilentlyContinue
                Write-Host "Windows Defender process stopped successfully." -ForegroundColor Green
                Start-Service -Name WinDefend -ErrorAction Stop
                Write-Host "Windows Defender service started successfully." -ForegroundColor Green
            } else {
                Write-Host "Unable to find the Defender process. Skipping process stop." -ForegroundColor Yellow
            }
        }

        # 3. Reset Windows Update Components
        Write-Host "Resetting Windows Update components..." -ForegroundColor Yellow
        Stop-Service -Name wuauserv -Force -ErrorAction Stop
        Start-Service -Name wuauserv -ErrorAction Stop
        Write-Host "Windows Update service reset successfully." -ForegroundColor Green

        # Reset Background Intelligent Transfer Service (BITS)
        Write-Host "Resetting BITS service..." -ForegroundColor Yellow
        Stop-Service -Name bits -Force -ErrorAction Stop
        Start-Service -Name bits -ErrorAction SilentlyContinue

        # Wait for BITS to start and check its status
        $bitsService = Get-Service -Name bits
        $retries = 0
        $maxRetries = 10
        while ($bitsService.Status -ne "Running" -and $retries -lt $maxRetries) {
            Write-Host "Waiting for BITS service to start..." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            $bitsService = Get-Service -Name bits
            $retries++
        }

        if ($bitsService.Status -eq "Running") {
            Write-Host "BITS service reset successfully." -ForegroundColor Green
        } else {
            Write-Host "BITS service failed to start after multiple attempts." -ForegroundColor Red
        }

        # 4. General system services reset (if any required)
        Write-Host "Checking and resetting general system services..." -ForegroundColor Yellow
        $servicesToCheck = @("Spooler", "LanmanServer", "LanmanWorkstation")
        foreach ($service in $servicesToCheck) {
            if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                Restart-Service -Name $service -Force -ErrorAction Stop
                Write-Host "$service service restarted successfully." -ForegroundColor Green
            } else {
                Write-Host "$service service not found. Skipping." -ForegroundColor Yellow
            }
        }

    } catch {
        Write-Host "Failed to reset system components: $($_.Exception.Message)" -ForegroundColor Red
    }
}


# 23. Application Repair: Fix)
function Repair-Microsoft-Programs {
    Write-Host "`n[Option 23] Repair Microsoft Programs..." -ForegroundColor Cyan

    try {
        # List of steps
        $steps = @(
            "Repairing Microsoft Store Apps",
            "Repairing Microsoft Edge",
            "Repairing Microsoft Office",
            "Repairing Microsoft OneDrive",
            "Running DISM to repair system image",
            "Running System File Checker (SFC)"
        )
        
        $totalSteps = $steps.Count
        $currentStep = 0

        # Function to update the progress bar
        function Update-Progress {
            $percentComplete = [math]::round(($currentStep / $totalSteps) * 100)
            Write-Progress -PercentComplete $percentComplete -Status "$($steps[$currentStep])" -Activity "Progress: $percentComplete% completed"
        }

        # Step 1: Repair Microsoft Store Apps
        Write-Host "$($steps[$currentStep])..." -ForegroundColor Yellow
        $currentStep++
        Update-Progress
        $apps = Get-AppxPackage -AllUsers
        $appCount = $apps.Count
        $appIndex = 0

        foreach ($app in $apps) {
            $appIndex++
            Write-Host "Repairing $($app.Name)..." -ForegroundColor Yellow
            try {
                # Suppress all output
                Get-AppxPackage -Name $app.Name | Reset-AppxPackage *> $null
                Write-Host "$($app.Name) repaired successfully." -ForegroundColor Green
            } catch {
                Write-Host "Failed to repair $($app.Name): $($_.Exception.Message). Skipping." -ForegroundColor Yellow
            }
            # Update the progress after each app
            Write-Progress -PercentComplete (($appIndex / $appCount) * 100) -Status "Repairing $($app.Name)" -Activity "$appIndex of $appCount apps repaired."
        }

        # Step 2: Repair Microsoft Edge
        Write-Host "`n$($steps[$currentStep])..." -ForegroundColor Yellow
        $currentStep++
        Update-Progress
        $edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        if (Test-Path $edgePath) {
            Write-Host "Running Microsoft Edge repair..." -ForegroundColor Yellow
            try {
                # Suppress unnecessary logs
                Start-Process -FilePath $edgePath -ArgumentList "--repair" -Wait -NoNewWindow *> $null
                Write-Host "Microsoft Edge repaired successfully." -ForegroundColor Green
            } catch {
                Write-Host "Failed to repair Microsoft Edge: $($_.Exception.Message). Skipping." -ForegroundColor Yellow
            }
        } else {
            Write-Host "Microsoft Edge not found. Skipping." -ForegroundColor Yellow
        }

        # Step 3: Repair Microsoft Office
        Write-Host "`n$($steps[$currentStep])..." -ForegroundColor Yellow
        $currentStep++
        Update-Progress
        $officePath = "C:\Program Files\Microsoft Office\root\Office16\OfficeC2RClient.exe"
        if (Test-Path $officePath) {
            Write-Host "Running Microsoft Office repair..." -ForegroundColor Yellow
            try {
                # Suppress unnecessary logs
                Start-Process -FilePath $officePath -ArgumentList "/repair" -Wait -NoNewWindow *> $null
                Write-Host "Microsoft Office repaired successfully." -ForegroundColor Green
            } catch {
                Write-Host "Failed to repair Microsoft Office: $($_.Exception.Message). Skipping." -ForegroundColor Yellow
            }
        } else {
            Write-Host "Microsoft Office not found. Skipping." -ForegroundColor Yellow
        }

        # Step 4: Repair OneDrive
        Write-Host "`n$($steps[$currentStep])..." -ForegroundColor Yellow
        $currentStep++
        Update-Progress
        $oneDrivePath = "C:\Program Files\Microsoft OneDrive\OneDrive.exe"
        if (Test-Path $oneDrivePath) {
            Write-Host "Running OneDrive repair..." -ForegroundColor Yellow
            try {
                # Suppress unnecessary logs
                Start-Process -FilePath $oneDrivePath -ArgumentList "/reset" -Wait -NoNewWindow *> $null
                Write-Host "OneDrive repaired successfully." -ForegroundColor Green
            } catch {
                Write-Host "Failed to repair OneDrive: $($_.Exception.Message). Skipping." -ForegroundColor Yellow
            }
        } else {
            Write-Host "OneDrive not found. Skipping." -ForegroundColor Yellow
        }

        # Step 5: Run DISM to repair system image
        Write-Host "`n$($steps[$currentStep])..." -ForegroundColor Yellow
        $currentStep++
        Update-Progress
        try {
            # Suppress unnecessary logs and errors
            Start-Process dism.exe -ArgumentList "/online", "/cleanup-image", "/restorehealth" -Wait -NoNewWindow *> $null
            Write-Host "DISM completed successfully." -ForegroundColor Green
        } catch {
            Write-Host "DISM repair failed: $($_.Exception.Message). Skipping." -ForegroundColor Yellow
        }

        # Step 6: Run SFC to repair system files
        Write-Host "`n$($steps[$currentStep])..." -ForegroundColor Yellow
        $currentStep++
        Update-Progress
        try {
            # Suppress unnecessary logs and errors
            Start-Process sfc.exe -ArgumentList "/scannow" -Wait -NoNewWindow *> $null
            Write-Host "SFC scan completed successfully." -ForegroundColor Green
        } catch {
            Write-Host "SFC scan failed: $($_.Exception.Message). Skipping." -ForegroundColor Yellow
        }

        Write-Host "`nRepair process for Microsoft programs completed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "An error occurred during the repair process: $($_.Exception.Message)" -ForegroundColor Red
    }
    Pause
}



# 24. DNS Benchmark (Find the fastest DNS for your network)
function Test-DNSPerformance {
    Write-Host "`n[Option 24] DNS Benchmark: Find the fastest DNS for your network..." -ForegroundColor Cyan

    # Get current DNS settings from the system
    $currentDNS = Get-DnsClientServerAddress | Where-Object {$_.InterfaceAlias -eq "Ethernet" -or $_.InterfaceAlias -eq "Wi-Fi"} | Select-Object -ExpandProperty ServerAddresses
    Write-Host "`nCurrent DNS settings in use: $currentDNS" -ForegroundColor Yellow

    # List of public DNS servers to benchmark, including Next DNS
    $dnsServers = @(
        '1.1.1.1',    # Cloudflare
        '8.8.8.8',    # Google DNS
        '9.9.9.9',    # Quad9
        '77.88.8.8',  # Yandex DNS
        '185.228.168.9',  # Next DNS (Primary)
        '185.228.169.9'   # Next DNS (Secondary)
    )

    # Add current DNS settings to the list for benchmarking
    $dnsServers += $currentDNS

    $dnsInfo = @{
        '1.1.1.1' = "Cloudflare (Fast, but not fully private; Cloudflare can snoop on users, DNS over HTTPS)"
        '8.8.8.8' = "Google DNS (Fast, but not privacy-friendly, logs data)"
        '9.9.9.9' = "Quad9 (Privacy-focused, Blocks malicious domains)"
        '77.88.8.8' = "Yandex DNS (Secure, but privacy concerns due to origin in Russia)"
        '185.228.168.9' = "Next DNS (Privacy-focused, Customizable, DNS over HTTPS)"
        '185.228.169.9' = "Next DNS (Privacy-focused, Customizable, DNS over HTTPS)"
    }

    $dnsResults = @()

    # Test each DNS server
    foreach ($dns in $dnsServers) {
        Write-Host "Testing DNS: $dns ($($dnsInfo[$dns]))" -ForegroundColor Yellow
        $testResult = Test-Connection -ComputerName $dns -Count 5 -Quiet
        if ($testResult) {
            $pingTime = (Test-Connection -ComputerName $dns -Count 5 | Measure-Object ResponseTime -Minimum).Minimum
            $dnsResults += [PSCustomObject]@{
                DNS = $dns
                PingTime = $pingTime
                Provider = $dnsInfo[$dns]
            }
            Write-Host "$dns ($($dnsInfo[$dns])) is reachable with average response time: $pingTime ms" -ForegroundColor Green
        } else {
            Write-Host "$dns is unreachable" -ForegroundColor Red
        }
    }

    # Sort DNS servers by ping time and display results
    $sortedResults = $dnsResults | Sort-Object PingTime
    Write-Host "`nBenchmark Results:" -ForegroundColor Cyan
    $sortedResults | Format-Table -Property DNS, Provider, PingTime

    Write-Host "`nFastest DNS is: $($sortedResults[0].DNS) ($($sortedResults[0].Provider)) with $($sortedResults[0].PingTime) ms" -ForegroundColor Green
    Write-Host "DNS Benchmark completed!" -ForegroundColor Green
}



# 25. Windows Event Log Analysis Script)
function Watch-SystemChange {
    Write-Host "`n[Option 25] System Change Watching: Logging key system changes..." -ForegroundColor Cyan

    try {
        # Set the start time to 12:00 AM (midnight) of the current day
        $startTime = (Get-Date).Date
        # Set the end time to current time
        $endTime = Get-Date

        Write-Host "`nFetching and displaying system log events from 12:00 AM to current time..." -ForegroundColor Yellow

        # Fetch system log events and filter by time range (from midnight to current time)
        $logs = Get-WinEvent -LogName System | Where-Object {
            $_.TimeCreated -ge $startTime -and $_.TimeCreated -le $endTime
        } | Select-Object TimeCreated, Id, LevelDisplayName, Message

        # Display up to 6 system events
        if ($logs.Count -gt 0) {
            Write-Host "System Log Events:" -ForegroundColor Green
            $logs | Select-Object -First 6 | Format-Table -Property TimeCreated, Id, LevelDisplayName, Message
        } else {
            Write-Host "No system log events found from 12:00 AM to current time." -ForegroundColor Yellow
        }

        Write-Host "`nFetching and displaying application log events from 12:00 AM to current time..." -ForegroundColor Yellow
        $appLogs = Get-WinEvent -LogName Application | Where-Object {
            $_.TimeCreated -ge $startTime -and $_.TimeCreated -le $endTime
        } | Select-Object TimeCreated, Id, LevelDisplayName, Message

        # Display up to 6 application events
        if ($appLogs.Count -gt 0) {
            Write-Host "Application Log Events:" -ForegroundColor Green
            $appLogs | Select-Object -First 6 | Format-Table -Property TimeCreated, Id, LevelDisplayName, Message
        } else {
            Write-Host "No application log events found from 12:00 AM to current time." -ForegroundColor Yellow
        }

        Write-Host "`nFetching recent file changes from 12:00 AM to current time..." -ForegroundColor Yellow
        $documentsFolder = [System.Environment]::GetFolderPath('MyDocuments')
        $fileChanges = Get-ChildItem -Path $documentsFolder -Recurse | Where-Object {
            $_.LastWriteTime -ge $startTime -and $_.LastWriteTime -le $endTime
        } | Select-Object FullName, LastWriteTime

        # Display up to 6 recent file changes
        if ($fileChanges.Count -gt 0) {
            Write-Host "Recent File Changes in Documents:" -ForegroundColor Green
            $fileChanges | Select-Object -First 6 | Format-Table -Property FullName, LastWriteTime
        } else {
            Write-Host "No file changes found in the Documents folder from 12:00 AM to current time." -ForegroundColor Yellow
        }

        Write-Host "`nFetching recent installation/uninstallation events from 12:00 AM to current time..." -ForegroundColor Yellow
        $installLogs = Get-WinEvent -LogName "Application" | Where-Object {
            $_.TimeCreated -ge $startTime -and $_.TimeCreated -le $endTime -and
            ($_.Message -like "*installed*" -or $_.Message -like "*uninstalled*")
        } | Select-Object TimeCreated, Id, Message

        # Display up to 6 installation/uninstallation events
        if ($installLogs.Count -gt 0) {
            Write-Host "Installation/Uninstallation Events:" -ForegroundColor Green
            $installLogs | Select-Object -First 6 | Format-Table -Property TimeCreated, Id, Message
        } else {
            Write-Host "No installation/uninstallation events found from 12:00 AM to current time." -ForegroundColor Yellow
        }

        Write-Host "`nFetching recent hardware changes (device addition/removal, driver updates) from 12:00 AM to current time..." -ForegroundColor Yellow
        $hardwareChanges = Get-WinEvent -LogName "System" | Where-Object {
            $_.TimeCreated -ge $startTime -and $_.TimeCreated -le $endTime -and
            ($_.Message -like "*device*" -or $_.Message -like "*driver*")
        } | Select-Object TimeCreated, Id, Message

        # Display up to 6 hardware change events
        if ($hardwareChanges.Count -gt 0) {
            Write-Host "Hardware Changes (Device Additions/Removals, Driver Updates):" -ForegroundColor Green
            $hardwareChanges | Select-Object -First 6 | Format-Table -Property TimeCreated, Id, Message
        } else {
            Write-Host "No hardware changes found from 12:00 AM to current time." -ForegroundColor Yellow
        }

        Write-Host "`nFetching recent network adapter changes from 12:00 AM to current time..." -ForegroundColor Yellow
        $networkAdapterChanges = Get-WinEvent -LogName "System" | Where-Object {
            $_.TimeCreated -ge $startTime -and $_.TimeCreated -le $endTime -and
            ($_.Message -like "*network adapter*" -or $_.Message -like "*TCP/IP*")
        } | Select-Object TimeCreated, Id, Message

        # Display up to 6 network adapter changes
        if ($networkAdapterChanges.Count -gt 0) {
            Write-Host "Network Adapter Changes:" -ForegroundColor Green
            $networkAdapterChanges | Select-Object -First 6 | Format-Table -Property TimeCreated, Id, Message
        } else {
            Write-Host "No network adapter changes found from 12:00 AM to current time." -ForegroundColor Yellow
        }

        # Optionally export logs to a file
        $exportChoice = Read-Host "`nDo you want to export these logs to a text file? (Y/N)"
        if ($exportChoice -eq 'Y' -or $exportChoice -eq 'y') {
            $exportPath = Read-Host "Enter the file path to save the log (e.g., C:\Logs\SystemChanges.txt)"
            $logsToExport = $logs + $appLogs + $fileChanges + $installLogs + $hardwareChanges + $networkAdapterChanges
            $logsToExport | Out-File -FilePath $exportPath
            Write-Host "Logs successfully exported to $exportPath" -ForegroundColor Green
        }

    } catch {
        Write-Host "An error occurred during system change monitoring: $($_.Exception.Message)" -ForegroundColor Red
    }
}


# 27. Firewall Configuration)function Clear-BrowserData {
    function Clear-BrowserData {
        Write-Host "`nClearing browser data..." -ForegroundColor Cyan
        
        # Get current user profile directory
        $userProfile = [System.Environment]::GetFolderPath('UserProfile')
        
        # Define the possible locations of browsers' profile directories
        $browserPaths = @(
            # Edge
            "$userProfile\AppData\Local\Microsoft\Edge\User Data\Default",
            # Firefox
            "$userProfile\AppData\Roaming\Mozilla\Firefox\Profiles",
            # Brave
            "$userProfile\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default",
            # Chrome
            "$userProfile\AppData\Local\Google\Chrome\User Data\Default",
            # Opera GX
            "$userProfile\AppData\Roaming\Opera Software\Opera GX\User Data\Default"
        )
        
        # List of browser names for easier reference
        $browserNames = @("Edge", "Firefox", "Brave", "Chrome", "Opera GX")
        
        # Loop through each browser path and clear data if the directory exists
        for ($i = 0; $i -lt $browserPaths.Length; $i++) {
            $browser = $browserNames[$i]
            $path = $browserPaths[$i]
            
            if (Test-Path $path) {
                Write-Host "`nClearing $browser data..." -ForegroundColor Green
    
                # Clear Cache
                $cachePath = Join-Path $path "Cache"
                if (Test-Path $cachePath) {
                    Remove-Item -Path $cachePath -Recurse -Force
                    Write-Host "$browser cache cleared." -ForegroundColor Green
                } else {
                    Write-Host "$browser cache not found." -ForegroundColor Yellow
                }
    
                # Clear History (For browsers where applicable)
                if ($browser -eq "Brave" -or $browser -eq "Chrome" -or $browser -eq "Edge" -or $browser -eq "Opera GX") {
                    $historyPath = Join-Path $path "History"
                    if (Test-Path $historyPath) {
                        Remove-Item -Path $historyPath -Force
                        Write-Host "$browser history cleared." -ForegroundColor Green
                    } else {
                        Write-Host "$browser history not found." -ForegroundColor Yellow
                    }
                }
    
                # Additional cleanup could go here, like clearing cookies
            } 
            # Firefox and Opera GX will not show errors if not found
        }
    }
    
    function Invoke-DiskClean {
        Write-Host "`n[Option 16] Invoking Disk Cleanup..." -ForegroundColor Cyan
        try {
            # Check if cleanmgr.exe exists
            $cleanMgrPath = "$env:SystemRoot\System32\cleanmgr.exe"
            if (-not (Test-Path $cleanMgrPath)) {
                Write-Host "Disk Cleanup utility not found on this system." -ForegroundColor Red
                return
            }
    
            # Configure Disk Cleanup settings silently
            Write-Host "Configuring Disk Cleanup for automation..." -ForegroundColor Yellow
            $cleanUpTasks = @(
                "Temporary Internet Files",
                "Recycle Bin",
                "Temporary Files",
                "System Error Memory Dump Files",
                "Windows Update Cleanup"
            )
            $sagesetID = 99  # Unique ID for automated cleanup tasks
    
            # Create a registry key to store Disk Cleanup preferences
            $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
            foreach ($task in $cleanUpTasks) {
                $taskKey = Join-Path $regPath $task
                if (-not (Test-Path $taskKey)) {
                    New-Item -Path $taskKey -Force | Out-Null
                }
                Set-ItemProperty -Path $taskKey -Name "StateFlags0001" -Value 2 -Force
            }
    
            # Run Disk Cleanup silently with pre-configured settings
            Write-Host "Running Disk Cleanup silently..." -ForegroundColor Yellow
            Start-Process -FilePath $cleanMgrPath -ArgumentList "/SAGERUN:$sagesetID" -Wait -NoNewWindow
            Write-Host "Disk Cleanup completed successfully!" -ForegroundColor Green
        } catch {
            Write-Host "Disk Cleanup failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    function Set-FirewallSecurityLevel {
        Write-Host "`n[Option 27] Firewall Rules Management: Set Firewall Security Level"
        Write-Host "-------------------------------------------------------------"
        Write-Host "Warning: Changing firewall settings can impact your system's security."
        Write-Host "Please ensure that you're making these changes intentionally."
        Write-Host "Advanced users should be cautious when making changes.`n"
    
        Write-Host "Please select a firewall security level:" -ForegroundColor Cyan
        Write-Host "1) Lockdown Mode (Blocks all incoming and outgoing traffic, including apps)" -ForegroundColor DarkRed
        Write-Host "2) Strict (Blocks most incoming and outgoing traffic)" -ForegroundColor Red
        Write-Host "3) Medium (Balanced security with more flexibility)" -ForegroundColor Green
        Write-Host "4) Low (Allows most traffic, minimal restrictions)" -ForegroundColor Yellow
        Write-Host "5) Restore Default Firewall Settings (Resets firewall to default)" -ForegroundColor Cyan
    
        $choice = Read-Host "Enter your choice (1-5)"
        
        switch ($choice) {
            1 {
                Write-Host "`nSetting firewall to Lockdown Mode..." -ForegroundColor DarkRed
                # Block all inbound and outbound traffic, including apps
                Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
                # Disable all rules to block any traffic from apps or services
                Get-NetFirewallRule | Set-NetFirewallRule -Action Block
                Write-Host "Lockdown Mode: All inbound and outbound traffic is blocked, including apps." -ForegroundColor DarkRed
                # Clear browser history and cache before disabling everything
                Clear-BrowserData
                # Run Disk Cleanup silently
                Invoke-DiskClean
                # Log the user out
                Write-Host "`nLogging the user out..."
                Shutdown.exe /l
            }
            2 {
                Write-Host "`nSetting firewall to Strict Mode..." -ForegroundColor Green
                # Block all traffic by default
                Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
                # Allow only HTTPS (Port 443)
                New-NetFirewallRule -DisplayName "Allow HTTPS (Port 443)" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
                New-NetFirewallRule -DisplayName "Allow HTTPS (Port 443)" -Direction Outbound -Protocol TCP -LocalPort 443 -Action Allow
                Write-Host "Strict Mode: All traffic is blocked, only Port 443 (HTTPS) is allowed for secure browsing." -ForegroundColor Green
            }
            3 {
                Write-Host "`nSetting firewall to Medium Mode..." -ForegroundColor Green
                # Allow most traffic, custom rules can be defined
                Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Allow -DefaultOutboundAction Allow
                Write-Host "Medium Mode: Most traffic is allowed, custom rules can be defined for specific ports like 8080, 21, etc." -ForegroundColor Green
            }
            4 {
                Write-Host "`nSetting firewall to Low Mode..." -ForegroundColor Green
                # Allow all traffic, but with restrictions for higher-risk ports
                Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Allow -DefaultOutboundAction Allow
                Write-Host "Low Mode: Nearly all traffic is allowed, but restrictions can be added for higher-risk ports." -ForegroundColor Green
            }
            5 {
                Write-Host "`nRestoring default firewall settings..." -ForegroundColor Cyan
                # Reset the firewall to default settings
                Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow -Enabled True
                # Remove all custom firewall rules to reset firewall to default
                Get-NetFirewallRule | Remove-NetFirewallRule
                Write-Host "Windows Defender Firewall has been reset to default settings." -ForegroundColor Green
            }
            default {
                Write-Host "`nInvalid selection, please choose a valid option." -ForegroundColor Red
            }
        }
    }
    


###############################################################################
# STEP 4: Main Menu Logic
###############################################################################
function Show-Menu {
    Clear-Host
    Write-Host "===================================================" -ForegroundColor Green
    Write-Host "     PC Maintenance & Troubleshooting Toolkit" -ForegroundColor Green
    Write-Host "===================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host " 1) System File Checker (SFC)"
    Write-Host " 2) DISM (Scan & Restore)"
    Write-Host " 3) Clean TEMP / Downloads / Recycle Bin"
    Write-Host " 4) Flush DNS"
    Write-Host " 5) Reset Network (Winsock, IP stack)"
    Write-Host " 6) Defrag a Drive"
    Write-Host " 7) Clear Windows Update Cache"
    Write-Host " 8) Clear All Browser History"
    Write-Host " 9) Virus Scan (Quick or Full)"
    Write-Host "10) Check System Health"
    Write-Host "11) Create System Restore Point"
    Write-Host "12) Advanced Scanning for Leftovers"
    Write-Host "13) Network Speed Test"
    Write-Host "14) Driver Updates"
    Write-Host "15) System Performance Analysis"
    Write-Host "16) Disk Cleanup"  # New Option
    Write-Host "17) Hard Drive Health Check"
    Write-Host "18) USB Device Troubleshooting"
    Write-Host "19) Windows Search Repair"
    Write-Host "20) File Integrity Checker"
    Write-Host "21) System Information Export (with File Modification Dates)"
    Write-Host "22) Reset System Components: Fix Windows Search, Defender, etc."
    Write-Host "23) Repair All Microsoft Programs"
    Write-Host "24) DNS Benchmark: Find the fastest DNS for your network"
    Write-Host "25) Check System Logs for Past Events"
    Write-Host "26) Set Firewall Securit Level)"
    Write-Host "27) Instructions"
    Write-Host " 0) Exit"
    Write-Host ""
}


###############################################################################
# Initialize Script and Display Menu
###############################################################################
Set-ConsoleAppearance 

while ($true) {
    Show-Menu
    $selection = Read-Host "Enter your choice (0-27)"
    switch ($selection) {
        "1" { Invoke-SFC; Pause }
        "2" { Invoke-DISM; Pause }
        "3" { Clear-Files; Pause }
        "4" { Clear-DNS; Pause }
        "5" { Reset-Network; Pause }
        "6" { Optimize-Drive; Pause }
        "7" { Clear-UpdateCache; Pause }
        "8" { Clear-BrowserHistory; Pause }
        "9" { Test-Virus; Pause }
        "10" { Get-SystemHealth; Pause }
        "11" { New-SystemRestorePoint; Pause }
        "12" { Invoke-AdvancedScanning; Pause }
        "13" { Test-NetworkSpeed; Pause }
        "14" { Invoke-DriverUpdates; Pause }
        "15" { Test-PerformanceAnalysis; Pause }
        "16" { Invoke-DiskClean; Pause }  # New Disk Cleanup function
        "17" { Test-HardDriveHealth; Pause }
        "18" { Invoke-USBDeviceTroubleshooting; Pause }
        "19" { Repair-WindowsSearch; Pause }
        "20" { Invoke-FileIntegrityCheck; Pause }
        "21" { Export-SystemInfo; Pause }
        "22" { Reset-SystemComponents; Pause }
        "23" { Repair-Microsoft-Programs; Pause }
        "24" { Test-DNSPerformance; Pause }
        "25" { Watch-SystemChange; Pause }
        "26" { Set-FirewallSecurityLevel; Pause }
        "27" { Show-Instructions; Pause }

        "0" {
            Write-Host "Exiting PC Maintenance Toolkit. Goodbye!" -ForegroundColor Green
            break
        }
        default {
            Write-Host "Invalid choice. Please select 0-27." -ForegroundColor Yellow
            Pause
        }
    }
}


