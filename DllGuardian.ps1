# Run as Administrator
# Script to detect and mitigate potential DLL injections, hooks, and listeners
Write-Host "Starting system scan for suspicious activity..." -ForegroundColor Yellow

# Function to check for suspicious DLLs in a process
function Check-ProcessModules {
    param ([System.Diagnostics.Process]$Process)
    
    $knownDlls = @(
        "kernel32.dll", "user32.dll", "ntdll.dll", "advapi32.dll", 
        "gdi32.dll", "shell32.dll", "ole32.dll", "comctl32.dll" # Add more known good DLLs
    )
    
    Write-Host "Scanning process: $($Process.Name) (PID: $($Process.Id))" -ForegroundColor Cyan
    $modules = $Process.Modules
    
    foreach ($module in $modules) {
        $moduleName = $module.ModuleName.ToLower()
        if ($knownDlls -notcontains $moduleName -and $moduleName -notmatch "^(ms|microsoft|windows)") {
            Write-Host "  Suspicious DLL: $moduleName" -ForegroundColor Red
            Write-Host "    Path: $($module.FileName)"
            Write-Host "    Base Address: 0x$($module.BaseAddress.ToString('X'))"
            return $true
        }
    }
    return $false
}

# Step 1: Scan all processes
$processes = Get-Process
$suspiciousPids = @()

foreach ($proc in $processes) {
    try {
        if (Check-ProcessModules -Process $proc) {
            $suspiciousPids += $proc.Id
        }
    } catch {
        Write-Warning "Could not inspect process $($proc.Name) (PID: $($proc.Id)): $($_.Exception.Message)"
    }
}

# Step 2: Browser-specific scan (e.g., Chrome, Firefox)
$browserNames = @("chrome", "firefox", "msedge", "iexplore")
foreach ($browser in $browserNames) {
    $browserProcs = Get-Process -Name $browser -ErrorAction SilentlyContinue
    foreach ($proc in $browserProcs) {
        if (Check-ProcessModules -Process $proc) {
            Write-Host "Potential browser hook detected in $browser (PID: $($proc.Id))" -ForegroundColor Red
            $suspiciousPids += $proc.Id
        }
    }
}

# Step 3: Check for unauthorized network listeners
$listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
foreach ($listener in $listeners) {
    $proc = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
    if ($proc) {
        if ($suspiciousPids -contains $proc.Id -or $proc.Path -notmatch "system32|program files") {
            Write-Host "Suspicious listener detected:" -ForegroundColor Red
            Write-Host "  Process: $($proc.Name) (PID: $($proc.Id))"
            Write-Host "  Local Port: $($listener.LocalPort)"
        }
    }
}

# Step 4: Mitigation (optional - uncomment to enable)
<#
foreach ($pid in $suspiciousPids) {
    try {
        $proc = Get-Process -Id $pid -ErrorAction Stop
        Write-Host "Terminating suspicious process: $($proc.Name) (PID: $pid)" -ForegroundColor Yellow
        Stop-Process -Id $pid -Force -ErrorAction Stop
        Write-Host "Process terminated." -ForegroundColor Green
        # Optionally delete the file (uncomment with caution)
        # Remove-Item -Path $proc.Path -Force -ErrorAction Stop
    } catch {
        Write-Error "Failed to terminate PID $pid: $($_.Exception.Message)"
    }
}
#>

Write-Host "Scan complete. Review output for suspicious activity." -ForegroundColor Green
