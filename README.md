How It Works
Process Scanning: Loops through all running processes and checks their loaded DLLs against a whitelist of known system DLLs. Flags anything unusual.
Browser Focus: Specifically inspects common browser processes for unexpected DLLs, which could indicate hooks or injections.
Network Check: Identifies listening TCP ports and correlates them with suspicious processes.
Mitigation: Optionally terminates suspicious processes (disabled by default—uncomment to enable).
Limitations
PowerShell Scope: PowerShell can’t directly "unhook" APIs or remove injected code from memory without native code or external tools (e.g., Process Explorer, Cuckoo Sandbox).
False Positives: The script might flag legitimate third-party DLLs (e.g., antivirus, VPNs). Expand the knownDlls array to reduce this.
Kernel-Level Threats: Rootkits or kernel-level hooks (e.g., SSDT modifications) are invisible to user-mode PowerShell.
Warez: No reliable way to detect pirated software generically—requires specific signatures or manual checks.
Privileges: Needs admin rights for full access to process memory and network info.
