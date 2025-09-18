# Fileless

It scans PowerShell event logs, performs memory dumps, and searches for suspicious invocations such as `Invoke-*`.  
The tool runs directly from the command line and executes a complete analysis based on the provided parameters.

---

## Features
- Event log scanning:
  - `Windows PowerShell`
  - `Microsoft-Windows-PowerShell/Operational`
- Memory dumping using [WinPmem](https://github.com/Velocidex/WinPmem).
- Pattern matching in both events and memory (`Invoke-*`).

---

## Issues

- Memory dumps can be very large if they have a lot of RAM.
- Event logs may have been cleared or overwritten, reducing visibility.  
- Pattern-based detection may produce false positives.

---