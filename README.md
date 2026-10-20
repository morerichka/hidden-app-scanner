# Hidden App Scanner

A read-only Windows tool with a simple GUI that looks for signs of hidden crypto-miners, spyware and malware masquerading as system processes on **your own** computer. It writes an HTML report that explains *why* each item looks suspicious.

![Hidden App Scanner window](docs/gui.png)

> **Read-only.** The tool never deletes, modifies or uploads anything. The only optional network use is sending file **hashes** (never the files) to VirusTotal, and only if you turn that on.

## Quick start

1. Download the repository: **Code -> Download ZIP**, then extract it.
2. Double-click **`Start-GUI.bat`** and approve the Windows prompt. Administrator rights are needed to see all processes and services.
3. Press **Scan**. A full scan takes 2-5 minutes. The report opens automatically and is saved in the `reports\` folder.

Without the GUI: run `Run-Scan-Console.bat`, or `powershell -ExecutionPolicy Bypass -File .\Scan-HiddenApps.ps1`.

Requires Windows 10/11 and the built-in Windows PowerShell 5.1. Nothing to install.

## What it checks

| Area | Indicators |
|---|---|
| **Masquerading** | system names (`svchost.exe`, `lsass.exe`, ...) outside `System32`; look-alike names (`svch0st`); wrong parent process; `svchost` without `-k`; double extensions; Latin/Cyrillic mixed in a file name |
| **Signatures** | no signature, invalid signature, file changed after signing; signing publisher differs from the vendor in the file properties |
| **Miners** | command lines (`stratum+tcp`, `--donate-level`, ...), names of known miners, mining-pool ports, sustained CPU/GPU load from an unsigned program |
| **Spyware** | keyloggers and monitoring software, remote-access tools (running processes and installed programs), Windows' own log of camera, microphone, screen-capture and location access |
| **Injection (limited)** | unsigned DLLs and DLLs from user-writable folders inside system processes; read+write+execute private memory regions in system processes. This does *not* cover every injection technique |
| **Persistence** | Run keys, Startup folders, scheduled tasks, services (including the DLL behind `svchost`), WMI subscriptions, Winlogon, IFEO, AppInit_DLLs |
| **Payloads** | for autostart entries and tasks the scanner also checks the scripts, DLLs and executables named in the arguments - location, signature, existence and (for scripts) content against [ules/script-rules.json](rules/script-rules.json). A signed interpreter such as `powershell.exe` is never trusted on its own, and Microsoft scheduled tasks are no longer skipped by folder name |
| **Protection & network** | Microsoft Defender detections of the last 30 days, Defender exclusions, disabled protection, `hosts` file, system proxy, hidden local accounts, browser extensions with broad permissions or sideloaded |
| **Reputation (optional)** | SHA256 lookup on VirusTotal - the practical way to catch a file signed with a stolen certificate |

## Startup Manager (optional, changes your system - reversibly)

The scanner itself is read-only. A separate tool, **`Start-StartupManager.bat`** (or the *Startup manager...* button in the main window), lets you switch off programs you do not need at sign-in.

![Startup Manager window](docs/startup-manager.png)

- **Nothing is deleted.** Run-key and Startup-folder entries are only *disabled*, using the same switch as Task Manager > Startup. Scheduled tasks are disabled; services (opt-in) are switched to *Manual*.
- **A restore file is written before every change** to `backups\`. *Restore from backup...* (or `-Restore <file>`) puts everything back exactly as it was.
- **Protected, cannot be selected:** Windows system components and security software (Windows Security, Defender, Bitdefender, Kaspersky, ...).
- **Pre-checked ("Recommended"):** third-party programs - chat clients, launchers, updaters, stale entries.
- **Left unchecked ("Review"):** hardware/driver helpers (ASUS, NVIDIA, Realtek, ...) that may drive hotkeys, audio, touchpad or fans, and Microsoft apps such as OneDrive. You decide.
- Changes apply at the next sign-in. "Also close the programs now" additionally ends running copies (unsaved work is lost).

Console use:

```powershell
.\Manage-Startup.ps1 -List                                  # show everything, nothing changes
.\Manage-Startup.ps1 -DisableRecommended -DryRun            # preview
.\Manage-Startup.ps1 -DisableRecommended -Only 'Adobe|Fing' # only entries matching a regex
.\Manage-Startup.ps1 -Restore .\backups\startup-YYYYMMDD-HHMMSS.json
```

Administrator rights are needed for all-users entries, scheduled tasks and services; without them those rows are shown but locked.

## Reading the report

Every finding has a **class**, a level (high / medium / low) and a list of reasons:

| Class | Meaning |
|---|---|
| **Confirmed threat** | Microsoft Defender detected it, or at least 3 VirusTotal engines flag the file |
| **Unwanted program** | known remote-access, monitoring/stalkerware or mining software - may be intentional, check that you installed it |
| **Suspicious indicator** | a sign worth a look (unsigned, odd location, odd behavior) - **not proof** |

Many legitimate programs are unsigned or live in `AppData`. Look at whether you recognize the program, and when in doubt check the file with the SHA256 link on the card.

### Scan coverage

Every report ends its findings with a **Scan coverage** table. Each step is marked **Checked**, **Limited** (done, but some data could not be read - for example without administrator rights, or protected processes), **Skipped** (option off), **Unavailable** or **Error**, with notes. A report with few findings and many *Limited* rows means *less was verified*, not *the computer is clean*.

What the tool **is not**: an antivirus. It has no real-time protection, no file-content scanning engine, no quarantine and no prevention. It explains *what is running, where it persisted and why it looks suspicious*, and complements Microsoft Defender or your antivirus. See [docs/ROADMAP.md](docs/ROADMAP.md).

What the tool **cannot see**: kernel-level rootkits and malicious drivers (use an offline scan such as Microsoft Defender Offline), surveillance on your router or phone, and compromised cloud accounts.

## VirusTotal check (optional)

1. Get a free key: [virustotal.com](https://www.virustotal.com) -> your profile -> **API key**.
2. In the GUI tick "Check files on VirusTotal" and paste the key. The key only lives in memory for that run.
3. In the console: `$env:VT_API_KEY='your-key'; .\Scan-HiddenApps.ps1 -UseVirusTotal -VtMax 60`.

**Only SHA256 hashes** are sent, never files. Only *existing* VirusTotal reports are read: a file VirusTotal has never seen is **not analyzed** (the report lists such files as unknown). The free public API allows 4 requests per minute (60 files take about 16 minutes) and, per VirusTotal's terms, is for personal, non-commercial use.

## Console parameters

| Parameter | Effect |
|---|---|
| `-SampleSeconds N` | length of the CPU/GPU sampling window (default 8) |
| `-SkipModules` | skip the loaded-DLL check (faster) |
| `-DeepFiles` | search user folders for miner files by **name and config contents** (slow). It is a targeted miner hunt, not a scan of every file; found files are hashed |
| `-UseVirusTotal` `-VtMax N` | look up file hashes on VirusTotal |
| `-NoElevate` / `-NoOpen` | do not ask for administrator rights / do not open the report |

## Rules and updates

Script-content heuristics live in [`rules/script-rules.json`](rules/script-rules.json) (version, date, regex, points, reason per rule), separate from the code, so they can be reviewed and updated on their own. The report lists the loaded rules version in the *Scan coverage* table. Rule files are plain data; they are not signed or auto-updated yet (see the roadmap).

## Tests

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\Run-Tests.ps1            # unit + end-to-end smoke test
powershell -NoProfile -ExecutionPolicy Bypass -File tests\Run-Tests.ps1 -SkipSmoke   # unit tests only```n
The suite covers path comparison, masquerading, payload analysis, Microsoft-task handling, finding classes, the coverage journal and repository hygiene (syntax, English-only). It also runs on Windows in GitHub Actions. A growing set of legitimate programs guards against false alarms.

## False positives, honestly

- Antivirus products may get suspicious: the script enumerates processes, services and modules, which malware does too. The source is open - read it.
- Microsoft Store apps are not Authenticode-signed, and some driver components carry Microsoft's driver (WHQL) certificate. These cases are handled, but rare exceptions are possible.
- Developer tools (Git, Node, game launchers) may occasionally show up at a low level.

Use only on computers you own or are authorized to audit.

## License

MIT - see [LICENSE](LICENSE).
