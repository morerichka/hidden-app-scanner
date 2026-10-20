# Roadmap

Hidden App Scanner is a **suspicious-activity scanner that explains what runs on your computer, where it persisted and why it deserves attention**. It complements an antivirus; it is not one. This page says honestly what exists, what is planned, and what is deliberately out of scope.

## Done

- Heuristics: signatures, masquerading, autostart, tasks, services, WMI, DLLs, CPU/GPU load, surveillance indicators.
- Payload analysis for autostart entries and tasks (scripts, DLLs, executables named in the arguments); Microsoft tasks are no longer skipped by folder name.
- Finding classes: *Confirmed threat* / *Unwanted program* / *Suspicious indicator*.
- Microsoft Defender detections of the last 30 days are read and reported as confirmed threats.
- **Scan coverage** table: every step is Checked / Limited / Skipped / Unavailable / Error, with notes, instead of implying a complete result.
- Content rules moved into a data file (`rules/script-rules.json`).
- Tests (`tests/Run-Tests.ps1`) and Windows CI.
- Startup Manager: reversible disabling of autostart entries with a restore file.

## Next (realistic)

1. **Scan a chosen file or folder** (`-ScanPath`): hash, signature, PE sanity (packing / entropy), script rules, archive listing; the report says which engine produced each verdict.
2. **Defender integration**: start a Microsoft Defender custom scan (`Start-MpScan`) for a path and show its result, clearly labeled as Defender's verdict.
3. **Rule updates**: versioned rule packs with a signature check, version and age shown in the report, and rollback to the previous pack.
4. **False-positive corpus**: a larger set of legitimate programs (drivers, launchers, developer tools) run on every change.
5. **Event history**: a local log of scans so changes between two reports can be shown (new autostart entry, new listening port).

## Later, only if there is a clear need

- **Quarantine with restore**: isolate a file after verifying its identity (hash + path), keep a change journal, restore on request.
- **Background agent** (Windows service) with a scan queue and load limits, separated from the UI and talking to it over a protected channel; signed builds.
- **Behavior correlation**: process start -> autostart created -> network connection; mass file modification.

## Deliberately not planned

- **Writing our own antivirus engine.** Content detection, prevention and self-protection need a dedicated team, constant signature research and a quality-assurance pipeline. For file verdicts the project will use Defender (and optionally YARA rules the user supplies) rather than pretend to compete.
- **Kernel minifilter driver / AMSI provider.** A file-operation filter driver that can block writes, or an AMSI provider that inspects script content, is a separate engineering stage (driver signing, stability, performance). It is only worth starting once the items above are solid.
- **VirusTotal as an engine.** The public API only returns existing reports for a hash (unknown files are not analyzed), is limited to 4 requests per minute and is not allowed for commercial products. It stays an optional reputation lookup that the user switches on.
