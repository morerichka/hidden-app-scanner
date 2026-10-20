<#
  Run-Tests.ps1 - self-contained tests for Hidden App Scanner (no Pester needed).
  Usage:  powershell -NoProfile -ExecutionPolicy Bypass -File tests\Run-Tests.ps1 [-SkipSmoke]
  Exit code: 0 = all passed, 1 = something failed.
#>
param([switch]$SkipSmoke)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$scanner = Join-Path $root 'Scan-HiddenApps.ps1'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("hasc-tests-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp | Out-Null

$script:pass = 0; $script:fail = 0
function Test-Case($name, [scriptblock]$body) {
  try {
    $r = & $body
    if ($r -eq $true) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $name  (got: $r)" -ForegroundColor Red }
  } catch { $script:fail++; Write-Host "  FAIL  $name  (exception: $($_.Exception.Message))" -ForegroundColor Red }
}

Write-Host "Loading scanner as a library..." -ForegroundColor Cyan
. $scanner -LibraryOnly -NoElevate
$ErrorActionPreference = 'Continue'

Write-Host "`nPath comparison" -ForegroundColor Cyan
Test-Case 'versioned Defender folder is under the Platform folder' { Test-PathUnder 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.3-0' 'C:\ProgramData\Microsoft\Windows Defender\Platform' }
Test-Case 'same folder counts as under' { Test-PathUnder 'C:\Windows\System32' 'c:\windows\system32\' }
Test-Case 'sibling with the same prefix is NOT under (System32evil)' { -not (Test-PathUnder 'C:\Windows\System32evil' 'C:\Windows\System32') }
Test-Case 'empty input is false' { -not (Test-PathUnder '' 'C:\Windows') }

Write-Host "`nHelpers" -ForegroundColor Cyan
Test-Case 'Levenshtein svch0st vs svchost = 1' { (Get-Lev 'svch0st' 'svchost') -eq 1 }
Test-Case 'private IPv4 ranges' { (Test-PrivateIp '192.168.0.5') -and (Test-PrivateIp '10.1.2.3') -and (Test-PrivateIp '172.20.0.1') }
Test-Case 'public IPv4 is not private' { -not (Test-PrivateIp '8.8.8.8') }
Test-Case 'encoded PowerShell command is detected' { $x = Get-CmdReasons ('powershell.exe -enc ' + ('A' * 60)); @($x | Where-Object { $_.T -match 'encoded' }).Count -ge 1 }
Test-Case 'hidden window is detected' { $x = Get-CmdReasons 'powershell.exe -WindowStyle Hidden -File x.ps1'; @($x | Where-Object { $_.T -match 'hidden window' }).Count -ge 1 }
Test-Case 'miner pool command pattern matches' { '-o pool.example.org:3333 -u wallet1 -p x' -match $MinerRx }

Write-Host "`nMasquerading" -ForegroundColor Cyan
$fakeDir = Join-Path $tmp 'fake'; New-Item -ItemType Directory -Path $fakeDir | Out-Null
[IO.File]::WriteAllBytes((Join-Path $fakeDir 'svchost.exe'), [byte[]](77, 90, 0, 0, 1, 2, 3))
[IO.File]::WriteAllBytes((Join-Path $fakeDir 'svch0st.exe'), [byte[]](77, 90, 0, 0, 1, 2, 3))
[IO.File]::WriteAllBytes((Join-Path $fakeDir 'invoice.pdf.exe'), [byte[]](77, 90, 0, 0, 1, 2, 3))
Test-Case 'svchost.exe outside System32 is flagged as masquerading (>= 8 points)' { $r = Get-PathReasons (Join-Path $fakeDir 'svchost.exe'); (@($r | Where-Object { $_.P -ge 8 -and $_.T -match 'masquerades' }).Count) -ge 1 }
Test-Case 'look-alike name svch0st.exe is flagged' { $r = Get-PathReasons (Join-Path $fakeDir 'svch0st.exe'); (@($r | Where-Object { $_.T -match 'suspiciously like' }).Count) -ge 1 }
Test-Case 'double extension is flagged' { $r = Get-PathReasons (Join-Path $fakeDir 'invoice.pdf.exe'); (@($r | Where-Object { $_.T -match 'double extension' }).Count) -ge 1 }
$sys = "$env:SystemRoot\System32"
foreach ($n in 'svchost.exe', 'cmd.exe', 'notepad.exe', 'conhost.exe', 'lsass.exe', 'services.exe', 'winlogon.exe', 'taskhostw.exe', 'RuntimeBroker.exe', 'dllhost.exe') {
  if (Test-Path "$sys\$n") { Test-Case "legitimate $n stays below the reporting threshold" { (Sum-Reasons (Get-PathReasons "$sys\$n")) -lt 2 } }
}

Write-Host "`nPayload analysis (rules engine, harmless marker)" -ForegroundColor Cyan
$rulesPath = Join-Path $tmp 'rules.json'
@{ version = 'test'; updated = '2026-01-01'; rules = @(@{ id = 'canary'; points = 5; reason = 'contains the test marker'; regex = 'CANARY_PAYLOAD_MARKER' }, @{ id = 'broken'; points = 1; reason = 'bad regex'; regex = '(' }) } | ConvertTo-Json -Depth 5 | Set-Content -Path $rulesPath -Encoding UTF8
Test-Case 'rules loader keeps valid rules and drops invalid regex' { (Import-ScriptRules $rulesPath) -and $script:ScriptRules.Count -eq 1 }
$script1 = Join-Path $tmp 'payload.ps1'; Set-Content -Path $script1 -Value "Write-Output 'hello'`n# CANARY_PAYLOAD_MARKER"
$cmd = "powershell.exe -NoProfile -File `"$script1`""
Test-Case 'script named in the arguments is found as a referenced file' { (Get-ReferencedFiles $cmd 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe') -contains $script1 }
Test-Case 'payload content is analyzed, not only the launcher' { $r = Get-PayloadReasons $cmd ''; (@($r | Where-Object { $_.T -match 'payload.ps1: script contains the test marker' }).Count) -ge 1 }
Test-Case 'a clean script produces no content reasons' { $clean = Join-Path $tmp 'clean.ps1'; Set-Content $clean 'Write-Output ok'; (Get-ScriptContentReasons $clean).Count -eq 0 }
Test-Case 'missing referenced script is reported' { $r = Get-PayloadReasons 'cmd.exe /c C:\no\such\thing.bat' ''; (@($r | Where-Object { $_.T -match 'does not exist' }).Count) -ge 1 }
Test-Case 'real rules file loads, every rule compiles' { (Import-ScriptRules (Join-Path $root 'rules\script-rules.json')) -and $script:ScriptRules.Count -ge 8 }
Test-Case 'real rules: hidden-window rule matches a hidden PowerShell launch' { (Get-ScriptContentReasons (& { $p = Join-Path $tmp 'h.ps1'; Set-Content $p 'powershell -WindowStyle Hidden -File a.ps1'; $p })).Count -ge 1 }

Write-Host "`nMicrosoft tasks are no longer skipped by folder name" -ForegroundColor Cyan
Test-Case 'signed Windows binary without payload files is trivial' { Test-MsTaskTrivial '%windir%\system32\notepad.exe' }
Test-Case 'signed interpreter is NOT trivial' { -not (Test-MsTaskTrivial '%windir%\system32\cmd.exe /c echo hi') }
Test-Case 'signed interpreter running a user script is NOT trivial' { -not (Test-MsTaskTrivial 'powershell.exe -File C:\Users\Public\x.ps1') }
Test-Case 'Windows binary with a payload file argument is NOT trivial' { -not (Test-MsTaskTrivial '%windir%\system32\rundll32.exe C:\Users\Public\x.dll,Run') }
Test-Case 'unknown target is NOT trivial' { -not (Test-MsTaskTrivial 'C:\Users\Public\tool.exe') }

Write-Host "`nFinding classes" -ForegroundColor Cyan
Test-Case 'Defender detection is a confirmed threat' { (Get-FindingClass 'Defender' @('x') 6) -eq 'Confirmed threat' }
Test-Case 'VirusTotal with many detections is a confirmed threat' { (Get-FindingClass 'VirusTotal' @('x') 9) -eq 'Confirmed threat' }
Test-Case 'VirusTotal with 1-2 detections is only an indicator' { (Get-FindingClass 'VirusTotal' @('x') 4) -eq 'Suspicious indicator' }
Test-Case 'remote-access tool is an unwanted program' { (Get-FindingClass 'Process' @('remote-access tool - make sure you installed it yourself') 4) -eq 'Unwanted program' }
Test-Case 'a plain heuristic is a suspicious indicator' { (Get-FindingClass 'Process' @('no digital signature') 2) -eq 'Suspicious indicator' }

Write-Host "`nCoverage journal" -ForegroundColor Cyan
$Coverage.Clear()
Test-Case 'a missing path (existence probe) does not degrade coverage' { Start-Check 'T1'; Get-Item 'C:\no\such\path' -ErrorAction SilentlyContinue | Out-Null; Close-Check; $Coverage[-1].Status -eq 'Checked' }
Test-Case 'a denied read makes the step Limited' { Start-Check 'T2'; Write-Error 'access denied (test)' -Category PermissionDenied -ErrorAction SilentlyContinue; Close-Check; ($Coverage[-1].Status -eq 'Limited') -and ($Coverage[-1].Note -match 'denied') }
Test-Case 'another failure makes the step Limited' { Start-Check 'T3'; Write-Error 'boom (test)' -Category InvalidOperation -ErrorAction SilentlyContinue; Close-Check; ($Coverage[-1].Status -eq 'Limited') -and ($Coverage[-1].Note -match 'failed') }
Test-Case 'explicit notes and statuses are kept' { Start-Check 'T4'; Add-CheckNote 'note A' 'Unavailable'; Close-Check; ($Coverage[-1].Status -eq 'Unavailable') -and ($Coverage[-1].Note -match 'note A') }
Test-Case 'Write-Step opens a new check and closes the previous one' { $n = $Coverage.Count; Write-Step 'Checking alpha...' | Out-Null; Write-Step 'Checking beta...' | Out-Null; Close-Check; ($Coverage.Count -eq $n + 2) -and ($Coverage[-2].Title -eq 'alpha') }

Write-Host "`nRepository hygiene" -ForegroundColor Cyan
Test-Case 'all scripts parse without syntax errors' {
  $bad = 0
  foreach ($f in Get-ChildItem $root -Recurse -Filter *.ps1 -File | Where-Object { $_.FullName -notmatch '\\(reports|backups|\.git)\\' }) {
    $e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$e); if ($e.Count -gt 0) { $bad++; Write-Host "    syntax: $($f.Name): $($e[0].Message)" }
  }
  $bad -eq 0
}
Test-Case 'repository text files are English-only (ASCII)' {
  $bad = 0
  foreach ($f in Get-ChildItem $root -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.md', '.bat', '.json', '.yml', '.txt' -and $_.FullName -notmatch '\\(reports|backups|\.git)\\' }) {
    $n = 0; foreach ($l in [IO.File]::ReadAllLines($f.FullName, [Text.Encoding]::UTF8)) { $n++; if ($l -match '[^\x00-\x7F]') { $bad++; Write-Host "    non-ASCII: $($f.Name):$n"; break } }
  }
  $bad -eq 0
}

if (-not $SkipSmoke) {
  Write-Host "`nEnd-to-end smoke test (about a minute)" -ForegroundColor Cyan
  $outDir = Join-Path $tmp 'out'
  $p = Start-Process powershell.exe -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$scanner`"", '-NoElevate', '-NoOpen', '-SkipModules', '-SampleSeconds', '3', '-OutDir', "`"$outDir`"" -PassThru -Wait -WindowStyle Hidden
  $rep = Get-ChildItem $outDir -Filter 'report-*.html' -ErrorAction SilentlyContinue | Select-Object -First 1
  Test-Case 'scanner exits cleanly and writes a report' { ($p.ExitCode -eq 0) -and $rep }
  if ($rep) {
    $html = [IO.File]::ReadAllText($rep.FullName)
    Test-Case 'report has Findings and Scan coverage sections' { ($html -match '<h2>Findings</h2>') -and ($html -match '<h2>Scan coverage</h2>') }
    Test-Case 'report states what was skipped (modules)' { $html -match 'disabled with -SkipModules' }
    Test-Case 'report is English-only' { $html -notmatch '[\u0400-\u04FF]' }
  }
}

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail -eq 0) { 'Green' } else { 'Red' })
exit $(if ($script:fail -eq 0) { 0 } else { 1 })
