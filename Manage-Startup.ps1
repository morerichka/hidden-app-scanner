<#
  Manage-Startup.ps1 - review autostart entries and (reversibly) disable the ones you do not need.

  SAFE BY DESIGN
   * Entries are only DISABLED, never deleted. For Run keys and Startup folders this uses the same
     StartupApproved switch as the Startup tab in Task Manager; scheduled tasks are disabled, services
     are switched to Manual.
   * Before any change a restore file is written to .\backups\ - use -Restore (or the Restore button).
   * Windows system components and security software are protected and cannot be selected.
  Changes take effect at the next sign-in / restart (use -StopRunning to also close running copies now).
#>
[CmdletBinding()]
param(
  [switch]$List,                 # print the table and exit
  [switch]$DisableRecommended,   # disable everything marked "Recommended" (no GUI)
  [string]$Restore = '',         # path to a backup file to restore
  [string]$Only = '',            # with -DisableRecommended: only entries whose name matches this regex
  [switch]$IncludeServices,      # also consider third-party services set to start automatically
  [switch]$StopRunning,          # also close running copies of the disabled programs
  [switch]$DryRun,               # show what would change, change nothing
  [switch]$NoElevate,
  [switch]$AutoRun,              # self-test: show the window with data, take a screenshot, close
  [string]$ShotPath = ''
)
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$backupDir = Join-Path $here 'backups'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$needsWrite = ($DisableRecommended -or $Restore -or -not ($List))
if (-not $isAdmin -and -not $NoElevate -and $needsWrite -and -not $AutoRun) {
  $a = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
  if ($IncludeServices) { $a += ' -IncludeServices' }
  if ($StopRunning) { $a += ' -StopRunning' }
  if ($DryRun) { $a += ' -DryRun' }
  if ($Only) { $a += " -Only '$Only'" }
  if ($DisableRecommended) { $a += ' -DisableRecommended' }
  if ($Restore) { $a += " -Restore `"$Restore`"" }
  try {
    $ws = if ($DisableRecommended -or $Restore) { 'Normal' } else { 'Hidden' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a -WindowStyle $ws -ErrorAction Stop
    exit
  } catch { Write-Host 'UAC declined - continuing without administrator rights (machine-wide items will be locked).' -ForegroundColor Yellow }
}

$winDir = $env:SystemRoot.ToLower()

# ---------------------------------------------------------------- trust / classification
$FileCache = @{}
function Normalize-Path($p) {
  if ([string]::IsNullOrWhiteSpace($p)) { return $p }
  $p = $p -replace '^\\\\\?\\', '' -replace '^\\\?\?\\', ''
  return $p
}
function Get-FileTrust($path) {
  $path = Normalize-Path $path
  if ([string]::IsNullOrWhiteSpace($path)) { return $null }
  $key = $path.ToLower()
  if ($FileCache.ContainsKey($key)) { return $FileCache[$key] }
  $o = [pscustomobject]@{ Path = $path; Exists = $false; Status = ''; Signer = ''; IsMs = $false; Company = '' }
  if (Test-Path -LiteralPath $path -PathType Leaf) {
    $o.Exists = $true
    $sig = Get-AuthenticodeSignature -LiteralPath $path
    $o.Status = [string]$sig.Status
    if ($sig.SignerCertificate) {
      $s = $sig.SignerCertificate.Subject
      if ($s -match 'CN="([^"]+)"') { $o.Signer = $Matches[1] } elseif ($s -match 'CN=([^,]+)') { $o.Signer = $Matches[1] } else { $o.Signer = $s }
    }
    $o.IsMs = ($o.Status -eq 'Valid' -and $o.Signer -match '^Microsoft (Windows|Corporation|Windows Publisher)$')
    $o.Company = (Get-Item -LiteralPath $path -Force).VersionInfo.CompanyName
  }
  $FileCache[$key] = $o
  return $o
}
function Get-ExePathFromCommand($cmd) {
  if ([string]::IsNullOrWhiteSpace($cmd)) { return $null }
  $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
  if ($c -match '^"([^"]+)"') { $p = $Matches[1] }
  elseif ($c -match '^([A-Za-z]:\\.*?\.(exe|dll|bat|cmd|ps1|vbs|js|lnk))(\s|$)') { $p = $Matches[1] }
  elseif ($c -match '^(\S+)') { $p = $Matches[1] }
  else { return $null }
  if ($p -match '^[A-Za-z]:\\') { return $p }
  foreach ($base in @("$env:SystemRoot\System32", $env:SystemRoot)) {
    $cand = Join-Path $base $p
    if (Test-Path -LiteralPath $cand -PathType Leaf) { return $cand }
  }
  return $null
}

$SecurityRx = 'bitdefender|defender|kaspersky|eset\b|norton|mcafee|avast|\bavg\b|malwarebytes|sophos|trend micro|windows security|securityhealth|crowdstrike|sentinel'
$HardwareRx = 'realtek|synaptics|\belan\b|nvidia|advanced micro devices|\bamd\b|intel|conexant|waves|dolby|asus|armoury|logitech|razer|corsair|wacom|alps|goodix|mediatek|qualcomm|bluetooth|touchpad|hp inc|hewlett|dell|lenovo|acer|msi\b|steelseries|elgato'

function Get-Category($name, $exePath, $command) {
  # returns @{Cat=...; Why=...}  Cat: Protected | Review | Recommended
  $trust = if ($exePath) { Get-FileTrust $exePath } else { $null }
  $signer = if ($trust) { $trust.Signer } else { '' }
  $hay = "$name $exePath $signer $command"
  if ($hay -match $SecurityRx) { return @{ Cat = 'Protected'; Why = 'security software - kept enabled' } }
  if ($trust -and $trust.IsMs -and $exePath.ToLower().StartsWith($winDir)) { return @{ Cat = 'Protected'; Why = 'Windows system component - kept enabled' } }
  if ($trust -and $trust.IsMs) { return @{ Cat = 'Review'; Why = "Microsoft app ($signer) - optional, not a core system part" } }
  if ($hay -match $HardwareRx) { return @{ Cat = 'Review'; Why = 'hardware / driver helper - may control hotkeys, audio, touchpad, fans or graphics' } }
  if (-not $trust -or -not $trust.Exists) { return @{ Cat = 'Recommended'; Why = 'target file not found (stale entry) - safe to disable' } }
  if ($trust.Status -eq 'Valid') { return @{ Cat = 'Recommended'; Why = "third-party program, signed by $signer" } }
  return @{ Cat = 'Recommended'; Why = 'third-party program without a valid signature' }
}

# ---------------------------------------------------------------- StartupApproved helpers
function Test-ApprovedDisabled($approvedPath, $valueName) {
  $v = (Get-ItemProperty -Path $approvedPath -ErrorAction SilentlyContinue).$valueName
  if ($v -is [byte[]] -and $v.Length -gt 0) { return (($v[0] -band 1) -eq 1) }
  return $false
}
function Get-ApprovedBytes($approvedPath, $valueName) {
  $v = (Get-ItemProperty -Path $approvedPath -ErrorAction SilentlyContinue).$valueName
  if ($v -is [byte[]]) { return $v }
  return $null
}
function Set-ApprovedDisabled($approvedPath, $valueName) {
  if (-not (Test-Path $approvedPath)) { New-Item -Path $approvedPath -Force | Out-Null }
  $b = New-Object byte[] 12
  $b[0] = 3
  [BitConverter]::GetBytes([DateTime]::UtcNow.ToFileTimeUtc()).CopyTo($b, 4)
  Set-ItemProperty -Path $approvedPath -Name $valueName -Value $b -Type Binary -ErrorAction Stop
}

# ---------------------------------------------------------------- enumeration
function Get-StartupItems {
  $items = New-Object System.Collections.Generic.List[object]
  function New-Item2($kind, $where, $name, $command, $enabled, $adminNeeded, $extra) {
    $exe = Get-ExePathFromCommand $command
    $cat = Get-Category $name $exe $command
    $o = [pscustomobject]@{
      Kind = $kind; Where = $where; Name = $name; Command = $command; Exe = $exe
      Signer = $(if ($exe) { (Get-FileTrust $exe).Signer } else { '' })
      Enabled = $enabled; Category = $cat.Cat; Why = $cat.Why; Locked = ($cat.Cat -eq 'Protected')
      ApprovedPath = ''; ApprovedName = ''; TaskPath = ''; TaskName = ''; ServiceName = ''; Delayed = $false
    }
    if ($adminNeeded -and -not $isAdmin) { $o.Locked = $true; $o.Why = 'needs administrator rights - ' + $o.Why }
    if (-not $enabled) { $o.Locked = $true; $o.Category = 'Disabled'; $o.Why = 'already disabled' }
    foreach ($k in $extra.Keys) { $o.$k = $extra[$k] }
    $items.Add($o)
  }

  $runDefs = @(
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; Approved = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'; Where = 'Run (current user)'; Admin = $false },
    @{ Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'; Approved = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'; Where = 'Run (all users)'; Admin = $true },
    @{ Path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Approved = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'; Where = 'Run (all users, 32-bit)'; Admin = $true }
  )
  foreach ($d in $runDefs) {
    $props = Get-ItemProperty -Path $d.Path
    if (-not $props) { continue }
    foreach ($pr in $props.PSObject.Properties) {
      if ($pr.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
      $dis = Test-ApprovedDisabled $d.Approved $pr.Name
      New-Item2 'Run' $d.Where $pr.Name ([string]$pr.Value) (-not $dis) $d.Admin @{ ApprovedPath = $d.Approved; ApprovedName = $pr.Name }
    }
  }

  $wsh = New-Object -ComObject WScript.Shell
  $folders = @(
    @{ Dir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"; Approved = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'; Where = 'Startup folder (current user)'; Admin = $false },
    @{ Dir = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"; Approved = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'; Where = 'Startup folder (all users)'; Admin = $true }
  )
  foreach ($f in $folders) {
    foreach ($file in @(Get-ChildItem -LiteralPath $f.Dir -File -Force)) {
      if ($file.Name -ieq 'desktop.ini') { continue }
      $cmd = if ($file.Extension -ieq '.lnk') { $l = $wsh.CreateShortcut($file.FullName); "`"$($l.TargetPath)`" $($l.Arguments)".Trim() } else { "`"$($file.FullName)`"" }
      $dis = Test-ApprovedDisabled $f.Approved $file.Name
      New-Item2 'StartupFolder' $f.Where $file.Name $cmd (-not $dis) $f.Admin @{ ApprovedPath = $f.Approved; ApprovedName = $file.Name }
    }
  }

  foreach ($t in @(Get-ScheduledTask)) {
    if ($t.TaskPath -like '\Microsoft\*') { continue }
    $trig = @($t.Triggers | Where-Object { $_.CimClass.CimClassName -in 'MSFT_TaskLogonTrigger', 'MSFT_TaskBootTrigger' })
    if ($trig.Count -eq 0) { continue }
    $act = @($t.Actions | Where-Object { $_.Execute })[0]
    if (-not $act) { continue }
    $cmd = ("$($act.Execute) $($act.Arguments)").Trim()
    New-Item2 'Task' "Scheduled task (at logon/boot)" "$($t.TaskPath)$($t.TaskName)" $cmd ($t.State -ne 'Disabled') $true @{ TaskPath = $t.TaskPath; TaskName = $t.TaskName }
  }

  if ($IncludeServices) {
    foreach ($s in @(Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' })) {
      $exe = Get-ExePathFromCommand $s.PathName
      if (-not $exe) { continue }
      $tr = Get-FileTrust $exe
      if ($tr -and $tr.IsMs) { continue }
      if ($exe.ToLower().StartsWith($winDir)) { continue }
      $delayed = ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)").DelayedAutostart -eq 1)
      New-Item2 'Service' "Service (starts automatically)" "$($s.DisplayName) [$($s.Name)]" $s.PathName $true $true @{ ServiceName = $s.Name; Delayed = $delayed }
    }
  }
  return $items
}

# ---------------------------------------------------------------- apply / restore
function Invoke-Disable($item) {
  switch ($item.Kind) {
    { $_ -in 'Run', 'StartupFolder' } {
      $prev = Get-ApprovedBytes $item.ApprovedPath $item.ApprovedName
      if (-not $DryRun) { Set-ApprovedDisabled $item.ApprovedPath $item.ApprovedName }
      return @{ Kind = 'Approved'; Path = $item.ApprovedPath; Name = $item.ApprovedName; Prev = $(if ($prev) { [Convert]::ToBase64String($prev) } else { $null }); Label = $item.Name }
    }
    'Task' {
      if (-not $DryRun) { Disable-ScheduledTask -TaskPath $item.TaskPath -TaskName $item.TaskName -ErrorAction Stop | Out-Null }
      return @{ Kind = 'Task'; TaskPath = $item.TaskPath; TaskName = $item.TaskName; Label = $item.Name }
    }
    'Service' {
      if (-not $DryRun) { & sc.exe config $item.ServiceName start= demand | Out-Null; if ($LASTEXITCODE -ne 0) { throw "sc config failed ($LASTEXITCODE)" } }
      return @{ Kind = 'Service'; ServiceName = $item.ServiceName; Delayed = $item.Delayed; Label = $item.Name }
    }
  }
}
function Stop-ItemProcesses($item) {
  if (-not $item.Exe) { return }
  foreach ($p in @(Get-Process | Where-Object { try { $_.Path -ieq $item.Exe } catch { $false } })) { try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch { } }
  if ($item.Kind -eq 'Service' -and -not $DryRun) { Stop-Service -Name $item.ServiceName -Force -ErrorAction SilentlyContinue }
}
function Invoke-DisableMany($selected) {
  $log = New-Object System.Collections.Generic.List[object]
  $done = New-Object System.Collections.Generic.List[object]
  $failed = New-Object System.Collections.Generic.List[string]
  foreach ($it in $selected) {
    try {
      $b = Invoke-Disable $it
      $done.Add($b)
      if ($StopRunning -and -not $DryRun) { Stop-ItemProcesses $it }
    } catch { $failed.Add("$($it.Name): $($_.Exception.Message)") }
  }
  $file = $null
  if (-not $DryRun -and $done.Count -gt 0) {
    if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
    $file = Join-Path $backupDir ("startup-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    try {
      $payload = [ordered]@{ created = (Get-Date).ToString('s'); computer = $env:COMPUTERNAME; items = $done.ToArray() }
      $payload | ConvertTo-Json -Depth 6 | Set-Content -Path $file -Encoding UTF8 -ErrorAction Stop
      if (-not (Test-Path $file)) { throw 'file was not created' }
    } catch {
      $failed.Add("RESTORE FILE COULD NOT BE WRITTEN ($($_.Exception.Message)). Changes were made - re-enable entries from Task Manager > Startup if needed.")
      $file = $null
    }
  }
  return @{ Done = $done.Count; Failed = @($failed); File = $file }
}
function Invoke-RestoreFile($path) {
  $bad = New-Object System.Collections.Generic.List[string]
  if (-not $path -or -not (Test-Path -LiteralPath $path)) { $bad.Add("restore file not found: $path"); return @{ Restored = 0; Failed = @($bad) } }
  try { $j = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop } catch { $bad.Add("restore file is not valid JSON: $($_.Exception.Message)"); return @{ Restored = 0; Failed = @($bad) } }
  if (-not $j -or -not $j.items) { $bad.Add("restore file has no items: $path"); return @{ Restored = 0; Failed = @($bad) } }
  $ok = 0
  foreach ($e in @($j.items)) {
    try {
      switch ($e.Kind) {
        'Approved' {
          if ($null -eq $e.Prev) { Remove-ItemProperty -Path $e.Path -Name $e.Name -ErrorAction Stop }
          else { Set-ItemProperty -Path $e.Path -Name $e.Name -Value ([Convert]::FromBase64String($e.Prev)) -Type Binary -ErrorAction Stop }
        }
        'Task' { Enable-ScheduledTask -TaskPath $e.TaskPath -TaskName $e.TaskName -ErrorAction Stop | Out-Null }
        'Service' { $mode = if ($e.Delayed) { 'delayed-auto' } else { 'auto' }; & sc.exe config $e.ServiceName start= $mode | Out-Null; if ($LASTEXITCODE -ne 0) { throw "sc config failed ($LASTEXITCODE)" } }
      }
      $ok++
    } catch { $bad.Add("$($e.Label): $($_.Exception.Message)") }
  }
  return @{ Restored = $ok; Failed = @($bad) }
}

# ---------------------------------------------------------------- CLI modes
if ($Restore) {
  $r = Invoke-RestoreFile $Restore
  Write-Host "Restored $($r.Restored) item(s) from $Restore" -ForegroundColor Green
  $r.Failed | ForEach-Object { Write-Host "  failed: $_" -ForegroundColor Yellow }
  if (-not $NoElevate) { Read-Host 'Press Enter to close' | Out-Null }
  exit
}
if ($List -or $DisableRecommended) {
  $items = Get-StartupItems
  if ($List) {
    $items | Sort-Object Category, Name | Format-Table @{n = 'Category'; e = { $_.Category }}, @{n = 'On'; e = { if ($_.Enabled) { 'yes' } else { 'no' } }}, Name, @{n = 'Publisher'; e = { $_.Signer }}, Where -AutoSize -Wrap | Out-String -Width 220 | Write-Host
    exit
  }
  $sel = @($items | Where-Object { $_.Category -eq 'Recommended' -and $_.Enabled -and -not $_.Locked -and (-not $Only -or $_.Name -match $Only) })
  Write-Host "$($sel.Count) item(s) recommended to disable$(if ($DryRun) { ' (dry run - nothing will change)' }):" -ForegroundColor Cyan
  $sel | ForEach-Object { Write-Host "  - $($_.Name)  [$($_.Where)]" }
  if ($sel.Count -gt 0) {
    $res = Invoke-DisableMany $sel
    Write-Host "$(if ($DryRun) { 'Would disable' } else { 'Disabled' }): $($res.Done)" -ForegroundColor Green
    if ($res.File) { Write-Host "Restore file: $($res.File)" -ForegroundColor Cyan; Write-Host "To undo: .\Manage-Startup.ps1 -Restore `"$($res.File)`"" }
    $res.Failed | ForEach-Object { Write-Host "  failed: $_" -ForegroundColor Yellow }
  }
  if (-not $NoElevate -and -not $DryRun) { Read-Host 'Press Enter to close' | Out-Null }
  exit
}

# ---------------------------------------------------------------- GUI
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Startup Manager'
$form.Size = New-Object System.Drawing.Size(1040, 680)
$form.MinimumSize = New-Object System.Drawing.Size(860, 520)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9.5)

function New-Ctl($type, $x, $y, $w, $h, $text) {
  $c = New-Object "System.Windows.Forms.$type"
  $c.Location = New-Object System.Drawing.Point($x, $y); $c.Size = New-Object System.Drawing.Size($w, $h)
  if ($null -ne $text) { $c.Text = $text }
  return $c
}
$lblTitle = New-Ctl Label 16 10 900 28 'Startup Manager - turn off programs you do not need at sign-in'
$lblTitle.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 14)
$lblInfo = New-Ctl Label 16 42 1000 40 'Nothing is deleted: entries are only disabled (the same switch as Task Manager > Startup), and a restore file is saved before every change. Windows components and security software are protected. Changes apply at the next sign-in.'
$lblInfo.Anchor = 'Top,Left,Right'
$cbServices = New-Ctl CheckBox 16 86 330 22 'Also list third-party services (advanced)'
$cbStop = New-Ctl CheckBox 360 86 330 22 'Also close the programs now (unsaved work is lost)'
$lblAdmin = New-Ctl Label 700 88 320 22 $(if ($isAdmin) { 'Administrator: yes' } else { 'Administrator: no - machine-wide items are locked' })
$lblAdmin.ForeColor = $(if ($isAdmin) { [System.Drawing.Color]::FromArgb(7, 148, 85) } else { [System.Drawing.Color]::FromArgb(220, 104, 3) })
$lblAdmin.Anchor = 'Top,Right'

$lv = New-Ctl ListView 16 116 1000 420 $null
$lv.View = 'Details'; $lv.CheckBoxes = $true; $lv.FullRowSelect = $true; $lv.GridLines = $true; $lv.HideSelection = $false
$lv.Anchor = 'Top,Bottom,Left,Right'
[void]$lv.Columns.Add('Name', 230)
[void]$lv.Columns.Add('Type', 150)
[void]$lv.Columns.Add('Publisher', 160)
[void]$lv.Columns.Add('Why', 300)
[void]$lv.Columns.Add('Command', 420)
$gRec = New-Object System.Windows.Forms.ListViewGroup; $gRec.Header = 'Recommended to disable'
$gRev = New-Object System.Windows.Forms.ListViewGroup; $gRev.Header = 'Review - hardware helpers and Microsoft apps (not selected)'
$gPro = New-Object System.Windows.Forms.ListViewGroup; $gPro.Header = 'Protected - kept enabled'
$gDis = New-Object System.Windows.Forms.ListViewGroup; $gDis.Header = 'Already disabled'
[void]$lv.Groups.AddRange(@($gRec, $gRev, $gPro, $gDis))

$btnApply = New-Ctl Button 16 548 190 36 'Disable checked'
$btnApply.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 10)
$btnRestore = New-Ctl Button 214 548 190 36 'Restore from backup...'
$btnRefresh = New-Ctl Button 412 548 110 36 'Refresh'
$btnRec = New-Ctl Button 530 548 170 36 'Check recommended'
$btnNone = New-Ctl Button 708 548 110 36 'Uncheck all'
foreach ($b in @($btnApply, $btnRestore, $btnRefresh, $btnRec, $btnNone)) { $b.Anchor = 'Bottom,Left' }
$status = New-Ctl Label 16 596 1000 22 'Loading...'
$status.Anchor = 'Bottom,Left,Right'
foreach ($c in @($lblTitle, $lblInfo, $cbServices, $cbStop, $lblAdmin, $lv, $btnApply, $btnRestore, $btnRefresh, $btnRec, $btnNone, $status)) { $form.Controls.Add($c) }

$script:loading = $false
$script:items = @()
function Update-Status {
  $n = @($lv.CheckedItems).Count
  $status.Text = "$($script:items.Count) autostart entries found | $n checked to disable"
}
function Load-List {
  $script:loading = $true
  $form.Cursor = 'WaitCursor'; $status.Text = 'Reading autostart entries and checking signatures...'; $form.Refresh()
  $script:IncludeServicesVar = $cbServices.Checked
  Set-Variable -Name IncludeServices -Value ([switch]$cbServices.Checked) -Scope Script
  $lv.Items.Clear()
  $script:items = @(Get-StartupItems)
  foreach ($it in ($script:items | Sort-Object Name)) {
    $row = New-Object System.Windows.Forms.ListViewItem($it.Name)
    [void]$row.SubItems.Add($it.Where); [void]$row.SubItems.Add($it.Signer); [void]$row.SubItems.Add($it.Why); [void]$row.SubItems.Add($it.Command)
    $row.Tag = $it
    $row.Group = switch ($it.Category) { 'Recommended' { $gRec } 'Review' { $gRev } 'Disabled' { $gDis } default { $gPro } }
    if ($it.Locked) { $row.ForeColor = [System.Drawing.Color]::Gray }
    [void]$lv.Items.Add($row)
  }
  $script:loading = $false
  $form.Cursor = 'Default'
  Update-Status
}
function Set-RecommendedChecked($state) {
  $script:loading = $true
  foreach ($row in $lv.Items) { $row.Checked = ($state -and $row.Tag.Category -eq 'Recommended' -and -not $row.Tag.Locked) }
  $script:loading = $false
  Update-Status
}
$lv.Add_ItemCheck({
    param($s, $e)
    if ($script:loading) { return }
    $t = $lv.Items[$e.Index].Tag
    if ($t.Locked -and $e.NewValue -eq 'Checked') { $e.NewValue = $e.CurrentValue }
  })
$lv.Add_ItemChecked({ if (-not $script:loading) { Update-Status } })
$cbServices.Add_CheckedChanged({ Load-List; Set-RecommendedChecked $true })
$btnRefresh.Add_Click({ Load-List; Set-RecommendedChecked $true })
$btnRec.Add_Click({ Set-RecommendedChecked $true })
$btnNone.Add_Click({ Set-RecommendedChecked $false })
$btnApply.Add_Click({
    $sel = @($lv.CheckedItems | ForEach-Object { $_.Tag })
    if ($sel.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show('Nothing is checked.', 'Startup Manager') | Out-Null; return }
    $msg = "Disable $($sel.Count) autostart entr$(if ($sel.Count -eq 1) { 'y' } else { 'ies' })?`n`nNothing is deleted. A restore file will be saved in:`n$backupDir"
    if ([System.Windows.Forms.MessageBox]::Show($msg, 'Confirm', 'YesNo', 'Question') -ne 'Yes') { return }
    Set-Variable -Name StopRunning -Value ([switch]$cbStop.Checked) -Scope Script
    $form.Cursor = 'WaitCursor'
    $res = Invoke-DisableMany $sel
    $form.Cursor = 'Default'
    $text = "Disabled: $($res.Done)."
    if ($res.File) { $text += "`nRestore file:`n$($res.File)" }
    if ($res.Failed.Count -gt 0) { $text += "`n`nCould not change:`n" + ($res.Failed -join "`n") }
    [System.Windows.Forms.MessageBox]::Show($text, 'Done') | Out-Null
    Load-List; Set-RecommendedChecked $true
  })
$btnRestore.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title = 'Choose a restore file'; $dlg.Filter = 'Restore files (startup-*.json)|startup-*.json|All files|*.*'
    if (Test-Path $backupDir) { $dlg.InitialDirectory = $backupDir }
    if ($dlg.ShowDialog() -ne 'OK') { return }
    $r = Invoke-RestoreFile $dlg.FileName
    $text = "Restored: $($r.Restored)."
    if ($r.Failed.Count -gt 0) { $text += "`n`nCould not restore:`n" + ($r.Failed -join "`n") }
    [System.Windows.Forms.MessageBox]::Show($text, 'Restore') | Out-Null
    Load-List; Set-RecommendedChecked $true
  })
$form.Add_Shown({
    Load-List; Set-RecommendedChecked $true
    if ($AutoRun) {
      if ($ShotPath) {
        $bmp = New-Object System.Drawing.Bitmap($form.Width, $form.Height)
        $form.DrawToBitmap($bmp, (New-Object System.Drawing.Rectangle(0, 0, $form.Width, $form.Height)))
        $bmp.Save($ShotPath, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
      }
      $form.Close()
    }
  })
[void]$form.ShowDialog()
