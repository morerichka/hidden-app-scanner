<#
  Scan-HiddenApps-GUI.ps1 - window wrapper for Scan-HiddenApps.ps1.
  Runs the scanner (read-only), shows its progress and opens the HTML report.
#>
[CmdletBinding()]
param(
  [switch]$NoElevate,
  [switch]$AutoRun,          # for self-test: start the scan immediately, save a window screenshot and close
  [string]$ShotPath = ''
)
$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$scanner = Join-Path $here 'Scan-HiddenApps.ps1'
$reportsDir = Join-Path $here 'reports'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $NoElevate) {
  try {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`"" -ErrorAction Stop
    exit
  } catch { }  # UAC declined - continue without administrator rights
}
if (-not (Test-Path $scanner)) { throw "Not found: $scanner" }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$font = New-Object System.Drawing.Font('Segoe UI', 9.5)
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Hidden App Scanner'
$form.Size = New-Object System.Drawing.Size(860, 660)
$form.MinimumSize = New-Object System.Drawing.Size(760, 560)
$form.StartPosition = 'CenterScreen'
$form.Font = $font

function New-Ctl($type, $x, $y, $w, $h, $text) {
  $c = New-Object "System.Windows.Forms.$type"
  $c.Location = New-Object System.Drawing.Point($x, $y)
  $c.Size = New-Object System.Drawing.Size($w, $h)
  if ($null -ne $text) { $c.Text = $text }
  return $c
}

$lblTitle = New-Ctl Label 16 12 800 28 'Hidden and masquerading program scanner'
$lblTitle.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 14)
$lblInfo = New-Ctl Label 16 44 810 38 'Looks for miners, spyware, programs masquerading as system processes and injected DLLs. Read-only: it deletes nothing and uploads nothing (except file hashes to VirusTotal, if you enable that).'
$lblAdmin = New-Ctl Label 16 84 810 22 $(if ($isAdmin) { 'Administrator rights: yes - the result will be complete.' } else { 'Administrator rights: no - the result will be incomplete. Restart and approve the Windows prompt.' })
$lblAdmin.ForeColor = $(if ($isAdmin) { [System.Drawing.Color]::FromArgb(7, 148, 85) } else { [System.Drawing.Color]::FromArgb(220, 104, 3) })

$grp = New-Ctl GroupBox 16 112 810 128 'Options'
$cbModules = New-Ctl CheckBox 14 24 380 22 'Look for injected DLLs and memory without a file (+1-2 min)'
$cbModules.Checked = $true
$cbDeep = New-Ctl CheckBox 14 50 380 22 'Search for miner files by name (very slow)'
$lblSample = New-Ctl Label 14 80 220 22 'CPU/GPU sampling, seconds:'
$nudSample = New-Ctl NumericUpDown 236 77 60 24 $null
$nudSample.Minimum = 3; $nudSample.Maximum = 60; $nudSample.Value = 8
$cbVt = New-Ctl CheckBox 420 24 380 22 'Check files on VirusTotal (key required)'
$lblKey = New-Ctl Label 420 52 70 22 'API key:'
$txtKey = New-Ctl TextBox 492 49 300 24 $null
$txtKey.UseSystemPasswordChar = $true
$txtKey.Enabled = $false
$lblMax = New-Ctl Label 420 82 238 22 'Max files (~16 s each):'
$nudMax = New-Ctl NumericUpDown 660 79 60 24 $null
$nudMax.Minimum = 5; $nudMax.Maximum = 300; $nudMax.Value = 40; $nudMax.Enabled = $false
$cbVt.Add_CheckedChanged({ $txtKey.Enabled = $cbVt.Checked; $nudMax.Enabled = $cbVt.Checked })
$grp.Controls.AddRange(@($cbModules, $cbDeep, $lblSample, $nudSample, $cbVt, $lblKey, $txtKey, $lblMax, $nudMax))

$btnStart = New-Ctl Button 16 250 160 34 'Scan'
$btnStart.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 10)
$btnStop = New-Ctl Button 184 250 110 34 'Stop'
$btnStop.Enabled = $false
$btnOpen = New-Ctl Button 302 250 150 34 'Open report'
$btnOpen.Enabled = $false
$btnFolder = New-Ctl Button 460 250 150 34 'Reports folder'

$bar = New-Ctl ProgressBar 16 292 810 8 $null
$bar.Style = 'Continuous'
$log = New-Ctl TextBox 16 308 810 270 $null
$log.Multiline = $true; $log.ReadOnly = $true; $log.ScrollBars = 'Vertical'
$log.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$log.Anchor = 'Top,Bottom,Left,Right'
$status = New-Ctl Label 16 586 810 22 'Ready.'
$status.Anchor = 'Bottom,Left,Right'
foreach ($c in @($lblTitle, $lblInfo, $lblAdmin, $grp, $btnStart, $btnStop, $btnOpen, $btnFolder, $bar, $log, $status)) { $form.Controls.Add($c) }
foreach ($c in @($lblInfo, $lblAdmin, $grp, $bar)) { $c.Anchor = 'Top,Left,Right' }

$script:queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
$script:proc = $null
$script:reportPath = $null
$script:summary = ''
$script:evOut = $null
$script:evErr = $null

function Add-Log($line) {
  $log.AppendText($line + [Environment]::NewLine)
  if ($line -match '^Report:\s*(.+)$') { $script:reportPath = $Matches[1].Trim() }
  if ($line -match '^Done\.') { $script:summary = $line }
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 250
$timer.Add_Tick({
    $line = $null
    while ($script:queue.TryDequeue([ref]$line)) { if ($null -ne $line) { Add-Log $line } }
    if ($script:proc -and $script:proc.HasExited) {
      Start-Sleep -Milliseconds 300
      while ($script:queue.TryDequeue([ref]$line)) { if ($null -ne $line) { Add-Log $line } }
      $timer.Stop()
      foreach ($e in @($script:evOut, $script:evErr)) { if ($e) { Unregister-Event -SourceIdentifier $e.Name -ErrorAction SilentlyContinue } }
      $code = $script:proc.ExitCode
      $script:proc = $null
      $bar.Style = 'Continuous'; $bar.Value = 0
      $btnStart.Enabled = $true; $btnStop.Enabled = $false; $grp.Enabled = $true
      if (-not $script:reportPath) {
        $newest = Get-ChildItem $reportsDir -Filter 'report-*.html' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
        if ($newest) { $script:reportPath = $newest.FullName }
      }
      if ($script:reportPath -and (Test-Path $script:reportPath) -and $code -eq 0) {
        $btnOpen.Enabled = $true
        $status.Text = if ($script:summary) { $script:summary } else { 'Done.' }
        if (-not $AutoRun) { Start-Process $script:reportPath }
      } else {
        $status.Text = "The scan ended without a report (exit code $code). See the log above for details."
      }
      if ($AutoRun) {
        if ($ShotPath) {
          $bmp = New-Object System.Drawing.Bitmap($form.Width, $form.Height)
          $form.DrawToBitmap($bmp, (New-Object System.Drawing.Rectangle(0, 0, $form.Width, $form.Height)))
          $bmp.Save($ShotPath, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
        }
        $form.Close()
      }
    }
  })

function Start-Scan {
  $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$scanner`" -NoElevate -NoOpen -SampleSeconds $([int]$nudSample.Value)"
  if (-not $cbModules.Checked) { $argList += ' -SkipModules' }
  if ($cbDeep.Checked) { $argList += ' -DeepFiles' }
  if ($cbVt.Checked) {
    if (-not $txtKey.Text.Trim()) { [System.Windows.Forms.MessageBox]::Show('Enter your VirusTotal API key or untick the box.', 'Key required') | Out-Null; return }
    $argList += " -UseVirusTotal -VtMax $([int]$nudMax.Value)"
  }
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = 'powershell.exe'
  $psi.Arguments = $argList
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
  $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
  if ($cbVt.Checked) { $psi.EnvironmentVariables['VT_API_KEY'] = $txtKey.Text.Trim() }   # the key lives only in memory for this run
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  $script:reportPath = $null; $script:summary = ''
  $script:evOut = Register-ObjectEvent -InputObject $p -EventName OutputDataReceived -MessageData $script:queue -Action { if ($null -ne $EventArgs.Data) { $Event.MessageData.Enqueue($EventArgs.Data) } }
  $script:evErr = Register-ObjectEvent -InputObject $p -EventName ErrorDataReceived -MessageData $script:queue -Action { if ($null -ne $EventArgs.Data) { $Event.MessageData.Enqueue('! ' + $EventArgs.Data) } }
  $log.Clear()
  [void]$p.Start()
  $p.BeginOutputReadLine(); $p.BeginErrorReadLine()
  $script:proc = $p
  $btnStart.Enabled = $false; $btnStop.Enabled = $true; $btnOpen.Enabled = $false; $grp.Enabled = $false
  $bar.Style = 'Marquee'
  $status.Text = 'Scanning... do not close the window. A full scan takes 2-5 minutes.'
  $timer.Start()
}

$btnStart.Add_Click({ Start-Scan })
$btnStop.Add_Click({
    if ($script:proc -and -not $script:proc.HasExited) {
      & taskkill.exe /PID $script:proc.Id /T /F | Out-Null
      Add-Log '--- stopped by user ---'
    }
  })
$btnOpen.Add_Click({ if ($script:reportPath -and (Test-Path $script:reportPath)) { Start-Process $script:reportPath } })
$btnFolder.Add_Click({ if (-not (Test-Path $reportsDir)) { New-Item -ItemType Directory -Path $reportsDir | Out-Null }; Start-Process $reportsDir })
$form.Add_FormClosing({
    if ($script:proc -and -not $script:proc.HasExited) { & taskkill.exe /PID $script:proc.Id /T /F | Out-Null }
  })
if ($AutoRun) { $form.Add_Shown({ Start-Scan }) }
[void]$form.ShowDialog()
