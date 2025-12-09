# Define the path to the config file in the same directory as the script
$configPath = Join-Path -Path $PSScriptRoot -ChildPath "config.json"

# Path for an error log to capture full exception text (InnerException + stack trace)
$logPath = Join-Path -Path $PSScriptRoot -ChildPath "error.log"

# Helper: log full exception object with timestamp and context
function Write-ExceptionLog {
    param(
        [Parameter(Mandatory=$true)] $ExceptionObject,
        [string] $Context = ""
    )
    try {
        $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $body = @()
        $body += "[$time] Context: $Context"
        $body += ($ExceptionObject | Out-String)
        $body += ("-" * 80)
        $body -join "`r`n" | Out-File -FilePath $logPath -Encoding UTF8 -Append
    } catch {
        # best-effort: if logging fails, swallow to avoid crashing monitor
    }
}

# Helper: configure TLS protocols and ignore certificate errors (for self-signed certs)
function Set-IgnoreSslValidation {
    # Accept multiple TLS versions and allow invalid certificates (use with caution)
    [System.Net.ServicePointManager]::SecurityProtocol = `
        [System.Net.SecurityProtocolType]::Tls12 -bor `
        [System.Net.SecurityProtocolType]::Tls11 -bor `
        [System.Net.SecurityProtocolType]::Tls

    # Explicit callback with proper parameters to avoid issues
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
        param($sender, $cert, $chain, $sslPolicyErrors)
        return $true
    }
}

# --- Logic to SAVE configuration ---
$saveConfig = {
    $configData = @{
        # Capture the Root Path text box [1]
        RootPath     = $txtRoot.Text
        
        # Capture all items in the Monitor ListBox [2]
        MonitorPaths = @($lstMonitor.Items)
        
        # Capture all items in the Web Server ListBox [3]
        WebServers   = @($lstWeb.Items)
    }

    # Convert to JSON and save to file
    $configData | ConvertTo-Json | Set-Content -Path $configPath -Force
}

# --- Logic to LOAD configuration ---
$loadConfig = {
    if (Test-Path $configPath) {
        try {
            $json = Get-Content -Path $configPath -Raw | ConvertFrom-Json
            
            # Restore Root Path
            if ($json.RootPath) { $txtRoot.Text = $json.RootPath }

            # Restore Monitor Paths
            if ($json.MonitorPaths) {
                $lstMonitor.Items.Clear()
                foreach ($path in $json.MonitorPaths) {
                    $lstMonitor.Items.Add($path) | Out-Null
                }
            }

            # Restore Web Servers
            if ($json.WebServers) {
                $lstWeb.Items.Clear()
                foreach ($srv in $json.WebServers) {
                    $lstWeb.Items.Add($srv) | Out-Null
                }
            }
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Error loading config.json: $_")
        }
    }
}
$btnAddWeb_Click = {
    $webserver = $txtWeb.Text.Trim()
    if ($webserver -ne "") {
        $lstWeb.Items.Add($webserver) | Out-Null
        $txtWeb.Clear()
        
        # SAVE CHANGES
        & $saveConfig
    }
}

$btnRmvWeb_Click = {
    if ($lstWeb.SelectedItem) {
        $lstWeb.Items.Remove($lstWeb.SelectedItem)
        
        # SAVE CHANGES
        & $saveConfig
    }
}
$btnAddMon_Click = {
    $monPath = $txtMon.Text.Trim()
    if ($monPath -ne "") {
        $lstMonitor.Items.Add($monPath) | Out-Null
        $txtMon.Clear()
        
        # SAVE CHANGES
        & $saveConfig
    }
}

$btnRmvMon_Click = {
    if ($lstMonitor.SelectedItem) {
        $lstMonitor.Items.Remove($lstMonitor.SelectedItem)
        
        # SAVE CHANGES
        & $saveConfig
    }
}

$btnHistory_Click = {
    # --- 1. SETUP UI & LOGIC ---
    
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Security Protocols - ensure TLS and ignore cert errors for scanning
    Set-IgnoreSslValidation

    # Form Setup
    $histForm = New-Object System.Windows.Forms.Form
    $histForm.Text = "History / File Scanner"
    $histForm.Size = New-Object System.Drawing.Size(750, 500)
    $histForm.StartPosition = "CenterParent"

    # Controls
    $lblDate = New-Object System.Windows.Forms.Label
    $lblDate.Text = "Files Created On:"; $lblDate.Location = "10, 10"; $lblDate.AutoSize = $true
    
    $dtPicker = New-Object System.Windows.Forms.DateTimePicker
    $dtPicker.Location = "120, 7"; $dtPicker.Format = "Short"
    $dtPicker.Value = (Get-Date).Date

    $lblReg = New-Object System.Windows.Forms.Label
    $lblReg.Text = "Filename Regex:"; $lblReg.Location = "10, 40"; $lblReg.AutoSize = $true
    
    $txtReg = New-Object System.Windows.Forms.TextBox
    $txtReg.Location = "120, 37"; $txtReg.Width = 500
    $txtReg.Text = '^(PendingAuctions\.(pdf|xml)|A_\d{8}_\d\.(xml|pdf)|BPD_SPL_\d{8}_\d\.pdf|R_\d{8}_\d\.(xml|pdf)|NCR_\d{8}_\d\.pdf|CPI_\d{8}\.(xml|pdf))$'

    $btnScan = New-Object System.Windows.Forms.Button
    $btnScan.Text = "Scan Files"; $btnScan.Location = "630, 35"
    
    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Location = "10, 80"; $grid.Size = "710, 370"; $grid.Anchor = "Top, Bottom, Left, Right"
    
    # Define Columns Explicitly (Index 0, 1, 2)
    $grid.ColumnCount = 3
    $grid.Columns.Name = "File"; $grid.Columns.Width = 200
    $grid.Columns[2].Name = "Path"; $grid.Columns[2].Width = 150
    $grid.Columns[1].Name = "Status"; $grid.Columns[1].AutoSizeMode = "Fill"

    # --- 2. SCANNING LOGIC ---
    $btnScan.Add_Click({
        $btnScan.Enabled = $false
        $btnScan.Text = "Scanning..."
        $grid.Rows.Clear()
        
        $regexPattern = $txtReg.Text
        $targetDate = $dtPicker.Value.Date
        $nextDay = $targetDate.AddDays(1)
        
        $monitorPaths = $lstMonitor.Items
        $webServers = $lstWeb.Items
        $rootPath = $txtRoot.Text

        foreach ($subPath in $monitorPaths) {
            $fullPath = Join-Path -Path $rootPath -ChildPath $subPath
            
            if (Test-Path $fullPath) {
                $dirInfo = New-Object System.IO.DirectoryInfo($fullPath)
                
                foreach ($file in $dirInfo.EnumerateFiles()) {
                    
                    [System.Windows.Forms.Application]::DoEvents()

                    if ($file.LastWriteTime -ge $targetDate -and $file.LastWriteTime -lt $nextDay) {
                        if ($file.Name -match $regexPattern) {

                            foreach ($srv in $webServers) {
                                # Add row: Index 0=File, Index 1=Path, Index 2=Status
                                $idx = $grid.Rows.Add($file.Name, $subPath, "Checking $srv...")
                                
                                $grid.FirstDisplayedScrollingRowIndex = $idx
                                $grid.Update()

                                $urlPath = "$subPath/$($file.Name)".Replace('\', '/')
                                $fullUrl = "https://$srv/$urlPath"

                                try {
                                    # Ensure TLS and certificate callback are set
                                    Set-IgnoreSslValidation

                                    $req = [System.Net.WebRequest]::Create($fullUrl)
                                    $req.Method = "HEAD"
                                    $req.Timeout = 2000
                                    $req.UseDefaultCredentials = $true
                                    
                                    $resp = $req.GetResponse()
                                    
                                    # --- FIXED: Explicitly target Column Index [1] (Status) ---
                                    $grid.Rows[$idx].Cells[1].Value = "FOUND ($($resp.StatusCode))"
                                    $grid.Rows[$idx].Cells[1].Style.BackColor = [System.Drawing.Color]::LightGreen
                                    # ----------------------------------------------------------
                                    
                                    $resp.Close()
                                }
                                catch {
                                    # Log full exception (including InnerException and stack)
                                    Write-ExceptionLog -ExceptionObject $_ -Context "History scan: $fullUrl"

                                    $ex = $_.Exception
                                    $msg = $ex.Message
                                    if ($ex.InnerException) { $msg += " - " + $ex.InnerException.Message }

                                    # If it's likely an SSL/authentication issue, retry with GET after ensuring certs are ignored
                                    if ($msg -match "(certificate|ssl|authentication|secure channel|handshake)") {
                                        try {
                                            Set-IgnoreSslValidation
                                            $req2 = [System.Net.WebRequest]::Create($fullUrl)
                                            $req2.Method = "GET"
                                            $req2.Timeout = 2000
                                            $req2.UseDefaultCredentials = $true
                                            $resp2 = $req2.GetResponse()

                                            $grid.Rows[$idx].Cells[1].Value = "FOUND ($($resp2.StatusCode))"
                                            $grid.Rows[$idx].Cells[1].Style.BackColor = [System.Drawing.Color]::LightGreen
                                            $resp2.Close()
                                            continue
                                        }
                                        catch {
                                            # Log the retry exception as well
                                            Write-ExceptionLog -ExceptionObject $_ -Context "History scan (GET fallback): $fullUrl"

                                            $ex2 = $_.Exception
                                            $msg = $ex2.Message
                                            if ($ex2.InnerException) { $msg += " - " + $ex2.InnerException.Message }
                                            if ($msg -match "timed out") { $msg = "Timeout" }

                                            $grid.Rows[$idx].Cells[1].Value = "SSL ERROR (logged)"
                                            $grid.Rows[$idx].Cells[1].Style.BackColor = [System.Drawing.Color]::LightCoral

                                            # Show full error to the user for diagnosis
                                            $fullText = ($_ | Out-String)
                                            [System.Windows.Forms.MessageBox]::Show($fullText, "Request Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                                            continue
                                        }
                                    }

                                    if ($msg -match "timed out") { $msg = "Timeout" }
                                    
                                    # --- FIXED: Explicitly target Column Index [1] (Status) ---
                                    $grid.Rows[$idx].Cells[1].Value = "MISSING (logged)"
                                    $grid.Rows[$idx].Cells[1].Style.BackColor = [System.Drawing.Color]::LightCoral
                                    # ----------------------------------------------------------
                                }
                            }
                        }
                    }
                }
            }
        }
        $btnScan.Enabled = $true
        $btnScan.Text = "Scan Files"
        [System.Windows.Forms.MessageBox]::Show("Scan Complete")
    })

    $histForm.Controls.AddRange(@($lblDate, $dtPicker, $lblReg, $txtReg, $btnScan, $grid))
    $histForm.ShowDialog()
}

$btnStart_Click = {
    # SAVE CHANGES (captures the current Root path)
    & $saveConfig
    
    # --- NEW: Ignore SSL Errors (for Self-Signed Certs) ---
    Set-IgnoreSslValidation
    # ------------------------------------------------------

    # --- 1. UI State Management [2] ---
    $tabConf.enabled = $false
    $btnStart.enabled = $false; $btnStart.BackColor = [System.Drawing.Color]::LightGray
    $btnStop.enabled = $true; $btnStop.BackColor = [System.Drawing.Color]::LightCoral
    $lblStatus.Text = "Status: MONITORING"; $lblStatus.ForeColor = [System.Drawing.Color]::Green

    # --- 2. Dynamic Grid Setup (Reset Columns) ---
    $DataGridView1.Columns.Clear()
    $DataGridView1.Columns.Add("File", "File") | Out-Null
    $DataGridView1.Columns.Add("SubPath", "Monitor Path") | Out-Null
    
    # Create a column for every Web Server in lstWeb [3]
    foreach ($webItem in $lstWeb.Items) {
        $DataGridView1.Columns.Add($webItem, $webItem) | Out-Null
    }

    # --- 3. Monitoring Logic [1] ---
    $script:activeWatchers = @() 
    $root = $txtRoot.Text 

    foreach ($subPath in $lstMonitor.Items) { # [4]
        
        $watchPath = Join-Path -Path $root -ChildPath $subPath

        if (Test-Path $watchPath) {
            $newWatcher = New-Object System.IO.FileSystemWatcher
            $newWatcher.Path = $watchPath
            $newWatcher.Filter = "*.*"
            $newWatcher.IncludeSubdirectories = $false
            $newWatcher.SynchronizingObject = $Form1 # [1]

            # --- 4. The Action Logic with Retry Loop [5] ---
            $action = {

                param($source, $e)

                # --- NEW: Check if item is a Directory ---
                # Construct the full physical path to test
                $fullPhysicalPath = Join-Path -Path $watchPath -ChildPath $e.Name
    
                # If it is a directory, exit this action block immediately
                if ([System.IO.Directory]::Exists($fullPhysicalPath)) { return }
                # -----------------------------------------

                # A. Initialize Grid Row
                $fileName = $e.Name

                $rowIndex = $DataGridView1.Rows.Add(@($fileName, $subPath))

                # B. define the Timeout (3 Minutes from Now)
                $timeout = (Get-Date).AddMinutes(3)
                
                # C. Track which servers still need checking
                # We copy the items to a generic list so we can remove them as they are found
                $serversToCheck = New-Object System.Collections.Generic.List[string]
                $lstWeb.Items | ForEach-Object { $serversToCheck.Add($_) }

                # D. The Loop: Runs until Time is up OR All servers found
                while ((Get-Date) -lt $timeout -and $serversToCheck.Count -gt 0) {
                    
                    # If user clicked Stop, break the loop immediately
                    if ($btnStop.Enabled -eq $false) { break }

                    # Create a copy to iterate safely while modifying the original list
                    $currentBatch = @($serversToCheck)

                    foreach ($webServer in $currentBatch) {
                        
                        # Update Status to "Scanning..."
                        $colIndex = $DataGridView1.Columns[$webServer].Index
                        $DataGridView1.Rows[$rowIndex].Cells[$colIndex].Value = "Scanning..."

                        # Construct URL
                        $urlPath = "$subPath/$fileName".Replace('\', '/')
                        $fullUrl = "https://$webServer/$urlPath"

                        # Ensure TLS and cert callback are set before each request attempt
                        Set-IgnoreSslValidation

                        # Check URL
                        try {
                            $req = [System.Net.WebRequest]::Create($fullUrl)
                            $req.Method = "HEAD"
                            $req.Timeout = 2000
                            $req.UseDefaultCredentials = $true
                            
                            $resp = $req.GetResponse()
                            
                            # IF FOUND: Update Grid and Remove from "To Check" list
                            $DataGridView1.Rows[$rowIndex].Cells[$colIndex].Value = "FOUND ($($resp.StatusCode))"
                            $DataGridView1.Rows[$rowIndex].Cells[$colIndex].Style.BackColor = [System.Drawing.Color]::LightGreen
                            $resp.Close()
                            
                            $serversToCheck.Remove($webServer) | Out-Null
                        }
                        catch {
                            # Log full exception for diagnosis (includes inner exception and stack trace)
                            Write-ExceptionLog -ExceptionObject $_ -Context "Watcher: $fullUrl"

                            $ex = $_.Exception
                            $msg = $ex.Message
                            if ($ex.InnerException) { $msg += " - " + $ex.InnerException.Message }

                            # If likely SSL/certificate/auth issue, try a GET fallback after ensuring certs are ignored
                            if ($msg -match "(certificate|ssl|authentication|secure channel|handshake)") {
                                try {
                                    Set-IgnoreSslValidation
                                    $req2 = [System.Net.WebRequest]::Create($fullUrl)
                                    $req2.Method = "GET"
                                    $req2.Timeout = 2000
                                    $req2.UseDefaultCredentials = $true
                                    $resp2 = $req2.GetResponse()

                                    $DataGridView1.Rows[$rowIndex].Cells[$colIndex].Value = "FOUND ($($resp2.StatusCode))"
                                    $DataGridView1.Rows[$rowIndex].Cells[$colIndex].Style.BackColor = [System.Drawing.Color]::LightGreen
                                    $resp2.Close()
                                    $serversToCheck.Remove($webServer) | Out-Null
                                    continue
                                }
                                catch {
                                    # Log the retry exception as well
                                    Write-ExceptionLog -ExceptionObject $_ -Context "Watcher (GET fallback): $fullUrl"

                                    $ex2 = $_.Exception
                                    $msg = $ex2.Message
                                    if ($ex2.InnerException) { $msg += " - " + $ex2.InnerException.Message }
                                    if ($msg -match "timed out") { $msg = "Timeout" }
                                    $DataGridView1.Rows[$rowIndex].Cells[$colIndex].Value = "SSL ERROR (logged)"
                                    $DataGridView1.Rows[$rowIndex].Cells[$colIndex].Style.BackColor = [System.Drawing.Color]::LightCoral
                                    continue
                                }
                            }

                            # IF MISSING: Update status, keep in list
                            $DataGridView1.Rows[$rowIndex].Cells[$colIndex].Value = "SEARCHING..."
                        }
                    }

                    # E. The Non-Freezing Wait (5 Seconds)
                    # We sleep in small 100ms chunks and process events so the UI doesn't hang
                    if ($serversToCheck.Count -gt 0) {
                        for ($i = 0; $i -lt 50; $i++) { 
                            Start-Sleep -Milliseconds 100
                            [System.Windows.Forms.Application]::DoEvents()
                            if ($btnStop.Enabled -eq $false) { break }
                        }
                    }
                }

                # F. Final Cleanup: Mark remaining servers as TIMEOUT
                foreach ($webServer in $serversToCheck) {
                    $colIndex = $DataGridView1.Columns[$webServer].Index
                    $DataGridView1.Rows[$rowIndex].Cells[$colIndex].Value = "TIMEOUT"
                    $DataGridView1.Rows[$rowIndex].Cells[$colIndex].Style.BackColor = [System.Drawing.Color]::LightCoral
                }

            }.GetNewClosure() 

            $newWatcher.add_Created($action)
            $newWatcher.EnableRaisingEvents = $true
            $script:activeWatchers += $newWatcher
        }
    }
}
$btnStop_Click = {
    # --- Existing UI State Management [5] ---
    $tabConf.enabled = $true
    $btnStart.enabled = $true; $btnStart.BackColor = [System.Drawing.Color]::LightGreen
    $btnStop.enabled = $false; $btnStop.BackColor = [System.Drawing.Color]::LightGray
    $lblStatus.Text = "Status: STOPPED!"; $lblStatus.ForeColor = [System.Drawing.Color]::Red

    # --- New Stop Logic ---
    foreach ($watcher in $script:activeWatchers) {
        $watcher.EnableRaisingEvents = $false
        $watcher.Dispose()
    }
    $script:activeWatchers = @() # Clear the list
}
Add-Type -AssemblyName System.Windows.Forms
. (Join-Path $PSScriptRoot 'monitor.designer.ps1')
& $loadConfig
$Form1.ShowDialog()
