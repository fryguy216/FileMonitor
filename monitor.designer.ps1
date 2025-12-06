$Form1 = New-Object -TypeName System.Windows.Forms.Form
[System.Windows.Forms.TabControl]$tab = $null
[System.Windows.Forms.TabPage]$tabDash = $null
[System.Windows.Forms.Button]$Button1 = $null
[System.Windows.Forms.DataGridView]$DataGridView1 = $null
[System.Windows.Forms.DataGridViewTextBoxColumn]$FullPath = $null
[System.Windows.Forms.DataGridViewTextBoxColumn]$ChangeType = $null
[System.Windows.Forms.DataGridViewTextBoxColumn]$Date = $null
[System.Windows.Forms.Label]$lblStatus = $null
[System.Windows.Forms.Button]$btnStop = $null
[System.Windows.Forms.Button]$btnStart = $null
[System.Windows.Forms.TabPage]$tabConf = $null
[System.Windows.Forms.TextBox]$txtRoot = $null
[System.Windows.Forms.Label]$lblRoot = $null
[System.Windows.Forms.Label]$lblMonitor = $null
[System.Windows.Forms.Label]$lblWeb = $null
[System.Windows.Forms.TextBox]$txtMon = $null
[System.Windows.Forms.Button]$btnAddMon = $null
[System.Windows.Forms.Button]$btnRmvMon = $null
[System.Windows.Forms.ListBox]$lstMonitor = $null
[System.Windows.Forms.Button]$btnRmvWeb = $null
[System.Windows.Forms.Button]$btnAddWeb = $null
[System.Windows.Forms.TextBox]$txtWeb = $null
[System.Windows.Forms.ListBox]$lstWeb = $null
function InitializeComponent
{
$tab = (New-Object -TypeName System.Windows.Forms.TabControl)
$tabDash = (New-Object -TypeName System.Windows.Forms.TabPage)
$Button1 = (New-Object -TypeName System.Windows.Forms.Button)
$DataGridView1 = (New-Object -TypeName System.Windows.Forms.DataGridView)
$FullPath = (New-Object -TypeName System.Windows.Forms.DataGridViewTextBoxColumn)
$ChangeType = (New-Object -TypeName System.Windows.Forms.DataGridViewTextBoxColumn)
$Date = (New-Object -TypeName System.Windows.Forms.DataGridViewTextBoxColumn)
$lblStatus = (New-Object -TypeName System.Windows.Forms.Label)
$btnStop = (New-Object -TypeName System.Windows.Forms.Button)
$btnStart = (New-Object -TypeName System.Windows.Forms.Button)
$tabConf = (New-Object -TypeName System.Windows.Forms.TabPage)
$txtRoot = (New-Object -TypeName System.Windows.Forms.TextBox)
$lblRoot = (New-Object -TypeName System.Windows.Forms.Label)
$lblMonitor = (New-Object -TypeName System.Windows.Forms.Label)
$lblWeb = (New-Object -TypeName System.Windows.Forms.Label)
$txtMon = (New-Object -TypeName System.Windows.Forms.TextBox)
$btnAddMon = (New-Object -TypeName System.Windows.Forms.Button)
$btnRmvMon = (New-Object -TypeName System.Windows.Forms.Button)
$lstMonitor = (New-Object -TypeName System.Windows.Forms.ListBox)
$btnRmvWeb = (New-Object -TypeName System.Windows.Forms.Button)
$btnAddWeb = (New-Object -TypeName System.Windows.Forms.Button)
$txtWeb = (New-Object -TypeName System.Windows.Forms.TextBox)
$lstWeb = (New-Object -TypeName System.Windows.Forms.ListBox)
$tab.SuspendLayout()
$tabDash.SuspendLayout()
([System.ComponentModel.ISupportInitialize]$DataGridView1).BeginInit()
$tabConf.SuspendLayout()
$Form1.SuspendLayout()
#
#tab
#
$tab.Controls.Add($tabDash)
$tab.Controls.Add($tabConf)
$tab.Dock = [System.Windows.Forms.DockStyle]::Fill
$tab.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]0,[System.Int32]0))
$tab.Name = [System.String]'tab'
$tab.SelectedIndex = [System.Int32]0
$tab.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]684,[System.Int32]461))
$tab.TabIndex = [System.Int32]0
#
#tabDash
#
$tabDash.Controls.Add($Button1)
$tabDash.Controls.Add($DataGridView1)
$tabDash.Controls.Add($lblStatus)
$tabDash.Controls.Add($btnStop)
$tabDash.Controls.Add($btnStart)
$tabDash.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]4,[System.Int32]22))
$tabDash.Name = [System.String]'tabDash'
$tabDash.Padding = (New-Object -TypeName System.Windows.Forms.Padding -ArgumentList @([System.Int32]3))
$tabDash.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]676,[System.Int32]435))
$tabDash.TabIndex = [System.Int32]0
$tabDash.Text = [System.String]'Dashboard'
$tabDash.UseVisualStyleBackColor = $true
#
#Button1
#
$Button1.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]400,[System.Int32]6))
$Button1.Name = [System.String]'Button1'
$Button1.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]85,[System.Int32]23))
$Button1.TabIndex = [System.Int32]4
$Button1.Text = [System.String]'History Scan'
$Button1.UseVisualStyleBackColor = $true
$Button1.add_Click($btnHistory_Click)
#
#DataGridView1
#
$DataGridView1.AllowUserToAddRows = $false
$DataGridView1.AllowUserToDeleteRows = $false
$DataGridView1.Anchor = ([System.Windows.Forms.AnchorStyles][System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)
$DataGridView1.ColumnHeadersHeightSizeMode = [System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode]::AutoSize
$DataGridView1.Columns.AddRange($FullPath,$ChangeType,$Date)
$DataGridView1.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]3,[System.Int32]35))
$DataGridView1.Name = [System.String]'DataGridView1'
$DataGridView1.ReadOnly = $true
$DataGridView1.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]670,[System.Int32]397))
$DataGridView1.TabIndex = [System.Int32]3
#
#FullPath
#
$FullPath.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
$FullPath.HeaderText = [System.String]'Path'
$FullPath.Name = [System.String]'FullPath'
$FullPath.ReadOnly = $true
#
#ChangeType
#
$ChangeType.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
$ChangeType.HeaderText = [System.String]'Change Type'
$ChangeType.Name = [System.String]'ChangeType'
$ChangeType.ReadOnly = $true
#
#Date
#
$Date.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
$Date.HeaderText = [System.String]'Date'
$Date.Name = [System.String]'Date'
$Date.ReadOnly = $true
#
#lblStatus
#
$lblStatus.Font = (New-Object -TypeName System.Drawing.Font -ArgumentList @([System.String]'Segoe UI',[System.Single]9.75,[System.Drawing.FontStyle]::Bold,[System.Drawing.GraphicsUnit]::Point,([System.Byte][System.Byte]0)))
$lblStatus.ForeColor = [System.Drawing.Color]::Red
$lblStatus.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]170,[System.Int32]6))
$lblStatus.Name = [System.String]'lblStatus'
$lblStatus.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]213,[System.Int32]23))
$lblStatus.TabIndex = [System.Int32]2
$lblStatus.Text = [System.String]'Status: STOPPED!'
#
#btnStop
#
$btnStop.Enabled = $false
$btnStop.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]89,[System.Int32]6))
$btnStop.Name = [System.String]'btnStop'
$btnStop.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]75,[System.Int32]23))
$btnStop.TabIndex = [System.Int32]1
$btnStop.Text = [System.String]'Stop'
$btnStop.UseVisualStyleBackColor = $true
$btnStop.add_Click($btnStop_Click)
#
#btnStart
#
$btnStart.BackColor = [System.Drawing.Color]::LightGreen
$btnStart.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]8,[System.Int32]6))
$btnStart.Name = [System.String]'btnStart'
$btnStart.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]75,[System.Int32]23))
$btnStart.TabIndex = [System.Int32]0
$btnStart.Text = [System.String]'Start'
$btnStart.UseVisualStyleBackColor = $false
$btnStart.add_Click($btnStart_Click)
#
#tabConf
#
$tabConf.Controls.Add($txtRoot)
$tabConf.Controls.Add($lblRoot)
$tabConf.Controls.Add($lblMonitor)
$tabConf.Controls.Add($lblWeb)
$tabConf.Controls.Add($txtMon)
$tabConf.Controls.Add($btnAddMon)
$tabConf.Controls.Add($btnRmvMon)
$tabConf.Controls.Add($lstMonitor)
$tabConf.Controls.Add($btnRmvWeb)
$tabConf.Controls.Add($btnAddWeb)
$tabConf.Controls.Add($txtWeb)
$tabConf.Controls.Add($lstWeb)
$tabConf.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]4,[System.Int32]22))
$tabConf.Name = [System.String]'tabConf'
$tabConf.Padding = (New-Object -TypeName System.Windows.Forms.Padding -ArgumentList @([System.Int32]3))
$tabConf.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]676,[System.Int32]435))
$tabConf.TabIndex = [System.Int32]1
$tabConf.Text = [System.String]'Configuration'
$tabConf.UseVisualStyleBackColor = $true
#
#txtRoot
#
$txtRoot.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]8,[System.Int32]20))
$txtRoot.Name = [System.String]'txtRoot'
$txtRoot.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]207,[System.Int32]21))
$txtRoot.TabIndex = [System.Int32]13
$txtRoot.Text = [System.String]'c:\test\'
#
#lblRoot
#
$lblRoot.Font = (New-Object -TypeName System.Drawing.Font -ArgumentList @([System.String]'Segoe UI',[System.Single]9.75,[System.Drawing.FontStyle]::Bold,[System.Drawing.GraphicsUnit]::Point,([System.Byte][System.Byte]0)))
$lblRoot.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]8,[System.Int32]3))
$lblRoot.Name = [System.String]'lblRoot'
$lblRoot.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]386,[System.Int32]23))
$lblRoot.TabIndex = [System.Int32]12
$lblRoot.Text = [System.String]'Root folder to monitor (must end with \):'
#
#lblMonitor
#
$lblMonitor.Font = (New-Object -TypeName System.Drawing.Font -ArgumentList @([System.String]'Segoe UI',[System.Single]9.75,[System.Drawing.FontStyle]::Bold,[System.Drawing.GraphicsUnit]::Point,([System.Byte][System.Byte]0)))
$lblMonitor.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]8,[System.Int32]65))
$lblMonitor.Name = [System.String]'lblMonitor'
$lblMonitor.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]386,[System.Int32]23))
$lblMonitor.TabIndex = [System.Int32]11
$lblMonitor.Text = [System.String]'Paths to Monitor (do not start or end with \):'
#
#lblWeb
#
$lblWeb.Font = (New-Object -TypeName System.Drawing.Font -ArgumentList @([System.String]'Segoe UI',[System.Single]9.75,[System.Drawing.FontStyle]::Bold,[System.Drawing.GraphicsUnit]::Point,([System.Byte][System.Byte]0)))
$lblWeb.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]8,[System.Int32]227))
$lblWeb.Name = [System.String]'lblWeb'
$lblWeb.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]386,[System.Int32]23))
$lblWeb.TabIndex = [System.Int32]10
$lblWeb.Text = [System.String]'Webservers to Scan (only FQDN):'
#
#txtMon
#
$txtMon.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]221,[System.Int32]192))
$txtMon.Name = [System.String]'txtMon'
$txtMon.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]173,[System.Int32]21))
$txtMon.TabIndex = [System.Int32]9
#
#btnAddMon
#
$btnAddMon.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]140,[System.Int32]192))
$btnAddMon.Name = [System.String]'btnAddMon'
$btnAddMon.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]75,[System.Int32]23))
$btnAddMon.TabIndex = [System.Int32]8
$btnAddMon.Text = [System.String]'+'
$btnAddMon.UseVisualStyleBackColor = $true
$btnAddMon.add_Click($btnAddMon_Click)
#
#btnRmvMon
#
$btnRmvMon.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]8,[System.Int32]192))
$btnRmvMon.Name = [System.String]'btnRmvMon'
$btnRmvMon.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]75,[System.Int32]23))
$btnRmvMon.TabIndex = [System.Int32]7
$btnRmvMon.Text = [System.String]'-'
$btnRmvMon.UseVisualStyleBackColor = $true
$btnRmvMon.add_Click($btnRmvMon_Click)
#
#lstMonitor
#
$lstMonitor.FormattingEnabled = $true
$lstMonitor.Items.AddRange([System.Object[]]@([System.String]'instit\annceresult\press\preanre\2025',[System.String]'instit\annceresult\press\preanre',[System.String]'xml'))
$lstMonitor.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]8,[System.Int32]91))
$lstMonitor.Name = [System.String]'lstMonitor'
$lstMonitor.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]207,[System.Int32]95))
$lstMonitor.TabIndex = [System.Int32]6
#
#btnRmvWeb
#
$btnRmvWeb.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]8,[System.Int32]354))
$btnRmvWeb.Name = [System.String]'btnRmvWeb'
$btnRmvWeb.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]75,[System.Int32]23))
$btnRmvWeb.TabIndex = [System.Int32]5
$btnRmvWeb.Text = [System.String]'-'
$btnRmvWeb.UseVisualStyleBackColor = $true
$btnRmvWeb.add_Click($btnRmvWeb_Click)
#
#btnAddWeb
#
$btnAddWeb.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]140,[System.Int32]354))
$btnAddWeb.Name = [System.String]'btnAddWeb'
$btnAddWeb.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]75,[System.Int32]23))
$btnAddWeb.TabIndex = [System.Int32]4
$btnAddWeb.Text = [System.String]'+'
$btnAddWeb.UseVisualStyleBackColor = $true
$btnAddWeb.add_Click($btnAddWeb_Click)
#
#txtWeb
#
$txtWeb.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]221,[System.Int32]354))
$txtWeb.Name = [System.String]'txtWeb'
$txtWeb.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]173,[System.Int32]21))
$txtWeb.TabIndex = [System.Int32]3
#
#lstWeb
#
$lstWeb.FormattingEnabled = $true
$lstWeb.Items.AddRange([System.Object[]]@([System.String]'www.treasurydirect.gov'))
$lstWeb.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]8,[System.Int32]253))
$lstWeb.Name = [System.String]'lstWeb'
$lstWeb.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]207,[System.Int32]95))
$lstWeb.Sorted = $true
$lstWeb.TabIndex = [System.Int32]2
#
#Form1
#
$Form1.ClientSize = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]684,[System.Int32]461))
$Form1.Controls.Add($tab)
$Form1.Text = [System.String]'File Replication Monitor'
$tab.ResumeLayout($false)
$tabDash.ResumeLayout($false)
([System.ComponentModel.ISupportInitialize]$DataGridView1).EndInit()
$tabConf.ResumeLayout($false)
$tabConf.PerformLayout()
$Form1.ResumeLayout($false)
Add-Member -InputObject $Form1 -Name tab -Value $tab -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name tabDash -Value $tabDash -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name Button1 -Value $Button1 -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name DataGridView1 -Value $DataGridView1 -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name FullPath -Value $FullPath -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name ChangeType -Value $ChangeType -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name Date -Value $Date -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name lblStatus -Value $lblStatus -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name btnStop -Value $btnStop -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name btnStart -Value $btnStart -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name tabConf -Value $tabConf -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name txtRoot -Value $txtRoot -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name lblRoot -Value $lblRoot -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name lblMonitor -Value $lblMonitor -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name lblWeb -Value $lblWeb -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name txtMon -Value $txtMon -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name btnAddMon -Value $btnAddMon -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name btnRmvMon -Value $btnRmvMon -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name lstMonitor -Value $lstMonitor -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name btnRmvWeb -Value $btnRmvWeb -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name btnAddWeb -Value $btnAddWeb -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name txtWeb -Value $txtWeb -MemberType NoteProperty
Add-Member -InputObject $Form1 -Name lstWeb -Value $lstWeb -MemberType NoteProperty
}
. InitializeComponent
