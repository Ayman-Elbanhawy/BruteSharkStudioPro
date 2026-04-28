param(
    [Parameter(Mandatory = $true)]
    [string]$OutputFile
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms

$selected = [System.Collections.Generic.List[string]]::new()

$fileDialog = [System.Windows.Forms.OpenFileDialog]::new()
$fileDialog.Title = 'Select PCAP or PCAPNG files for BruteShark'
$fileDialog.Filter = 'Capture files (*.pcap;*.pcapng)|*.pcap;*.pcapng|All files (*.*)|*.*'
$fileDialog.Multiselect = $true
$fileDialog.CheckFileExists = $true

if ($fileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    foreach ($file in $fileDialog.FileNames) {
        [void]$selected.Add($file)
    }
}

$folderDialog = [System.Windows.Forms.FolderBrowserDialog]::new()
$folderDialog.Description = 'Optionally select a folder containing PCAP or PCAPNG files for BruteShark'
$folderDialog.ShowNewFolderButton = $false

if ($folderDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    Get-ChildItem -LiteralPath $folderDialog.SelectedPath -File -Recurse -Include '*.pcap','*.pcapng' |
        ForEach-Object { [void]$selected.Add($_.FullName) }
}

$unique = $selected |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    Sort-Object -Unique

Set-Content -LiteralPath $OutputFile -Value $unique -Encoding UTF8
