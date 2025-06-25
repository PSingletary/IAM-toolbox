# IAMTools.psm1
# Load all public and private functions

# Import Public Functions
Get-ChildItem -Path "$PSScriptRoot/Public/*.ps1" -Recurse | ForEach-Object {
    . $_.FullName
}

# Import Private Functions
Get-ChildItem -Path "$PSScriptRoot/Private/*.ps1" -Recurse | ForEach-Object {
    . $_.FullName
}
