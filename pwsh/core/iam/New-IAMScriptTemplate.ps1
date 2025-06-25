function New-IAMScriptTemplate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ScriptName,

        [Parameter()]
        [string]$Description = "A brief description of what this script does.",

        [Parameter()]
        [string]$Path = "$PSScriptRoot/../Templates"
    )

    if (-not (Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    $outputFile = Join-Path -Path $Path -ChildPath "$ScriptName.ps1"
    $date = Get-Date -Format 'yyyy-MM-dd'

$template = @"
<#
.SYNOPSIS
    $Description

.DESCRIPTION
    $Description

.PARAMETER ClientId
    OAuth2 client ID.

.PARAMETER ClientSecret
    OAuth2 client secret.

.PARAMETER TokenUri
    OAuth2 token endpoint URI.

.EXAMPLE
    .\${ScriptName}.ps1 -ClientId 'abc' -ClientSecret 'xyz' -TokenUri 'https://example.com/oauth2/token'

.NOTES
    Author: Patrick
    Created: $date
    Version: 0.1.0
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = \$true)]
    [string] \$ClientId,

    [Parameter(Mandatory = \$true)]
    [string] \$ClientSecret,

    [Parameter(Mandatory = \$true)]
    [string] \$TokenUri
)

function Get-OAuth2Token {
    param (
        [string] \$ClientId,
        [string] \$ClientSecret,
        [string] \$TokenUri
    )

    \$body = @{
        grant_type    = 'client_credentials'
        client_id     = \$ClientId
        client_secret = \$ClientSecret
    }

    try {
        \$response = Invoke-RestMethod -Uri \$TokenUri -Method Post -Body \$body -ContentType 'application/x-www-form-urlencoded'
        return \$response.access_token
    }
    catch {
        Write-Error "Failed to retrieve OAuth2 token: \$_"
        throw
    }
}

function Write-Log {
    param (
        [string] \$Message,
        [string] \$Level = 'INFO'
    )
    \$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Output "[\$timestamp][\$Level] \$Message"
}

try {
    Write-Log "Requesting OAuth2 token..."
    \$token = Get-OAuth2Token -ClientId \$ClientId -ClientSecret \$ClientSecret -TokenUri \$TokenUri

    \$headers = @{
        Authorization = "Bearer \$token"
        'Content-Type' = 'application/json'
    }

    \$uri = 'https://api.example.com/v1/resource'
    \$response = Invoke-RestMethod -Uri \$uri -Method Get -Headers \$headers

    Write-Output \$response
}
catch {
    Write-Log "An error occurred: \$_" -Level 'ERROR'
    throw
}
"@

    $template | Out-File -FilePath $outputFile -Encoding UTF8 -Force
    Write-Host "✅ Script template with API auth created: $outputFile"
}
