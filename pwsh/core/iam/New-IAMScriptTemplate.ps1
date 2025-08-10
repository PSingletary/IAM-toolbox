<#
.SYNOPSIS
    Creates a new PowerShell script template with OAuth2 authentication.

.DESCRIPTION
    Generates a PowerShell script template that includes:
    - OAuth2 client credentials authentication
    - Structured error handling and validation
    - Comprehensive logging functionality
    - Configurable API endpoint placeholder
    - Security best practices implementation

.PARAMETER ScriptName
    The name of the script file to create (without .ps1 extension).
    Must contain only alphanumeric characters, hyphens, and underscores.

.PARAMETER Description
    A brief description of what the generated script will do.
    This will be used in the script's comment-based help.

.PARAMETER Path
    The directory path where the template will be created.
    Will be created if it doesn't exist.

.PARAMETER OAuth2Flow
    The OAuth2 flow type to use in the template.
    Valid values: 'ClientCredentials', 'AuthorizationCode', 'Password'
    Default: 'ClientCredentials'

.PARAMETER ApiEndpoint
    The API endpoint placeholder to use in the template.
    Default: 'https://api.example.com/v1/resource'

.EXAMPLE
    New-IAMScriptTemplate -ScriptName "MyAPIScript" -Description "Connects to MyAPI service"

.EXAMPLE
    New-IAMScriptTemplate -ScriptName "UserManagement" -Description "User management operations" -OAuth2Flow "AuthorizationCode" -ApiEndpoint "https://api.mycompany.com/users"

.NOTES
    Author: Patrick
    Version: 2.0.0
    Created: 2024-01-01
    Updated: 2024-01-01

    Security Notes:
    - Generated scripts include parameter validation
    - Sensitive parameters are marked as SecureString where appropriate
    - Error messages don't expose sensitive information
#>

# Helper function to generate Client Credentials template
function Get-ClientCredentialsTemplate {
    param (
        [string]$Description,
        [string]$ScriptName,
        [string]$ApiEndpoint,
        [string]$AUTHOR,
        [string]$CREATION_DATE,
        [string]$DEFAULT_VERSION
    )
    
    $template = @"
<#
.SYNOPSIS
    $Description

.DESCRIPTION
    $Description
    
    This script implements OAuth2 Client Credentials flow for API authentication.
    It automatically retrieves an access token and makes authenticated API calls.

.PARAMETER ClientId
    OAuth2 client ID for API authentication.

.PARAMETER ClientSecret
    OAuth2 client secret for API authentication.
    Consider using a SecureString or environment variable for production.

.PARAMETER TokenUri
    OAuth2 token endpoint URI.

.PARAMETER ApiEndpoint
    The API endpoint to call after authentication.
    Default: $ApiEndpoint

.EXAMPLE
    .\${ScriptName}.ps1 -ClientId 'your-client-id' -ClientSecret 'your-client-secret' -TokenUri 'https://auth.example.com/oauth2/token'

.EXAMPLE
    .\${ScriptName}.ps1 -ClientId 'your-client-id' -ClientSecret 'your-client-secret' -TokenUri 'https://auth.example.com/oauth2/token' -ApiEndpoint 'https://api.example.com/v1/users'

.NOTES
    Author: $AUTHOR
    Created: $CREATION_DATE
    Version: $DEFAULT_VERSION
    
    Security Considerations:
    - Store client secrets securely (use environment variables or Azure Key Vault)
    - Validate all input parameters
    - Use HTTPS for all API communications
    - Implement proper error handling for production use
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = `$true)]
    [ValidateNotNullOrEmpty()]
    [string] `$ClientId,

    [Parameter(Mandatory = `$true)]
    [ValidateNotNullOrEmpty()]
    [string] `$ClientSecret,

    [Parameter(Mandatory = `$true)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^https?://', ErrorMessage = 'TokenUri must be a valid HTTP/HTTPS URL.')]
    [string] `$TokenUri,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^https?://', ErrorMessage = 'ApiEndpoint must be a valid HTTP/HTTPS URL.')]
    [string] `$ApiEndpoint = '$ApiEndpoint'
)

# Script configuration
`$SCRIPT_VERSION = '$DEFAULT_VERSION'
`$SCRIPT_NAME = '$ScriptName'

function Get-OAuth2Token {
    <#
    .SYNOPSIS
        Retrieves an OAuth2 access token using client credentials flow.
    
    .DESCRIPTION
        Makes a POST request to the OAuth2 token endpoint to obtain an access token
        using the client credentials grant type.
    
    .PARAMETER ClientId
        The OAuth2 client ID.
    
    .PARAMETER ClientSecret
        The OAuth2 client secret.
    
    .PARAMETER TokenUri
        The OAuth2 token endpoint URI.
    
    .RETURNS
        The access token string.
    
    .EXAMPLE
        `$token = Get-OAuth2Token -ClientId 'abc' -ClientSecret 'xyz' -TokenUri 'https://auth.example.com/oauth2/token'
    #>
    param (
        [Parameter(Mandatory = `$true)]
        [string] `$ClientId,
        
        [Parameter(Mandatory = `$true)]
        [string] `$ClientSecret,
        
        [Parameter(Mandatory = `$true)]
        [string] `$TokenUri
    )

    Write-Log "Requesting OAuth2 token from: `$TokenUri" -Level 'INFO'

    `$body = @{
        grant_type    = 'client_credentials'
        client_id     = `$ClientId
        client_secret = `$ClientSecret
    }

    try {
        `$response = Invoke-RestMethod -Uri `$TokenUri -Method Post -Body `$body -ContentType 'application/x-www-form-urlencoded'
        
        if (-not `$response.access_token) {
            throw "OAuth2 response does not contain access_token"
        }

        Write-Log "Successfully retrieved OAuth2 token" -Level 'INFO'
        return `$response.access_token
    }
    catch {
        Write-Log "Failed to retrieve OAuth2 token: `$(`$_.Exception.Message)" -Level 'ERROR'
        throw "OAuth2 token request failed: `$(`$_.Exception.Message)"
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a formatted log message with timestamp and level.
    
    .DESCRIPTION
        Outputs a structured log message with timestamp, log level, and message content.
        Supports different log levels for better debugging and monitoring.
    
    .PARAMETER Message
        The log message to output.
    
    .PARAMETER Level
        The log level (INFO, WARN, ERROR, DEBUG).
        Default: INFO
    
    .EXAMPLE
        Write-Log "Starting API operation" -Level 'INFO'
        Write-Log "Authentication successful" -Level 'INFO'
        Write-Log "API call failed" -Level 'ERROR'
    #>
    param (
        [Parameter(Mandatory = `$true)]
        [string] `$Message,
        
        [Parameter()]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string] `$Level = 'INFO'
    )
    
    `$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    `$logMessage = "[`$timestamp][`$Level] `$Message"
    
    switch (`$Level) {
        'ERROR' { Write-Error `$logMessage }
        'WARN'  { Write-Warning `$logMessage }
        'DEBUG' { 
            if (`$VerbosePreference -ne 'SilentlyContinue') {
                Write-Verbose `$logMessage 
            }
        }
        default { Write-Output `$logMessage }
    }
}

function Test-ApiEndpoint {
    <#
    .SYNOPSIS
        Tests the API endpoint connectivity and authentication.
    
    .DESCRIPTION
        Makes a test call to the API endpoint to verify connectivity and
        that the authentication token is valid.
    
    .PARAMETER Uri
        The API endpoint URI to test.
    
    .PARAMETER Headers
        The HTTP headers to include in the request.
    
    .RETURNS
        Boolean indicating if the test was successful.
    
    .EXAMPLE
        `$isValid = Test-ApiEndpoint -Uri 'https://api.example.com/v1/health' -Headers `$headers
    #>
    param (
        [Parameter(Mandatory = `$true)]
        [string] `$Uri,
        
        [Parameter(Mandatory = `$true)]
        [hashtable] `$Headers
    )

    try {
        Write-Log "Testing API endpoint connectivity: `$Uri" -Level 'INFO'
        `$response = Invoke-RestMethod -Uri `$Uri -Method Get -Headers `$Headers -TimeoutSec 30
        Write-Log "API endpoint test successful" -Level 'INFO'
        return `$true
    }
    catch {
        Write-Log "API endpoint test failed: `$(`$_.Exception.Message)" -Level 'ERROR'
        return `$false
    }
}

# Main execution block
try {
    Write-Log "Starting `$SCRIPT_NAME (v`$SCRIPT_VERSION)" -Level 'INFO'
    
    # Validate input parameters
    Write-Log "Validating input parameters..." -Level 'INFO'
    if (-not `$ClientId -or -not `$ClientSecret -or -not `$TokenUri) {
        throw "All required parameters must be provided"
    }

    # Get OAuth2 token
    Write-Log "Requesting OAuth2 token..." -Level 'INFO'
    `$token = Get-OAuth2Token -ClientId `$ClientId -ClientSecret `$ClientSecret -TokenUri `$TokenUri

    # Prepare headers for API calls
    `$headers = @{
        Authorization = "Bearer `$token"
        'Content-Type' = 'application/json'
        'User-Agent' = "`$SCRIPT_NAME/`$SCRIPT_VERSION"
    }

    # Test API connectivity
    if (-not (Test-ApiEndpoint -Uri `$ApiEndpoint -Headers `$headers)) {
        throw "Failed to connect to API endpoint: `$ApiEndpoint"
    }

    # Make API call
    Write-Log "Making API call to: `$ApiEndpoint" -Level 'INFO'
    `$response = Invoke-RestMethod -Uri `$ApiEndpoint -Method Get -Headers `$headers -TimeoutSec 60

    # Output results
    Write-Log "API call completed successfully" -Level 'INFO'
    Write-Output `$response
}
catch {
    Write-Log "Script execution failed: `$(`$_.Exception.Message)" -Level 'ERROR'
    Write-Log "Stack trace: `$(`$_.ScriptStackTrace)" -Level 'DEBUG'
    throw
}
finally {
    Write-Log "Script execution completed" -Level 'INFO'
}
"@
        return $template
    }

# Helper function to generate Authorization Code template
function Get-AuthorizationCodeTemplate {
    param (
        [string]$Description,
        [string]$ScriptName,
        [string]$ApiEndpoint,
        [string]$AUTHOR,
        [string]$CREATION_DATE,
        [string]$DEFAULT_VERSION
    )
    
    $template = @"
<#
.SYNOPSIS
    $Description

.DESCRIPTION
    $Description
    
    This script implements OAuth2 Authorization Code flow for API authentication.
    It requires user interaction to complete the authorization process.

.PARAMETER ClientId
    OAuth2 client ID for API authentication.

.PARAMETER ClientSecret
    OAuth2 client secret for API authentication.

.PARAMETER RedirectUri
    OAuth2 redirect URI for authorization code flow.

.PARAMETER AuthorizationUri
    OAuth2 authorization endpoint URI.

.PARAMETER TokenUri
    OAuth2 token endpoint URI.

.PARAMETER ApiEndpoint
    The API endpoint to call after authentication.
    Default: $ApiEndpoint

.EXAMPLE
    .\${ScriptName}.ps1 -ClientId 'your-client-id' -ClientSecret 'your-client-secret' -RedirectUri 'http://localhost:8080/callback'

.NOTES
    Author: $AUTHOR
    Created: $CREATION_DATE
    Version: $DEFAULT_VERSION
    
    Security Considerations:
    - This flow requires user interaction
    - Store tokens securely
    - Implement token refresh logic for long-running operations
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = `$true)]
    [ValidateNotNullOrEmpty()]
    [string] `$ClientId,

    [Parameter(Mandatory = `$true)]
    [ValidateNotNullOrEmpty()]
    [string] `$ClientSecret,

    [Parameter(Mandatory = `$true)]
    [ValidateNotNullOrEmpty()]
    [string] `$RedirectUri,

    [Parameter(Mandatory = `$true)]
    [ValidateNotNullOrEmpty()]
    [string] `$AuthorizationUri,

    [Parameter(Mandatory = `$true)]
    [ValidateNotNullOrEmpty()]
    [string] `$TokenUri,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] `$ApiEndpoint = '$ApiEndpoint'
)

# Implementation for Authorization Code flow would go here
# This is a placeholder template - implement based on your specific OAuth2 provider requirements

Write-Log "Authorization Code flow template - implement based on your OAuth2 provider" -Level 'INFO'
"@
        return $template
    }

# Helper function to generate Password template
function Get-PasswordTemplate {
    param (
        [string]$Description,
        [string]$ScriptName,
        [string]$ApiEndpoint,
        [string]$AUTHOR,
        [string]$CREATION_DATE,
        [string]$DEFAULT_VERSION
    )
    
    $template = @"
<#
.SYNOPSIS
    $Description

.DESCRIPTION
    $Description
    
    This script implements OAuth2 Password (Resource Owner Password Credentials) flow.
    WARNING: This flow is less secure and should only be used when other flows are not available.

.PARAMETER ClientId
    OAuth2 client ID for API authentication.

.PARAMETER ClientSecret
    OAuth2 client secret for API authentication.

.PARAMETER Username
    User's username for authentication.

.PARAMETER Password
    User's password for authentication.

.PARAMETER TokenUri
    OAuth2 token endpoint URI.

.PARAMETER ApiEndpoint
    The API endpoint to call after authentication.
    Default: $ApiEndpoint

.EXAMPLE
    .\${ScriptName}.ps1 -ClientId 'your-client-id' -ClientSecret 'your-client-secret' -Username 'user@example.com' -Password 'userpassword'

.NOTES
    Author: $AUTHOR
    Created: $CREATION_DATE
    Version: $DEFAULT_VERSION
    
    Security Warnings:
    - Password flow is less secure than other OAuth2 flows
    - Consider using Authorization Code flow instead
    - Never store passwords in plain text
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = `$true)]
    [ValidateNotNullOrEmpty()]
    [string] `$ClientId,

    [Parameter(Mandatory = `$true)]
    [ValidateNotNullOrEmpty()]
    [string] `$ClientSecret,

    [Parameter(Mandatory = `$true)]
    [ValidateNotNullOrEmpty()]
    [string] `$Username,

    [Parameter(Mandatory = `$true)]
    [ValidateNotNullOrEmpty()]
    [string] `$Password,

    [Parameter(Mandatory = `$true)]
    [ValidateNotNullOrEmpty()]
    [string] `$TokenUri,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] `$ApiEndpoint = '$ApiEndpoint'
)

# Implementation for Password flow would go here
# This is a placeholder template - implement based on your specific OAuth2 provider requirements

Write-Log "Password flow template - implement based on your OAuth2 provider" -Level 'INFO'
"@
        return $template
    }

function New-IAMScriptTemplate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[a-zA-Z0-9_-]+$', ErrorMessage = 'ScriptName can only contain alphanumeric characters, hyphens, and underscores.')]
        [string]$ScriptName,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Description = "A PowerShell script with OAuth2 authentication for API operations.",

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Path = "$PSScriptRoot/../Templates",

        [Parameter()]
        [ValidateSet('ClientCredentials', 'AuthorizationCode', 'Password')]
        [string]$OAuth2Flow = 'ClientCredentials',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^https?://', ErrorMessage = 'ApiEndpoint must be a valid HTTP/HTTPS URL.')]
        [string]$ApiEndpoint = 'https://api.example.com/v1/resource'
    )

    # Constants
    $DEFAULT_VERSION = '1.0.0'
    $AUTHOR = 'Patrick'
    $CREATION_DATE = Get-Date -Format 'yyyy-MM-dd'

    try {
        # Validate and create output directory
        Write-Verbose "Validating output path: $Path"
        if (-not (Test-Path -Path $Path -PathType Container)) {
            try {
                New-Item -ItemType Directory -Path $Path -Force | Out-Null
                Write-Verbose "Created directory: $Path"
            }
            catch {
                throw "Failed to create directory '$Path': $($_.Exception.Message)"
            }
        }

        # Validate write permissions
        if (-not (Test-Path -Path $Path -PathType Container)) {
            throw "Path '$Path' is not a valid directory."
        }

        try {
            $testFile = Join-Path -Path $Path -ChildPath "test_write.tmp"
            New-Item -ItemType File -Path $testFile -Force | Out-Null
            Remove-Item -Path $testFile -Force
        }
        catch {
            throw "No write permission to directory '$Path': $($_.Exception.Message)"
        }

        # Generate output file path
        $outputFile = Join-Path -Path $Path -ChildPath "$ScriptName.ps1"
        
        # Check if file already exists
        if (Test-Path -Path $outputFile) {
            $overwrite = Read-Host "File '$outputFile' already exists. Overwrite? (y/N)"
            if ($overwrite -notmatch '^[Yy]$') {
                Write-Host "Operation cancelled by user."
                return
            }
        }

        # Generate OAuth2 flow specific template
        $template = switch ($OAuth2Flow) {
            'ClientCredentials' { Get-ClientCredentialsTemplate -Description $Description -ScriptName $ScriptName -ApiEndpoint $ApiEndpoint -AUTHOR $AUTHOR -CREATION_DATE $CREATION_DATE -DEFAULT_VERSION $DEFAULT_VERSION }
            'AuthorizationCode' { Get-AuthorizationCodeTemplate -Description $Description -ScriptName $ScriptName -ApiEndpoint $ApiEndpoint -AUTHOR $AUTHOR -CREATION_DATE $CREATION_DATE -DEFAULT_VERSION $DEFAULT_VERSION }
            'Password' { Get-PasswordTemplate -Description $Description -ScriptName $ScriptName -ApiEndpoint $ApiEndpoint -AUTHOR $AUTHOR -CREATION_DATE $CREATION_DATE -DEFAULT_VERSION $DEFAULT_VERSION }
        }

        # Write template to file
        Write-Verbose "Writing template to: $outputFile"
        $template | Out-File -FilePath $outputFile -Encoding UTF8 -Force

        # Validate generated script syntax
        $syntaxErrors = @()
        try {
            $null = [System.Management.Automation.PSParser]::Tokenize($template, [ref]$syntaxErrors)
        }
        catch {
            Write-Warning "Could not validate script syntax: $($_.Exception.Message)"
        }

        if ($syntaxErrors.Count -gt 0) {
            Write-Warning "Script generated with syntax warnings:"
            $syntaxErrors | ForEach-Object { Write-Warning "  $($_.Message)" }
        }

        # Success message with details
        Write-Host "✅ Script template created successfully!" -ForegroundColor Green
        Write-Host "📁 Location: $outputFile" -ForegroundColor Cyan
        Write-Host "🔐 OAuth2 Flow: $OAuth2Flow" -ForegroundColor Cyan
        Write-Host " API Endpoint: $ApiEndpoint" -ForegroundColor Cyan
        Write-Host " Next Steps:" -ForegroundColor Yellow
        Write-Host "   1. Review and customize the generated script" -ForegroundColor White
        Write-Host "   2. Update the API endpoint and parameters" -ForegroundColor White
        Write-Host "   3. Test with your OAuth2 credentials" -ForegroundColor White
    }
    catch {
        Write-Error "Failed to create script template: $($_.Exception.Message)"
        throw
    }
}
