# Load the module
BeforeAll {
    Import-Module "$PSScriptRoot/../IAMTools.psd1" -Force
}

Describe 'Get-UserDetails' {
    It 'Returns expected output for a valid username' {
        $result = Get-UserDetails -Username 'jdoe'
        $result | Should -Not -BeNullOrEmpty
    }

    It 'Throws an error when username is missing' {
        { Get-UserDetails } | Should -Throw
    }
}
