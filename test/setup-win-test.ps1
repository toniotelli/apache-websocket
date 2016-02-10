# Get command-line parameters.
#   -ModuleDirectory <path>: the path to your httpd installation's modules directory
#   -Version <version>: your httpd version (either 2.2 or 2.4)
Param(
  [Parameter(Mandatory=$true)]
  [string]$moduleDirectory,
  [Parameter(Mandatory=$true)]
  [string]$version
)

If ($version -eq '2.2') {
  $conf_22 = ''
  $conf_24 = '# '
} ElseIf ($version -eq '2.4') {
  $conf_22 = '# '
  $conf_24 = ''
} Else {
  Write-Error "Expected -Version to be either 2.2 or 2.4 (got $version)"
  Return
}

# Create the support directories for the server.
New-Item -ItemType Directory -Force -Path httpd\htdocs > $null
New-Item -ItemType Directory -Force -Path httpd\logs > $null
New-Item -ItemType Directory -Force -Path httpd\modules > $null

# Generate the test configuration.
Get-Content -Path httpd\test.conf.in | %{
  $_ -replace '@mpm_comment@',        '# '     `
     -replace '@TEST_MPM@',           'winnt'  `
     -replace '@conf_22@',            $conf_22 `
     -replace '@conf_24@',            $conf_24 `
     -replace '@conf_unix@',          '# '     `
     -replace '@system_modules_dir@', $moduleDirectory
} | Set-Content -Path httpd\test.conf
