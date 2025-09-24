<#
.SYNOPSIS
    This is a script to set up a Windows Honeypot Repository using advanced audit policies, sets SACLs, and installs/configures Snare to forward Security logs to a SIEM via syslog (TCP/514).
.PARAMETER SIEMServer
    The SIEM server hostname or IP.
.EXAMPLE
    .\script.ps1 SIEMServer.domain.com
.NOTES
    - Run as Administrator.
    - Snare Community Edition is used (free for non-commercial use).
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$SIEMServer
)

# 1. Enable Advanced Audit Policies
Write-Host "Enabling Advanced Audit Policies..."
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# 2. Set SACLs on R:\Backups
Write-Host "Configuring SACLs on R:\Backups..."
$folder = "R:\Backups"
if (-not (Test-Path $folder)) {
    Write-Host "Folder $folder does not exist. Creating..."
    New-Item -ItemType Directory -Path $folder | Out-Null
}

# Corrected way to combine permissions: remove the parentheses.
# PowerShell's bitwise OR operator (-bor) will correctly combine the flags.
$everyonePerms = [System.Security.AccessControl.FileSystemRights]::Traverse `
    -bor [System.Security.AccessControl.FileSystemRights]::ExecuteFile `
    -bor [System.Security.AccessControl.FileSystemRights]::CreateFiles `
    -bor [System.Security.AccessControl.FileSystemRights]::WriteData `
    -bor [System.Security.AccessControl.FileSystemRights]::CreateDirectories `
    -bor [System.Security.AccessControl.FileSystemRights]::AppendData `
    -bor [System.Security.AccessControl.FileSystemRights]::WriteAttributes `
    -bor [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes `
    -bor [System.Security.AccessControl.FileSystemRights]::Delete `
    -bor [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles `
    -bor [System.Security.AccessControl.FileSystemRights]::ChangePermissions `
    -bor [System.Security.AccessControl.FileSystemRights]::TakeOwnership

$adminPerms = [System.Security.AccessControl.FileSystemRights]::Delete `
    -bor [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles

# Get the ACL and clear existing audit rules
$acl = Get-Acl -Path $folder
$acl.SetAuditRuleProtection($true, $false) # Protect from inheritance, remove existing

# Everyone SACL: Success+Failure, applies to folder, subfolders, files
$everyoneRule = New-Object System.Security.AccessControl.FileSystemAuditRule (
    "Everyone",
    $everyonePerms,
    ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
     [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
    [System.Security.AccessControl.PropagationFlags]::None,
    ([System.Security.AccessControl.AuditFlags]::Success -bor `
     [System.Security.AccessControl.AuditFlags]::Failure)
)

# Administrators SACL: Success, applies to folder, subfolders, files
$adminRule = New-Object System.Security.AccessControl.FileSystemAuditRule (
    "Administrators",
    $adminPerms,
    ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
     [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AuditFlags]::Success
)

# Add the rules and apply the ACL
$acl.AddAuditRule($everyoneRule)
$acl.AddAuditRule($adminRule)
Set-Acl -Path $folder -AclObject $acl

