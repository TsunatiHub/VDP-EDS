##  Veeeam CS Hardening Windows Services Disable Scripts
##  By Nate Patel


## Enable Firewall
netsh advfirewall set allprofiles state on



##  Shutdown Services

# Disable Remote Desktop Services (RDP)
## sc config TermService start=disabled
## sc stop TermService

# Disable Remote Registry Service
sc config RemoteRegistry start= auto
sc start RemoteRegistry

# Disable Windows Remote Management Service
sc config WinRM start= auto
sc start WinRM

## Disable Out-of-Date Protocols

# Disable Web Proxy Auto-Discovery Service
REG ADD "HKLM\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v start /t REG_DWORD /d "4" /f

# Disable WDigest Credentials Caching
REG ADD "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d "1" /f

# Disable Windows Script Host
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d "1" /f

# Disable NetBIOS Protocol
wmic nicconfig where (IPEnabled=TRUE) call SetTcpipNetbios 2

# Disable SMBv1 Protocol
dism /Online /Disable-Feature /FeatureName:SMB1Protocol

# Disable Link-Local Multicast Name Resolution (LLMNR)
REG ADD  "HKLM\Software\policies\Microsoft\Windows NT\DNSClient"
REG ADD  "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d "0" /f

# Run Local Security Authority Server Service (LSASS) as a protected process
bcdedit /enum {current} 2>nul | findstr /i "winload.efi" >nul && set v=1 || set v=2
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d %v% /f >nul

# Disable Depreciated SSL 2.0 and 3.0 and TLS 1.0 1.1 

REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v Enabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSl 2.0\Server" /v Enabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v Enabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSl 3.0\Server" /v Enabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v Enabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v Enabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v Enabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v Enabled /t REG_DWORD /d 0 /f

# SMBv3 signing and encryption should be enabled
powershell.exe -NoProfile -Command "Set-SmbServerConfiguration -RequireSecuritySignature $true -EncryptData $true -EnableSecuritySignature $true -Confirm:$false"