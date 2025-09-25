# gMSA Creation Script
# This script creates a Group Managed Service Account (gMSA) in Active Directory.
# Pre-requisites:
# Create a Global Security Group in AD and add the computer accounts of the servers that will use the gMSA.

#1. Set Name Variables
$Domain_FQDN = "Domain.com";                               # Fully Qualified Domain Name of the domain
$GMSA_Group = "gMSA_Servers";                           # Name of the Global Security Group Created in AD
$GMSA_Name = "gMDSA_Acct";                              # Name of the gMSA account to create !15 CHAR MAX!
$GMSA_Desc = "GMSA Account/Group for $GMSA_Group";      # Description for the gMSA account

#2. Create KDS Root Key (if not already created)
# Note: It can take up to 10 hours for the key to replicate across all DCs
Add-KdsRootKey -EffectiveTime ((get-date).addhours(-10));

#3. Create GMSA account (SAM/NAME Must be no more than 15 chars)
$GMSA_Servers = Get-ADGroupMember -Identity $GMSA_Group | Select-Object -ExpandProperty Name;
$GMSA_Server_IDs = $GMSA_Servers | ForEach-Object { (Get-ADComputer -Identity $_).DistinguishedName };

New-ADServiceAccount -Name $GMSA_Name -Enabled $true -Description $GMSA_Desc `
    -DisplayName $GMSA_Name -PrincipalsAllowedToRetrieveManagedPassword $GMSA_Server_IDs `
    -DNSHostName "$GMSA_Name.$Domain_FQDN";

