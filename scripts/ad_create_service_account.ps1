# ad_create_service_account: create one application service account in OU=_SERVICE. CHANGES something (D17, Lab 1).
# Needs Create User objects on OU=_SERVICE plus Reset Password and write userAccountControl on users there, delegated to
# AI-Operators by lab/setup-lab.ps1. The password is random, set here and thrown away: the agent never sees, returns or
# logs it (credential-free, D2). Nothing else is set: Kerberos encryption comes from the DC's default, AES-only since the
# Lab 1 fix (DefaultDomainSupportedEncTypes 0x18). Setting msDS-SupportedEncryptionTypes here was tried and dropped: the
# agent has no write right on that attribute, New-ADUser fails partway and leaves a disabled half-made account, and
# granting the right would also let the agent set RC4 back. The OWNER RIGHTS entry on OU=_SERVICE (lab/setup-lab.ps1
# -Part Service) stops the agent, as creator and owner, from rewriting the account's permissions.
# JSON in on stdin ({"name": "svc-...", "description": "..."}).
$ErrorActionPreference = 'Stop'
try {
    $a = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $name = "$($a.name)"; $desc = "$($a.description)"
    if ($name -notmatch '^svc-[a-z0-9-]{2,16}$') { throw 'name must be svc- followed by 2-16 lowercase letters, digits or hyphens' }
    if ($desc -notmatch '^[A-Za-z0-9 .,()/_-]{0,120}$') { throw 'description has characters that are not allowed (max 120)' }
    Import-Module ActiveDirectory -ErrorAction Stop
    $ou = "OU=_SERVICE,$((Get-ADDomain).DistinguishedName)"
    $chars = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+=?'
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $pw = ConvertTo-SecureString (-join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })) -AsPlainText -Force
    New-ADUser -Name $name -SamAccountName $name -UserPrincipalName "$name@$((Get-ADDomain).DNSRoot)" -Path $ou `
        -Description $desc -AccountPassword $pw -Enabled $true
    $pw.Dispose()
    $u = Get-ADUser -Identity $name -Properties Created, Enabled, PasswordNeverExpires, pwdLastSet, servicePrincipalName,
        'msDS-SupportedEncryptionTypes', nTSecurityDescriptor
    [pscustomobject]@{
        user = $u.SamAccountName; dn = $u.DistinguishedName; enabled = [bool]$u.Enabled
        created = $u.Created.ToUniversalTime().ToString('o'); passwordNeverExpires = [bool]$u.PasswordNeverExpires
        spns = @($u.servicePrincipalName); supportedEncryptionTypes = $u.'msDS-SupportedEncryptionTypes'
        owner = $u.nTSecurityDescriptor.Owner
    } | ConvertTo-Json
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
