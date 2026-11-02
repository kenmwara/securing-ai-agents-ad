# ad_create_service_account: create one application service account in OU=_SERVICE. CHANGES something (D17, Lab 1).
# Needs Create User objects on OU=_SERVICE plus Reset Password and write userAccountControl on users there, delegated to
# AI-Operators by lab/setup-lab.ps1. The password is random, set here and thrown away: the agent never sees, returns or
# logs it (credential-free, D2). Nothing beyond name, description and the password is set, so the account carries the
# domain's defaults; Lab 1 measures what those defaults are. JSON in on stdin ({"name": "svc-...", "description": "..."}).
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
