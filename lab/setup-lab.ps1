# lab/setup-lab.ps1 (Phase 4.1): the delegation that decides what the agent can change (SolutionDesign.md section 5).
#   -Part Delegation   on DC01, elevated: grant AI-Operators exactly the v1 write rights, nothing else
#   -Part EventSource  on CLIENT01, elevated: register the "admcp" Application event-log source (admcp/calllog.py)
# Idempotent. Never grants anything on _ADMINS, privileged groups, the Domain Controllers OU or the domain root.
#
# Known gap to test in the campaign: userAccountControl is the whole flag word. Write access to it lets the holder set
# any flag (DONT_REQ_PREAUTH, PASSWD_NOTREQD...), not only ACCOUNTDISABLE. ad_disable_account only disables, but a
# bypass path (S-1, Claude Code's own shell) holds the same right. Check what DC01's 4738 events show when it happens.
param([Parameter(Mandatory)][ValidateSet("Delegation", "EventSource", "Service")][string]$Part)
$ErrorActionPreference = "Stop"

if ($Part -eq "EventSource") {
    if (-not [System.Diagnostics.EventLog]::SourceExists("admcp")) { New-EventLog -LogName Application -Source "admcp" }
    Write-Output "admcp event source registered on $env:COMPUTERNAME"
    return
}

Import-Module ActiveDirectory
$domain = Get-ADDomain
$who = "$($domain.NetBIOSName)\AI-Operators"

if ($Part -eq "Service") {
    # D17 (Lab 1, 1 Nov 2026): ad_create_service_account. OU _SERVICE, and on it only: create user objects, plus reset
    # password and write userAccountControl on the users inside (so the tool can set a random password and enable).
    # An audit SACL (Everyone, success: create child + write property) makes every change there log 5136.
    $svc = "OU=_SERVICE,$($domain.DistinguishedName)"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$svc'")) {
        New-ADOrganizationalUnit -Name "_SERVICE" -Path $domain.DistinguishedName `
            -Description "Application service accounts. The AD agent may create accounts here and nowhere else (D17)"
    }
    foreach ($r in @(@{ i = "T"; g = "CC;user" }, @{ i = "S"; g = "CA;Reset Password;user" }, @{ i = "S"; g = "WP;userAccountControl;user" })) {
        dsacls $svc /I:$($r.i) /G "${who}:$($r.g)" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "dsacls failed ($LASTEXITCODE) granting $($r.g) on $svc" }
        Write-Output "granted $who $($r.g) on $svc (/I:$($r.i))"
    }
    $acl = Get-Acl "AD:$svc" -Audit
    $everyone = New-Object Security.Principal.SecurityIdentifier "S-1-1-0"
    $acl.AddAuditRule((New-Object DirectoryServices.ActiveDirectoryAuditRule $everyone,
        ([DirectoryServices.ActiveDirectoryRights]"CreateChild, WriteProperty, WriteDacl, WriteOwner"),
        ([Security.AccessControl.AuditFlags]"Success"), ([DirectoryServices.ActiveDirectorySecurityInheritance]"All")))
    Set-Acl "AD:$svc" $acl
    Write-Output "audit SACL on ${svc}: Everyone, success, create child + write property + write DACL + write owner"
    return
}
# Groups is found by name, as phase0-dc01.ps1 does: it is not guaranteed to sit at the domain root
$groupsOU = @(Get-ADOrganizationalUnit -Filter "Name -eq 'Groups'")
if ($groupsOU.Count -ne 1) { throw "Expected exactly one OU named Groups, found $($groupsOU.Count)" }
$grants = @(
    @{ ou = "OU=_USERS,$($domain.DistinguishedName)"; right = "WP;lockoutTime;user" },         # ad_unlock_account
    @{ ou = "OU=_USERS,$($domain.DistinguishedName)"; right = "WP;userAccountControl;user" },  # ad_disable_account
    @{ ou = $groupsOU[0].DistinguishedName;           right = "WP;member;group" }              # ad_add_group_member
)
foreach ($g in $grants) {
    Get-ADOrganizationalUnit -Identity $g.ou | Out-Null   # stops here, loudly, if the OU is missing
    dsacls $g.ou /I:S /G "${who}:$($g.right)" | Out-Null   # /I:S = inherited by child objects of that class only
    if ($LASTEXITCODE -ne 0) { throw "dsacls failed ($LASTEXITCODE) granting $($g.right) on $($g.ou)" }
    Write-Output "granted $who $($g.right) on $($g.ou)"
}
