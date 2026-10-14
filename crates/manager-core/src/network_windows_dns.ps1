# This fixed script is passed as EncodedCommand. Input is data from stdin;
# no profile, command text, GPO name, remote session or executable is accepted.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$PSModuleAutoLoadingPreference = 'None'
$env:PSModulePath = ''
$env:PATH = ''
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Microsoft.PowerShell.Core\Import-Module ([IO.Path]::Combine($PSHOME, 'Modules', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module ([IO.Path]::Combine($PSHOME, 'Modules', 'DnsClient', 'DnsClient.psd1')) -ErrorAction Stop

function Canonical($value) {
    $result = [ordered]@{}
    $names = [string[]]@($value.CimInstanceProperties.Name)
    [Array]::Sort($names, [StringComparer]::Ordinal)
    foreach ($name in $names) { $result[$name] = $value.CimInstanceProperties[$name].Value }
    return Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $result -Depth 10 -Compress
}
function Servers($value) {
    $servers = [Collections.Generic.List[string]]::new()
    foreach ($item in @($value.NameServers)) {
        foreach ($server in ([string]$item -split '[;,\s]+')) {
            if ($server.Length -gt 0) { $servers.Add($server) }
        }
    }
    return $servers.ToArray()
}
function View($value, [bool]$local) {
    $name = ''; $displayName = ''; $comment = ''
    if ($local) { $name = [string]$value.Name; $displayName = [string]$value.DisplayName; $comment = [string]$value.Comment }
    return [ordered]@{ name = $name; namespaces = @($value.Namespace); servers = @(Servers $value); displayName = $displayName; comment = $comment; canonical = (Canonical $value) }
}
function ReadPolicy {
    $local = @(DnsClient\Get-DnsClientNrptRule -ErrorAction Stop)
    $effective = @(DnsClient\Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)
    if ($local.Count -gt 512 -or $effective.Count -gt 512) { throw 'NRPT policy exceeds limit' }
    $localViews = @($local | Microsoft.PowerShell.Core\ForEach-Object { View $_ $true })
    $effectiveViews = @($effective | Microsoft.PowerShell.Core\ForEach-Object { View $_ $false })
    return [ordered]@{ local = $localViews; effective = $effectiveViews }
}
function Overlap([string]$existing, [string]$wanted) {
    $existing = $existing.TrimStart('.').ToLowerInvariant()
    $wanted = $wanted.TrimStart('.')
    if ($existing.Length -eq 0 -or $existing -notmatch '^[a-z0-9-]+(\.[a-z0-9-]+)*$') { return $true }
    return ($existing -eq $wanted -or $existing.EndsWith('.' + $wanted, [StringComparison]::Ordinal) -or $wanted.EndsWith('.' + $existing, [StringComparison]::Ordinal))
}
function Hash([string]$canonical) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
try {
    $text = [Console]::In.ReadToEnd()
    if ($text.Length -gt 16384) { throw 'NRPT request exceeds limit' }
    $request = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $text
    if ($request.operation -notin @('inspect', 'apply', 'remove')) { throw 'invalid operation' }
    $wanted = $request.desired
    if (@($wanted.namespaces).Count -lt 1 -or @($wanted.namespaces).Count -gt 32 -or @($wanted.servers).Count -lt 1 -or @($wanted.servers).Count -gt 4) { throw 'invalid DNS bounds' }
    foreach ($namespace in @($wanted.namespaces)) {
        if ($namespace.Length -gt 254 -or $namespace -cnotmatch '^\.[a-z0-9-]+(\.[a-z0-9-]+)*$') { throw 'invalid suffix' }
    }
    foreach ($server in @($wanted.servers)) {
        $address = $null
        if (-not [Net.IPAddress]::TryParse($server, [ref]$address) -or $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $address.ToString() -cne $server) { throw 'invalid name server' }
    }
    if ($wanted.displayName -cnotmatch '^OpenFortiVPN Manager [a-f0-9]{64}$' -or $wanted.comment -cne 'openfortivpn-manager scoped-dns v1') { throw 'invalid ownership marker' }
    $policy = ReadPolicy
    $owned = @($policy.local | Microsoft.PowerShell.Core\Where-Object { $_.displayName -ceq $wanted.displayName })
    if ($owned.Count -gt 1) { throw 'duplicate owned rule' }
    # Check inside this operation immediately before writes as well as in Rust.
    foreach ($rule in @($policy.local) + @($policy.effective)) {
        if ($rule.displayName -ceq $wanted.displayName) { continue }
        foreach ($namespace in @($rule.namespaces)) {
            foreach ($suffix in @($wanted.namespaces)) {
                if (Overlap $namespace $suffix) {
                    # Effective rows lack ownership metadata. An exact local
                    # rule must exist; Rust validates effective values on readback.
                    if ($rule.name.Length -gt 0 -or $owned.Count -eq 0) { throw 'conflicting NRPT policy' }
                }
            }
        }
    }
    if ($request.operation -eq 'apply') {
        if ($owned.Count -ne 0) { throw 'rule already exists' }
        $null = DnsClient\Add-DnsClientNrptRule -Namespace ([string[]]$wanted.namespaces) -NameServers ([string[]]$wanted.servers) -NameEncoding Punycode -DisplayName ([string]$wanted.displayName) -Comment ([string]$wanted.comment) -ErrorAction Stop
        $policy = ReadPolicy
    } elseif ($request.operation -eq 'remove') {
        if ($owned.Count -ne 1 -or $request.expectedHash -cnotmatch '^[a-f0-9]{64}$' -or (Hash $owned[0].canonical) -cne $request.expectedHash) { throw 'owned rule changed' }
        $null = DnsClient\Remove-DnsClientNrptRule -Name ([string]$owned[0].name) -Force -ErrorAction Stop
        $policy = ReadPolicy
    }
    [Console]::Out.Write((Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $policy -Depth 12 -Compress))
    exit 0
} catch {
    # Do not echo arbitrary CIM/system errors or request data to logs.
    [Console]::Error.Write('NRPT operation failed')
    exit 1
}
