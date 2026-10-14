#!/usr/bin/env python3
"""Execute the compiled-in NRPT script with an isolated mock DnsClient module.

This checks real PowerShell serialization, parameter binding and guarded
mutations. It never imports Windows DnsClient, changes DNS, or implies Windows
platform acceptance. Run with --powershell /absolute/path/to/pwsh.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


MOCK = r'''
Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @'
using System.Collections.Generic;
public sealed class TestProperty { public string Name; public object Value; }
public sealed class TestProperties : List<TestProperty> {
    public TestProperty this[string name] { get { return Find(p => p.Name == name); } }
}
'@
function ReadRules {
    $text = [IO.File]::ReadAllText($env:OFV_NRPT_TEST_STATE)
    # Windows PowerShell 5.1 emits a JSON array as one pipeline object;
    # PowerShell 7 enumerates it. Explicit iteration handles both versions.
    $rules = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $text
    foreach ($rule in $rules) { $rule }
}
function WriteRules($rules) {
    $text = Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject @($rules) -Depth 12 -Compress
    [IO.File]::WriteAllText($env:OFV_NRPT_TEST_STATE, $text)
}
function Object($properties) {
    $items = [TestProperties]::new()
    $result = [ordered]@{}
    foreach ($property in $properties.PSObject.Properties) {
        $item = [TestProperty]::new(); $item.Name = $property.Name; $item.Value = $property.Value
        $items.Add($item); $result[$property.Name] = $property.Value
    }
    $result['CimInstanceProperties'] = $items
    return [pscustomobject]$result
}
function Get-DnsClientNrptRule {
    [CmdletBinding()] param()
    foreach ($rule in @(ReadRules)) { Object $rule }
}
function Get-DnsClientNrptPolicy {
    [CmdletBinding()] param([switch]$Effective)
    foreach ($rule in @(ReadRules)) { Object $rule }
}
function Add-DnsClientNrptRule {
    [CmdletBinding()] param([string[]]$Namespace, [string[]]$NameServers, [string]$NameEncoding, [string]$DisplayName, [string]$Comment)
    $rules = @(ReadRules)
    $new = [pscustomobject][ordered]@{
        Name = '{11111111-1111-1111-1111-111111111111}'; Version = 2
        Namespace = $Namespace; NameServers = ($NameServers -join ';')
        NameEncoding = $NameEncoding; DisplayName = $DisplayName; Comment = $Comment
        DirectAccessEnabled = $false; DnsSecEnabled = $false
        DnsSecValidationRequired = $null; DnsSecQueryIPsecRequired = $null
        DirectAccessQueryIPsecRequired = $null
    }
    WriteRules @($rules + @($new))
}
function Remove-DnsClientNrptRule {
    [CmdletBinding()] param([string]$Name, [switch]$Force)
    $rules = @(ReadRules | Microsoft.PowerShell.Core\Where-Object { $_.Name -cne $Name })
    WriteRules $rules
}
Microsoft.PowerShell.Core\Export-ModuleMember -Function Get-DnsClientNrptRule, Get-DnsClientNrptPolicy, Add-DnsClientNrptRule, Remove-DnsClientNrptRule
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--powershell", required=True, type=Path)
    args = parser.parse_args()
    executable = args.powershell.resolve(strict=True)
    source = Path(__file__).resolve().parents[1] / "src/network_windows_dns.ps1"
    source_text = source.read_text()
    imports = "Microsoft.PowerShell.Core\\Import-Module ([IO.Path]::Combine($PSHOME, 'Modules', 'DnsClient', 'DnsClient.psd1')) -ErrorAction Stop"
    assert source_text.count(imports) == 1
    wanted = {
        "luid": 42, "namespaces": [".corp.example"], "servers": ["10.0.0.53", "10.0.0.54"],
        "displayName": "OpenFortiVPN Manager " + "a" * 64,
        "comment": "openfortivpn-manager scoped-dns v1",
    }
    with tempfile.TemporaryDirectory(prefix="ofv-nrpt-mock-") as temporary:
        root = Path(temporary)
        module = root / "DnsClient.psm1"
        module.write_text(MOCK)
        script = root / "nrpt.ps1"
        quoted_module = str(module).replace("'", "''")
        test_source = source_text.replace(imports, f"Microsoft.PowerShell.Core\\Import-Module '{quoted_module}' -ErrorAction Stop")
        # Only this synthetic fixture may expose exception details. Production
        # keeps its fixed error envelope and never logs request/CIM contents.
        test_source = test_source.replace(
            "[Console]::Error.Write('NRPT operation failed')",
            "[Console]::Error.Write(($_ | Microsoft.PowerShell.Utility\\Out-String))",
        )
        script.write_text(test_source)
        state = root / "state.json"
        state.write_text("[]")
        env = os.environ.copy()
        env["OFV_NRPT_TEST_STATE"] = str(state)

        def run(operation, expected=None, successful=True):
            request = {"operation": operation, "desired": wanted, "expectedHash": expected}
            result = subprocess.run(
                [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script)],
                input=json.dumps(request).encode(), capture_output=True, env=env, timeout=30,
            )
            if successful:
                assert result.returncode == 0, result.stderr.decode(errors="replace")
                assert not result.stderr, result.stderr
                return json.loads(result.stdout)
            assert result.returncode != 0
            return result

        assert run("inspect") == {"local": [], "effective": []}
        created = run("apply")
        assert len(created["local"]) == len(created["effective"]) == 1
        local = created["local"][0]
        assert local["namespaces"] == wanted["namespaces"]
        assert local["servers"] == wanted["servers"], "PowerShell must emit flat server arrays"
        canonical = local["canonical"]
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        assert json.loads(canonical)["DisplayName"] == wanted["displayName"]
        before = state.read_bytes()
        run("remove", "0" * 64, successful=False)
        assert state.read_bytes() == before, "fingerprint mismatch must preserve owned rule"
        rules = json.loads(state.read_text())
        rules[0]["FuturePolicyProperty"] = "external edit"
        state.write_text(json.dumps(rules))
        edited = state.read_bytes()
        run("remove", digest, successful=False)
        assert state.read_bytes() == edited, "unknown external edits must block removal"
        inspected = run("inspect")
        digest = hashlib.sha256(inspected["local"][0]["canonical"].encode()).hexdigest()
        assert run("remove", digest) == {"local": [], "effective": []}

        for namespace in [".example", ".dev.corp.example", "corp.example", ".", "*"]:
            foreign = json.loads(canonical)
            foreign["DisplayName"] = "external"; foreign["Namespace"] = [namespace]
            state.write_text(json.dumps([foreign]))
            before = state.read_bytes()
            run("apply", successful=False)
            assert state.read_bytes() == before, "overlap must block before mutation"
        state.write_text("[]")
        created = run("apply")
        rules = json.loads(state.read_text())
        state.write_text(json.dumps(rules + rules))
        run("inspect", successful=False)
    print("NRPT mock cmdlet matrix passed: real PowerShell transport, no host DNS changes")


if __name__ == "__main__":
    main()
