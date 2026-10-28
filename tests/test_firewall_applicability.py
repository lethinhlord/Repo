"""Firewall filters must intersect on one actual adapter, not different NICs."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1]/'scripts/Test-DatnWindowsPreflight.ps1'
ADAPTERS = [
    {'Name':'Lab', 'Profile':'Private', 'InterfaceType':'Lan',
     'Addresses':['10.20.0.10', 'fe80::1']},
    {'Name':'Management', 'Profile':'Public', 'InterfaceType':'Lan',
     'Addresses':['192.168.58.148']},
]
CASES = [
    ('Private','Lab','Any','Any','APPLIES'),
    ('Public','Lab','Any','Any','NOT_APPLICABLE'),
    ('Private','Management','Any','Any','NOT_APPLICABLE'),
    ('Private','Lab','192.168.58.148','Any','NOT_APPLICABLE'),
    ('Private','Lab','10.20.0.0/24','Lan','APPLIES'),
    ('Private','Lab','10.21.0.0/24','Any','NOT_APPLICABLE'),
    ('Private','Lab','fe80::/64','Any','APPLIES'),
    ('Private','Lab','::1/128','Any','NOT_APPLICABLE'),
    ('Any','*','Any','Wireless','NOT_APPLICABLE'),
    ('Private','Lab','UnresolvedDynamicScope','Any','INCONCLUSIVE'),
    ('Private','Lab','10.20.0.1-10.20.0.20','Any','APPLIES'),
]


@pytest.mark.parametrize('profile,alias,address,interface_type,expected', CASES)
def test_rule_applicability_intersects_profile_interface_type_and_local_ip(
    tmp_path, profile, alias, address, interface_type, expected,
):
    shell = shutil.which('powershell.exe')
    if shell is None:
        pytest.skip('Windows PowerShell 5.1 unavailable')
    source = tmp_path/'case.json'
    source.write_text(json.dumps({'Adapters':ADAPTERS, 'Profiles':[profile],
        'InterfaceAliases':[alias], 'LocalAddresses':[address],
        'InterfaceTypes':[interface_type]}), encoding='utf-8')
    environment = {**os.environ, 'DATN_SCRIPT':str(SCRIPT), 'DATN_CASE':str(source)}
    command = r'''
$ErrorActionPreference='Stop'
. $env:DATN_SCRIPT
$case = Get-Content -LiteralPath $env:DATN_CASE -Raw | ConvertFrom-Json
$result = Get-DatnFirewallRuleApplicability -Adapters $case.Adapters -Profiles $case.Profiles `
  -InterfaceAliases $case.InterfaceAliases -LocalAddresses $case.LocalAddresses `
  -InterfaceTypes $case.InterfaceTypes
$result | ConvertTo-Json -Compress
'''
    result = subprocess.run([shell,'-NoProfile','-NonInteractive','-Command',command],
        env=environment, text=True, capture_output=True, timeout=20, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['Status'] == expected
