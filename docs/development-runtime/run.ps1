# Offline development inference through Docker Linux. Compatible with Windows PowerShell5.1/7.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Archive,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$Sha256,
    [Parameter(Mandatory=$true)][string]$Records,
    [Parameter(Mandatory=$true)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
$archivePath = (Resolve-Path -LiteralPath $Archive).ProviderPath
$recordsPath = (Resolve-Path -LiteralPath $Records).ProviderPath
foreach ($inputPath in @($archivePath, $recordsPath)) {
    if (-not (Test-Path -LiteralPath $inputPath -PathType Leaf)) { throw "Not a file: $inputPath" }
}
$destination = [IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $destination) { throw "Output already exists: $destination" }
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).ProviderPath
$server = & docker info --format '{{.OSType}}'
if ($LASTEXITCODE -ne 0 -or $server -ne 'linux') {
    throw 'Start Docker Desktop with Linux containers, then retry.'
}
# BuildKit uses Dockerfile.dockerignore: only the lock and runner enter the build context.
$image = & docker build --quiet --file (Join-Path $PSScriptRoot 'Dockerfile') $repo
if ($LASTEXITCODE -ne 0 -or $image -notmatch '^sha256:[0-9a-f]{64}$') {
    throw 'Docker image build failed; no inference output was written.'
}
$arguments = @(
    'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--pids-limit', '128', '--memory', '1g', '--cpus', '2',
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
    '--mount', ('type=bind,"source=' + $archivePath + '",target=/input/model.tar.gz,readonly'),
    '--mount', ('type=bind,"source=' + $recordsPath + '",target=/input/records.jsonl,readonly'),
    $image, '--archive', '/input/model.tar.gz', '--sha256', $Sha256,
    '--records', '/input/records.jsonl'
)
$lines = & docker @arguments
if ($LASTEXITCODE -ne 0) { throw 'Docker inference failed; no inference output was written.' }
$text = $lines -join "`n"
$result = $text | ConvertFrom-Json
if ($result.status -ne 'DEVELOPMENT_INFERENCE_COMPLETE' -or
    $result.automation_eligible -ne $false -or $result.deployment_eligible -ne $false) {
    throw 'Invalid development inference result.'
}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
$bytes = [Text.UTF8Encoding]::new($false).GetBytes($text + "`n")
$stream = [IO.File]::Open($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
Write-Output "Saved $($result.record_count) development predictions: $destination"
Write-Output "Docker image: $image"
