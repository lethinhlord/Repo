param(
    [Parameter(Mandatory=$true)][string]$Directory,
    [string]$ExpectedRepository = 'https://github.com/lethinhlord/Repo.git'
)
# Transfer verification only. Restore validation is performed by the collector;
# both its receipt and every transferred byte are checked here before PASS.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
try {
    $resolved = (Resolve-Path -LiteralPath $Directory).ProviderPath
    $items = @(Get-ChildItem -LiteralPath $resolved -Force)
    if (@($items | Where-Object { $_.PSIsContainer -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }).Count -ne 0) {
        throw 'Unexpected directory or link in backup'
    }
    $inventory = Join-Path $resolved 'checksums.sha256'
    $lines = @(Get-Content -LiteralPath $inventory)
    if ($lines.Count -eq 0) { throw 'Checksum inventory is empty' }
    $entries = @{}
    foreach ($line in $lines) {
        if ($line -notmatch '^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$') { throw 'Invalid checksum inventory line' }
        $expected = $Matches[1]; $name = $Matches[2]
        if ($entries.ContainsKey($name) -or $name -eq 'checksums.sha256') { throw 'Duplicate or self-checksummed entry' }
        $file = Get-Item -LiteralPath (Join-Path $resolved $name)
        if ($file.Length -le 0) { throw "Empty backup component: $name" }
        if ((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
            throw "Hash mismatch: $name"
        }
        $entries[$name] = $expected
    }
    $report = Get-Content -LiteralPath (Join-Path $resolved 'restore-report.json') -Raw | ConvertFrom-Json
    $archive = [string]$report.archive
    if ($archive -notmatch '^collection-[A-Za-z0-9_-]+\.tar\.gz$') { throw 'Invalid archive name' }
    $required = @($archive, 'git-commit.txt', 'source-tag.txt', 'source-tag-object.txt', 'source-url.txt', 'restore-report.json')
    if ($entries.Count -ne $required.Count) { throw 'Incomplete or unexpected checksum inventory' }
    foreach ($name in $required) {
        if (-not $entries.ContainsKey($name)) { throw "Missing required component: $name" }
    }
    if ($items.Count -ne ($required.Count + 1)) { throw 'Unlisted backup components' }
    if ($report.status -ne 'BACKUP_RESTORED_AND_VALIDATED' -or $report.archive_sha256 -ne $entries[$archive]) {
        throw 'Restore receipt does not bind the transferred archive'
    }
    $runs = @($report.validated_runs)
    if ($runs.Count -eq 0 -or @($runs | Select-Object -Unique).Count -ne $runs.Count) {
        throw 'Restore receipt has no unique validated run inventory'
    }
    foreach ($run in $runs) {
        if ($run -isnot [string] -or $run -notmatch '^[A-Za-z0-9_-]+$') { throw 'Invalid validated run ID' }
    }
    $commit = (Get-Content -LiteralPath (Join-Path $resolved 'git-commit.txt') -Raw).Trim()
    $tag = (Get-Content -LiteralPath (Join-Path $resolved 'source-tag.txt') -Raw).Trim()
    $tagObject = (Get-Content -LiteralPath (Join-Path $resolved 'source-tag-object.txt') -Raw).Trim()
    $origin = (Get-Content -LiteralPath (Join-Path $resolved 'source-url.txt') -Raw).Trim()
    if ($commit -notmatch '^[0-9a-f]{40}$' -or $tagObject -notmatch '^[0-9a-f]{40}$' -or
        $tag -notmatch '^[A-Za-z0-9._/-]+$' -or $origin -ne $ExpectedRepository -or
        $report.candidate.commit -ne $commit -or $report.candidate.tag -ne $tag -or
        $report.candidate.tag_object -ne $tagObject -or $report.candidate.origin -ne $origin) {
        throw 'Source metadata does not match restore receipt and expected repository'
    }
    'HOST_BACKUP_VERIFY=PASS'
    exit 0
} catch {
    [Console]::Error.WriteLine("HOST_BACKUP_VERIFY=FAIL: $($_.Exception.Message)")
    exit 1
}
