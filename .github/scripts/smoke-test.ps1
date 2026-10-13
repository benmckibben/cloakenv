# Smoke-test the Windows release archive: extract it and run the real binary
# through an init / set / list / run round trip in a throwaway directory.
#
#   smoke-test.ps1 -Archive ARCHIVE.zip -Version X.Y.Z
#
# The Windows counterpart of smoke-test.sh. Everything here is dummy data: a
# made-up passphrase and a made-up "secret", in a temp directory that is deleted
# afterwards. Nothing leaves the machine.
param(
  [Parameter(Mandatory = $true)][string]$Archive,
  [Parameter(Mandatory = $true)][string]$Version
)
$ErrorActionPreference = 'Stop'

function Fail([string]$message) {
  Write-Host "::error::smoke test failed: $message"
  exit 1
}

$Archive = (Resolve-Path $Archive).Path
$work = Join-Path ([IO.Path]::GetTempPath()) ("cloakenv-smoke-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
  Expand-Archive -Path $Archive -DestinationPath $work
  $exe = Get-ChildItem -Path $work -Recurse -Filter cloakenv.exe | Select-Object -First 1
  if (-not $exe) { Fail "no cloakenv.exe in $Archive" }
  $dir = $exe.DirectoryName
  foreach ($f in 'README.md', 'LICENSE-MIT', 'LICENSE-APACHE', 'CHANGELOG.md') {
    if (-not (Test-Path (Join-Path $dir $f))) { Fail "$f is missing from the archive" }
  }
  $exe = $exe.FullName

  $got = (& $exe --version) -join ''
  Write-Host $got
  if ($got -ne "cloakenv $Version") { Fail "expected 'cloakenv $Version', got '$got'" }

  $proj = Join-Path $work 'project'
  New-Item -ItemType Directory -Path $proj | Out-Null
  Set-Location $proj
  $env:CLOAKENV_PASSPHRASE = 'smoke-test passphrase, not a real one'
  Remove-Item Env:CLOAKENV_PASSPHRASE_FILE, Env:CLOAKENV_VAULT -ErrorAction SilentlyContinue
  $secret = 'sk-smoke-SECRET-0042'

  & $exe init
  if ($LASTEXITCODE -ne 0) { Fail "init exited $LASTEXITCODE" }
  if (-not (Test-Path '.cloak/vault.bin')) { Fail 'init did not create .cloak/vault.bin' }
  if ((Get-Content '.cloak/.gitignore' -Raw).Trim() -ne '*') { Fail 'init did not write .cloak/.gitignore' }

  $secret | & $exe set SMOKE_SECRET
  if ($LASTEXITCODE -ne 0) { Fail "set exited $LASTEXITCODE" }

  # The vault is encrypted: neither the value nor the name is in the file.
  $text = [Text.Encoding]::Latin1.GetString([IO.File]::ReadAllBytes((Resolve-Path '.cloak/vault.bin')))
  if ($text.Contains($secret) -or $text.Contains('SMOKE_SECRET')) { Fail 'the vault file contains the secret or its name in clear' }

  $listed = (& $exe list) -join ','
  if ($listed -ne 'SMOKE_SECRET') { Fail "list printed '$listed'" }

  # run injects the value; there is no exec on Windows, cloakenv stays the parent.
  $injected = ((& $exe run -- cmd /c 'echo %SMOKE_SECRET%') -join '').Trim()
  if ($injected -ne $secret) { Fail 'the secret was not injected' }

  # The passphrase never reaches the command (cmd leaves an unset %VAR% as is).
  $leaked = ((& $exe run -- cmd /c 'echo %CLOAKENV_PASSPHRASE%') -join '').Trim()
  if ($leaked -ne '%CLOAKENV_PASSPHRASE%') { Fail 'CLOAKENV_PASSPHRASE reached the command' }

  # --shield redacts the value from stdout and from stderr.
  $out = ((& $exe run --shield -- cmd /c 'echo out:%SMOKE_SECRET%') -join '').Trim()
  Write-Host $out
  if ($out -ne 'out:[REDACTED_BY_CLOAKENV]') { Fail "--shield did not redact stdout: '$out'" }
  $err = ((& $exe run --shield -- cmd /c 'echo err:%SMOKE_SECRET% 1>&2' 2>&1) | Out-String).Trim()
  Write-Host $err
  if ($err -notmatch [regex]::Escape('err:[REDACTED_BY_CLOAKENV]') -or $err.Contains($secret)) { Fail "--shield did not redact stderr: '$err'" }

  # Exit codes pass through, with and without --shield, including above 255.
  foreach ($code in 7, 1000) {
    & $exe run -- cmd /c "exit $code"
    if ($LASTEXITCODE -ne $code) { Fail "run: expected exit code $code, got $LASTEXITCODE" }
    & $exe run --shield -- cmd /c "exit $code"
    if ($LASTEXITCODE -ne $code) { Fail "run --shield: expected exit code $code, got $LASTEXITCODE" }
  }

  # Fail closed: a wrong passphrase starts nothing and exits 125.
  $env:CLOAKENV_PASSPHRASE = 'the wrong passphrase'
  & $exe run -- cmd /c 'echo.>ran-anyway' 2>$null
  if ($LASTEXITCODE -ne 125) { Fail "wrong passphrase: expected exit code 125, got $LASTEXITCODE" }
  if (Test-Path 'ran-anyway') { Fail 'the command ran despite a wrong passphrase' }

  Write-Host 'smoke test passed'
  # pwsh -command exits with the last native command's code, which here is the
  # deliberate wrong-passphrase run (125); say explicitly that all is well.
  exit 0
}
finally {
  Set-Location $env:RUNNER_TEMP
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
