param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $DevArgs
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
& python (Join-Path $Root "tools/dev.py") @DevArgs
