$ErrorActionPreference = "Stop"
$manifestPath = "C:\Users\user\.gemini\antigravity\scratch\rag-revisoria-fiscal\data\drive_manifest.json"
$outDir = "C:\Users\user\.gemini\antigravity\scratch\rag-revisoria-fiscal\data\raw"
$files = Get-Content -Raw -Path $manifestPath | ConvertFrom-Json

foreach ($file in $files) {
    $safeName = $file.name -replace '[,]', ''
    $targetPath = Join-Path $outDir $file.name
    if (-not (Test-Path -LiteralPath $targetPath)) {
        Write-Host "Downloading $($file.name) ($($file.id))..."
        gdrive readonly download $file.id --out "$targetPath"
    } else {
        Write-Host "Already exists: $($file.name)"
    }
}
Write-Host "All files synchronized successfully."
