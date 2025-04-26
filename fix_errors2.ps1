$filePath = "internal\collector\system.go"
$content = Get-Content $filePath -Raw

# 1. Corrigir referências a memPercent para memoryPercent
$content = $content -replace "memPercent\)", "memoryPercent)"
$content = $content -replace "memPercent ==", "memoryPercent =="
$content = $content -replace "memPercent,", "memoryPercent,"

# 2. Corrigir referência incorreta a MemoryUsageMBMB
$content = $content -replace "processInfo\.MemoryUsageMBMB", "processInfo.MemoryUsageMB"

# Escrever o conteúdo corrigido de volta ao arquivo
$content | Set-Content $filePath -Encoding UTF8

Write-Host "Correções adicionais aplicadas com sucesso!"
