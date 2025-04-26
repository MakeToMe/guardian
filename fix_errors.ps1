$filePath = "internal\collector\system.go"
$content = Get-Content $filePath -Raw

# 1. Corrigir a variável indiceInicio indefinida
$content = $content -replace "indiceInicio = 0", "var indiceInicio int = 0"

# 2. Remover as variáveis virt declaradas mas não utilizadas
$content = $content -replace "virt := `"`"", "// virt := `"`""
$content = $content -replace "virt = campos\[4\]", "// virt = campos[4]"

# 3. Corrigir referências a MemoryUsage para MemoryUsageMB
$content = $content -replace "processInfo\.MemoryUsage", "processInfo.MemoryUsageMB"
$content = $content -replace "proc\.MemoryUsage", "proc.MemoryUsageMB"

# 4. Corrigir referências a MemPercent para MemoryPercent
$content = $content -replace "proc\.MemPercent", "proc.MemoryPercent"
$content = $content -replace "memPercent,", "memoryPercent,"

# Escrever o conteúdo corrigido de volta ao arquivo
$content | Set-Content $filePath -Encoding UTF8

Write-Host "Correções aplicadas com sucesso!"
