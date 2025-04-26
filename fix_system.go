package fix

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	// Ler o arquivo original
	filePath := filepath.Join("internal", "collector", "system.go")
	content, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Erro ao ler o arquivo: %v\n", err)
		return
	}

	// Fazer as correções necessárias
	contentStr := string(content)
	
	// 1. Remover a importação não utilizada do pacote regexp (já feito)
	
	// 2. Corrigir a variável indiceInicio indefinida
	contentStr = strings.Replace(contentStr, 
		"indiceInicio = 0", 
		"var indiceInicio int = 0", 
		-1)
	
	// 3. Remover as variáveis virt declaradas mas não utilizadas
	contentStr = strings.Replace(contentStr, 
		"virt := \"\"", 
		"// virt := \"\"", 
		-1)
	contentStr = strings.Replace(contentStr, 
		"virt = campos[4]", 
		"// virt = campos[4]", 
		-1)
	
	// 4. Corrigir referências a MemoryUsage para MemoryUsageMB (já feito para algumas)
	contentStr = strings.Replace(contentStr, 
		"processInfo.MemoryUsage", 
		"processInfo.MemoryUsageMB", 
		-1)
	contentStr = strings.Replace(contentStr, 
		"proc.MemoryUsage", 
		"proc.MemoryUsageMB", 
		-1)
	
	// 5. Corrigir referências a MemPercent para MemoryPercent (já feito para algumas)
	contentStr = strings.Replace(contentStr, 
		"proc.MemPercent", 
		"proc.MemoryPercent", 
		-1)
	contentStr = strings.Replace(contentStr, 
		"memPercent", 
		"memoryPercent", 
		-1)

	// Escrever o conteúdo corrigido de volta ao arquivo
	err = os.WriteFile(filePath, []byte(contentStr), 0644)
	if err != nil {
		fmt.Printf("Erro ao escrever o arquivo: %v\n", err)
		return
	}

	fmt.Println("Correções aplicadas com sucesso!")
}
