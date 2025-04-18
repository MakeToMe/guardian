package docker

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"

	"github.com/MakeToMe/mtm_guardian/internal/models"
)

// ColetarDockerStats coleta estatísticas dos containers Docker
func ColetarDockerStats() ([]models.ContainerStats, error) {
	// Verificar se o Docker está instalado e em execução
	if !dockerEstaDisponivel() {
		return nil, fmt.Errorf("Docker não está disponível no sistema")
	}

	// Executar o comando docker stats para obter estatísticas
	var cmd *exec.Cmd
	if isWindows() {
		cmd = exec.Command("cmd", "/c", "docker stats --no-stream --format \"{{json .}}\"")
	} else {
		cmd = exec.Command("sh", "-c", "docker stats --no-stream --format '{{json .}}'")
	}

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("erro ao executar comando docker stats: %v", err)
	}

	// Processar a saída do comando
	lines := strings.Split(string(output), "\n")
	containers := make([]models.ContainerStats, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Remover aspas extras que podem estar causando problemas
		line = strings.Replace(line, "\"{{json .}}\"", "{{json .}}", -1)
		line = strings.Replace(line, "'{{json .}}'", "{{json .}}", -1)

		// Processar o JSON
		var container map[string]string
		err := json.Unmarshal([]byte(line), &container)
		if err != nil {
			log.Printf("Erro ao decodificar JSON: %v, linha: %s", err, line)
			continue
		}

		// Extrair informações do container
		containerStats := models.ContainerStats{
			ID:       container["ID"],
			Name:     container["Name"],
			MemUsage: container["MemUsage"],
			NetIO:    container["NetIO"],
			BlockIO:  container["BlockIO"],
			Container: container["ID"],  // Campo adicional para compatibilidade
			CPUPerc:  container["CPUPerc"],
			MemPerc:  container["MemPerc"],
			PIDs:     container["PIDs"],
		}

		// Processar CPU% (armazenar como float para cálculos internos)
		if cpuStr, ok := container["CPUPerc"]; ok {
			cpuStr = strings.TrimSuffix(cpuStr, "%")
			cpuPercent, err := strconv.ParseFloat(cpuStr, 64)
			if err == nil {
				containerStats.CPUPercent = cpuPercent
			}
		}

		// Processar MEM% (armazenar como float para cálculos internos)
		if memStr, ok := container["MemPerc"]; ok {
			memStr = strings.TrimSuffix(memStr, "%")
			memPercent, err := strconv.ParseFloat(memStr, 64)
			if err == nil {
				containerStats.MemPercent = memPercent
			}
		}

		// Processar PIDs (armazenar como int para cálculos internos)
		if pidsStr, ok := container["PIDs"]; ok {
			pids, err := strconv.Atoi(pidsStr)
			if err == nil {
				containerStats.PidsCount = pids
			}
		}

		containers = append(containers, containerStats)
	}

	return containers, nil
}

// ProcessarEstatisticasRede processa as estatísticas de rede dos containers
func ProcessarEstatisticasRede(containers []models.ContainerStats) models.NetworkStats {
	var totalRXBytes, totalTXBytes int64
	
	for i := range containers {
		// Extrair informações de rede (NetIO)
		if containers[i].NetIO != "" {
			parts := strings.Split(containers[i].NetIO, "/")
			if len(parts) == 2 {
				rxStr := strings.TrimSpace(parts[0])
				txStr := strings.TrimSpace(parts[1])
				
				// Converter para bytes
				rxBytes := ConverterParaBytes(rxStr)
				txBytes := ConverterParaBytes(txStr)
				
				// Armazenar valores no formato antigo
				containers[i].NetIORXBytes = rxBytes
				containers[i].NetIOTXBytes = txBytes
				containers[i].NetIO_RX_Bytes = float64(rxBytes)
				containers[i].NetIO_TX_Bytes = float64(txBytes)
				containers[i].NetIO_RX_Formatted = rxStr
				containers[i].NetIO_TX_Formatted = txStr
				
				// Acumular totais
				totalRXBytes += rxBytes
				totalTXBytes += txBytes
			}
		}
	}
	
	// Formatar os totais para exibição
	totalRXFormatted := FormatarBytes(totalRXBytes)
	totalTXFormatted := FormatarBytes(totalTXBytes)
	totalBandwidth := FormatarBytes(totalRXBytes + totalTXBytes)
	
	return models.NetworkStats{
		TotalRXBytes:     totalRXBytes,
		TotalTXBytes:     totalTXBytes,
		TotalRXFormatted: totalRXFormatted,
		TotalTXFormatted: totalTXFormatted,
		TotalBandwidth:   totalBandwidth,
	}
}

// ConverterParaBytes converte uma string de tamanho (ex: '7.28GB') para bytes
func ConverterParaBytes(tamanhoStr string) int64 {
	tamanhoStr = strings.TrimSpace(tamanhoStr)
	
	// Extrair o número e a unidade
	var numero float64
	var unidade string
	
	if tamanhoStr == "" {
		return 0
	}
	
	// Encontrar o índice do primeiro caractere não numérico
	i := 0
	for i < len(tamanhoStr) && ((tamanhoStr[i] >= '0' && tamanhoStr[i] <= '9') || tamanhoStr[i] == '.') {
		i++
	}
	
	// Extrair o valor numérico e a unidade
	numStr := tamanhoStr[:i]
	if i < len(tamanhoStr) {
		unidade = strings.ToUpper(tamanhoStr[i:])
	}
	
	// Converter o valor numérico para float
	var err error
	numero, err = strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0
	}
	
	// Converter para bytes com base na unidade
	multiplicadores := map[string]int64{
		"B":  1,
		"K":  1024,
		"KB": 1024,
		"M":  1024 * 1024,
		"MB": 1024 * 1024,
		"G":  1024 * 1024 * 1024,
		"GB": 1024 * 1024 * 1024,
		"T":  1024 * 1024 * 1024 * 1024,
		"TB": 1024 * 1024 * 1024 * 1024,
	}
	
	if mult, ok := multiplicadores[unidade]; ok {
		return int64(numero * float64(mult))
	}
	
	return int64(numero) // Assume que já está em bytes se não houver unidade
}

// FormatarBytes formata bytes para uma representação legível (KB, MB, GB, etc.)
func FormatarBytes(bytesValor int64) string {
	const unit = 1024
	if bytesValor < unit {
		return fmt.Sprintf("%d B", bytesValor)
	}
	
	div, exp := int64(unit), 0
	for n := bytesValor / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	
	unidades := []string{"KB", "MB", "GB", "TB"}
	return fmt.Sprintf("%.2f %s", float64(bytesValor)/float64(div), unidades[exp])
}

// dockerEstaDisponivel verifica se o Docker está instalado e em execução
func dockerEstaDisponivel() bool {
	var cmd *exec.Cmd
	if isWindows() {
		cmd = exec.Command("cmd", "/c", "docker version")
	} else {
		cmd = exec.Command("sh", "-c", "docker version")
	}
	
	err := cmd.Run()
	return err == nil
}

// isWindows verifica se o sistema operacional é Windows
func isWindows() bool {
	cmd := exec.Command("cmd", "/c", "echo %OS%")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	return strings.Contains(strings.ToLower(string(output)), "windows")
}
