package collector

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/MakeToMe/mtm_guardian/internal/models"
)

// ObterIPMaquina obtém o IP público da máquina
func ObterIPMaquina() (string, error) {
	// Tentar obter o IP público usando um serviço externo
	resp, err := http.Get("http://ipecho.net/plain")
	if err != nil {
		return ObterIPLocal()
	}
	defer resp.Body.Close()

	// Verificar se a resposta foi bem-sucedida
	if resp.StatusCode != http.StatusOK {
		return ObterIPLocal()
	}

	// Ler o corpo da resposta
	buf := make([]byte, 20) // Um IPv4 tem no máximo 15 caracteres
	n, err := resp.Body.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return ObterIPLocal()
	}

	// Retornar o IP
	return string(buf[:n]), nil
}

// ObterIPLocal obtém o IP local da máquina
func ObterIPLocal() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}

	return "", fmt.Errorf("não foi possível encontrar um endereço IP válido")
}

// ExecutarComando executa um comando no sistema operacional e retorna a saída
func ExecutarComando(comando string) (string, error) {
	// No Windows, usamos cmd /c para executar comandos
	var cmd *exec.Cmd
	
	// Verificar o sistema operacional
	if isWindows() {
		cmd = exec.Command("cmd", "/c", comando)
	} else {
		cmd = exec.Command("sh", "-c", comando)
	}
	
	// Executar o comando
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	
	return string(output), nil
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

// ColetarCPU coleta métricas de CPU
func ColetarCPU() (int, float64, float64, error) {
	var cores int
	var cpuUsed, cpuIdle float64
	
	// Obter número de cores de CPU
	if isWindows() {
		// No Windows, usamos wmic para obter informações de CPU
		output, err := ExecutarComando("wmic cpu get NumberOfCores")
		if err != nil {
			return 1, 0, 100, err
		}
		
		lines := strings.Split(output, "\n")
		if len(lines) >= 2 {
			cores, err = strconv.Atoi(strings.TrimSpace(lines[1]))
			if err != nil {
				cores = 1
			}
		} else {
			cores = 1
		}
		
		// Obter uso de CPU no Windows
		output, err = ExecutarComando("wmic cpu get LoadPercentage")
		if err != nil {
			return cores, 0, 100, err
		}
		
		lines = strings.Split(output, "\n")
		if len(lines) >= 2 {
			cpuUsed, err = strconv.ParseFloat(strings.TrimSpace(lines[1]), 64)
			if err != nil {
				cpuUsed = 0
			}
		} else {
			cpuUsed = 0
		}
		
		cpuIdle = 100 - cpuUsed
	} else {
		// Em sistemas Unix/Linux, usamos comandos diferentes
		output, err := ExecutarComando("nproc")
		if err != nil {
			return 1, 0, 100, err
		}
		
		cores, err = strconv.Atoi(strings.TrimSpace(output))
		if err != nil {
			cores = 1
		}
		
		// Coletar uso de CPU usando mpstat
		output, err = ExecutarComando("mpstat -P ALL 1 1")
		if err != nil {
			return cores, 0, 100, err
		}
		
		lines := strings.Split(output, "\n")
		if len(lines) > 3 {
			lastLine := lines[len(lines)-2] // A penúltima linha contém as estatísticas
			fields := strings.Fields(lastLine)
			
			if len(fields) >= 12 {
				cpuIdle, err = strconv.ParseFloat(fields[11], 64) // %idle está na última coluna
				if err != nil {
					cpuIdle = 100
				}
				cpuUsed = 100 - cpuIdle
			}
		}
	}
	
	return cores, cpuUsed, cpuIdle, nil
}

// ColetarMemoria coleta métricas de memória
func ColetarMemoria() (float64, float64, float64, float64, float64, error) {
	var ramTotalGB, ramUsedGB, ramUsedPercent, ramAvailableGB, ramAvailablePercent float64
	
	if isWindows() {
		// No Windows, usamos wmic para obter informações de memória
		output, err := ExecutarComando("wmic OS get TotalVisibleMemorySize,FreePhysicalMemory")
		if err != nil {
			return 0, 0, 0, 0, 0, err
		}
		
		lines := strings.Split(output, "\n")
		if len(lines) < 2 {
			return 0, 0, 0, 0, 0, fmt.Errorf("formato de saída inesperado")
		}
		
		fields := strings.Fields(lines[1])
		if len(fields) < 2 {
			return 0, 0, 0, 0, 0, fmt.Errorf("formato de saída inesperado")
		}
		
		totalMemKB, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return 0, 0, 0, 0, 0, err
		}
		
		freeMemKB, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return 0, 0, 0, 0, 0, err
		}
		
		// Converter de KB para GB
		ramTotalGB = totalMemKB / (1024 * 1024)
		ramAvailableGB = freeMemKB / (1024 * 1024)
		ramUsedGB = ramTotalGB - ramAvailableGB
		
		// Calcular percentuais
		ramUsedPercent = (ramUsedGB / ramTotalGB) * 100
		ramAvailablePercent = (ramAvailableGB / ramTotalGB) * 100
	} else {
		// Em sistemas Unix/Linux, usamos o comando free
		output, err := ExecutarComando("free")
		if err != nil {
			return 0, 0, 0, 0, 0, err
		}
		
		lines := strings.Split(output, "\n")
		if len(lines) < 2 {
			return 0, 0, 0, 0, 0, fmt.Errorf("formato de saída inesperado")
		}
		
		fields := strings.Fields(lines[1])
		if len(fields) < 7 {
			return 0, 0, 0, 0, 0, fmt.Errorf("formato de saída inesperado")
		}
		
		ramTotalMB, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return 0, 0, 0, 0, 0, err
		}
		
		ramUsedMB, err := strconv.ParseFloat(fields[2], 64)
		if err != nil {
			return 0, 0, 0, 0, 0, err
		}
		
		ramAvailableMB, err := strconv.ParseFloat(fields[6], 64)
		if err != nil {
			return 0, 0, 0, 0, 0, err
		}
		
		// Converter de MB para GB
		ramTotalGB = ramTotalMB / 1024
		ramUsedGB = ramUsedMB / 1024
		ramAvailableGB = ramAvailableMB / 1024
		
		// Calcular percentuais
		ramUsedPercent = (ramUsedMB / ramTotalMB) * 100
		ramAvailablePercent = (ramAvailableMB / ramTotalMB) * 100
	}
	
	return ramTotalGB, ramUsedGB, ramUsedPercent, ramAvailableGB, ramAvailablePercent, nil
}

// ColetarDisco coleta métricas de disco
func ColetarDisco() (float64, float64, float64, float64, error) {
	var diskTotalGB, diskUsedGB, diskUsedPercent, diskAvailableGB float64
	
	if isWindows() {
		// No Windows, usamos wmic para obter informações de disco
		output, err := ExecutarComando("wmic logicaldisk where DeviceID='C:' get Size,FreeSpace")
		if err != nil {
			return 0, 0, 0, 0, err
		}
		
		lines := strings.Split(output, "\n")
		if len(lines) < 2 {
			return 0, 0, 0, 0, fmt.Errorf("formato de saída inesperado")
		}
		
		fields := strings.Fields(lines[1])
		if len(fields) < 2 {
			return 0, 0, 0, 0, fmt.Errorf("formato de saída inesperado")
		}
		
		freeSpace, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return 0, 0, 0, 0, err
		}
		
		totalSize, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return 0, 0, 0, 0, err
		}
		
		// Converter de bytes para GB
		diskTotalGB = totalSize / (1024 * 1024 * 1024)
		diskAvailableGB = freeSpace / (1024 * 1024 * 1024)
		diskUsedGB = diskTotalGB - diskAvailableGB
		
		// Calcular percentual
		diskUsedPercent = (diskUsedGB / diskTotalGB) * 100
	} else {
		// Em sistemas Unix/Linux, usamos o comando df
		output, err := ExecutarComando("df -h / | tail -1")
		if err != nil {
			return 0, 0, 0, 0, err
		}
		
		fields := strings.Fields(output)
		if len(fields) < 5 {
			return 0, 0, 0, 0, fmt.Errorf("formato de saída inesperado")
		}
		
		// Converter valores para GB
		diskTotalGB, err = ConverterParaGB(fields[1])
		if err != nil {
			return 0, 0, 0, 0, err
		}
		
		diskUsedGB, err = ConverterParaGB(fields[2])
		if err != nil {
			return 0, 0, 0, 0, err
		}
		
		diskAvailableGB, err = ConverterParaGB(fields[3])
		if err != nil {
			return 0, 0, 0, 0, err
		}
		
		// Obter percentual de uso
		diskUsedPercentStr := strings.TrimSuffix(fields[4], "%")
		diskUsedPercent, err = strconv.ParseFloat(diskUsedPercentStr, 64)
		if err != nil {
			return 0, 0, 0, 0, err
		}
	}
	
	return diskTotalGB, diskUsedGB, diskUsedPercent, diskAvailableGB, nil
}

// ConverterParaGB converte um valor de disco para GB
func ConverterParaGB(valor string) (float64, error) {
	// Remover qualquer caractere não numérico no início da string
	for len(valor) > 0 && (valor[0] < '0' || valor[0] > '9') {
		valor = valor[1:]
	}
	
	if len(valor) == 0 {
		return 0, fmt.Errorf("valor inválido")
	}
	
	// Encontrar o índice do primeiro caractere não numérico
	i := 0
	for i < len(valor) && ((valor[i] >= '0' && valor[i] <= '9') || valor[i] == '.') {
		i++
	}
	
	// Extrair o valor numérico e a unidade
	numStr := valor[:i]
	unit := ""
	if i < len(valor) {
		unit = strings.ToUpper(valor[i:])
	}
	
	// Converter o valor numérico para float
	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, err
	}
	
	// Converter para GB com base na unidade
	switch unit {
	case "K", "KB":
		return num / (1024 * 1024), nil
	case "M", "MB":
		return num / 1024, nil
	case "G", "GB":
		return num, nil
	case "T", "TB":
		return num * 1024, nil
	default:
		return num, nil // Assumir que já está em GB se não houver unidade
	}
}

// ColetarMetricas coleta todas as métricas do sistema
func ColetarMetricas() (models.SystemMetrics, error) {
	metrics := models.SystemMetrics{
		Timestamp: time.Now(),
	}
	
	// Obter IP da máquina
	ip, err := ObterIPMaquina()
	if err != nil {
		ip, _ = ObterIPLocal()
	}
	metrics.IP = ip
	
	// Coletar métricas de CPU
	cores, cpuUsed, cpuIdle, err := ColetarCPU()
	if err != nil {
		return metrics, err
	}
	metrics.CPU = models.CPUMetrics{
		Cores:       cores,
		UsedPercent: cpuUsed,
		IdlePercent: cpuIdle,
	}
	
	// Coletar métricas de memória
	ramTotalGB, ramUsedGB, ramUsedPercent, ramAvailableGB, ramAvailablePercent, err := ColetarMemoria()
	if err != nil {
		return metrics, err
	}
	metrics.Memory = models.MemMetrics{
		TotalGB:         ramTotalGB,
		UsedGB:          ramUsedGB,
		UsedPercent:     ramUsedPercent,
		AvailableGB:     ramAvailableGB,
		AvailablePercent: ramAvailablePercent,
	}
	
	// Coletar métricas de disco
	diskTotalGB, diskUsedGB, diskUsedPercent, diskAvailableGB, err := ColetarDisco()
	if err != nil {
		return metrics, err
	}
	metrics.Disk = models.DiskMetrics{
		TotalGB:     diskTotalGB,
		UsedGB:      diskUsedGB,
		UsedPercent: diskUsedPercent,
		AvailableGB: diskAvailableGB,
		FreePercent: 100 - diskUsedPercent,
	}
	
	return metrics, nil
}
