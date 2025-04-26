package collector

import (
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/MakeToMe/mtm_guardian/internal/models"
)

// ObterIPMaquina obtÃ©m o IP pÃºblico da mÃ¡quina
func ObterIPMaquina() (string, error) {
	// Tentar obter o IP pÃºblico usando um serviÃ§o externo
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
	buf := make([]byte, 20) // Um IPv4 tem no mÃ¡ximo 15 caracteres
	n, err := resp.Body.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return ObterIPLocal()
	}

	// Retornar o IP
	return string(buf[:n]), nil
}

// ObterIPLocal obtÃ©m o IP local da mÃ¡quina
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

	return "", fmt.Errorf("nÃ£o foi possÃ­vel encontrar um endereÃ§o IP vÃ¡lido")
}

// ExecutarComando executa um comando no sistema operacional e retorna a saÃ­da
func ExecutarComando(comando string) (string, error) {
	// Em Linux/Unix, usamos sh
	cmd := exec.Command("sh", "-c", comando)
	
	// Executar o comando
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	
	return string(output), nil
}


// ColetarCPU coleta mÃ©tricas de CPU globais
func ColetarCPU() (int, float64, float64, error) {
	var cores int
	var cpuUsed, cpuIdle float64
	
	// Em sistemas Unix/Linux, usamos o comando nproc
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
		lastLine := lines[len(lines)-2] // A penÃºltima linha contÃ©m as estatÃ­sticas
		fields := strings.Fields(lastLine)
		
		if len(fields) >= 12 {
			cpuIdle, err = strconv.ParseFloat(fields[11], 64) // %idle estÃ¡ na Ãºltima coluna
			if err != nil {
				cpuIdle = 100
			}
			cpuUsed = 100 - cpuIdle
		}
	}
	
	return cores, cpuUsed, cpuIdle, nil
}

// ColetarCPUPorNucleo coleta mÃ©tricas de CPU para cada nÃºcleo individualmente
func ColetarCPUPorNucleo() ([]models.CoreMetrics, error) {
	var coreStats []models.CoreMetrics

	// Em sistemas Unix/Linux, usamos /proc/stat para obter informaÃ§Ãµes de CPU por nÃºcleo
	output, err := ExecutarComando("cat /proc/stat | grep ^cpu")
	if err != nil {
		return nil, err
	}
	
	linhas := strings.Split(output, "\n")
	
	for _, linha := range linhas {
		// Ignorar linhas vazias
		if linha == "" || len(strings.TrimSpace(linha)) == 0 {
			continue
		}
		
		// Procurando linhas que comeÃ§am com 'cpu' seguido de um nÃºmero (cpuN)
		if strings.HasPrefix(strings.TrimSpace(linha), "cpu") {
			campos := strings.Fields(linha)
			if len(campos) < 2 {
				continue
			}
			
			// Extrair o ID do nÃºcleo do nome 'cpuN'
			cpuName := campos[0]
			if cpuName == "cpu" {
				continue // Pular a linha de CPU total
			}
			
			// Extrair o nÃºmero do nÃºcleo do nome (ex: cpu0 -> 0)
			cpuNumStr := strings.TrimPrefix(cpuName, "cpu")
			cpuNum, err := strconv.Atoi(cpuNumStr)
			if err != nil {
				continue // Pular se nÃ£o conseguir extrair o nÃºmero
			}
			
			// Calcular uso de CPU baseado nos valores de /proc/stat
			// Formato: cpu user nice system idle iowait irq softirq steal guest guest_nice
			if len(campos) >= 5 { // Precisamos de pelo menos user, nice, system, idle
				user, _ := strconv.ParseFloat(campos[1], 64)
				nice, _ := strconv.ParseFloat(campos[2], 64)
				system, _ := strconv.ParseFloat(campos[3], 64)
				idle, _ := strconv.ParseFloat(campos[4], 64)
				
				// Calcular iowait se disponÃ­vel
				iowait := 0.0
				if len(campos) >= 6 {
					iowait, _ = strconv.ParseFloat(campos[5], 64)
				}
				
				// Total de tempo
				total := user + nice + system + idle + iowait
				if total > 0 {
					// Calcular porcentagens
					idlePercent := (idle / total) * 100
					usedPercent := 100.0 - idlePercent
					
					// Adicionar Ã  lista de mÃ©tricas por nÃºcleo
					coreMetrics := models.CoreMetrics{
						CoreID:      cpuNum,
						UsedPercent: math.Round(usedPercent*100) / 100, // Arredondar para 2 casas decimais
						IdlePercent: math.Round(idlePercent*100) / 100,
					}
					coreStats = append(coreStats, coreMetrics)
				}
			}
		}
	}
	
	// Se nÃ£o conseguimos coletar nenhuma estatÃ­stica por nÃºcleo, retornamos um erro
	if len(coreStats) == 0 {
		return nil, fmt.Errorf("nÃ£o foi possÃ­vel coletar estatÃ­sticas por nÃºcleo")
	}
	
	return coreStats, nil
}

// ColetarMemoria coleta mÃ©tricas de memÃ³ria
func ColetarMemoria() (float64, float64, float64, float64, float64, error) {
	var ramTotalGB, ramUsedGB, ramUsedPercent, ramAvailableGB, ramAvailablePercent float64
	
	// Em sistemas Unix/Linux, usamos o comando free
	output, err := ExecutarComando("free")
	if err != nil {
		return 0, 0, 0, 0, 0, err
	}
	
	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		return 0, 0, 0, 0, 0, fmt.Errorf("formato de saÃ­da inesperado")
	}
	
	fields := strings.Fields(lines[1])
	if len(fields) < 7 {
		return 0, 0, 0, 0, 0, fmt.Errorf("formato de saÃ­da inesperado")
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
	
	return ramTotalGB, ramUsedGB, ramUsedPercent, ramAvailableGB, ramAvailablePercent, nil
}

// ColetarDisco coleta mÃ©tricas de disco
func ColetarDisco() (float64, float64, float64, float64, error) {
	var diskTotalGB, diskUsedGB, diskUsedPercent, diskAvailableGB float64
	
	// Em sistemas Unix/Linux, usamos o comando df
	output, err := ExecutarComando("df -h / | tail -1")
	if err != nil {
		return 0, 0, 0, 0, err
	}
	
	fields := strings.Fields(output)
	if len(fields) < 5 {
		return 0, 0, 0, 0, fmt.Errorf("formato de saÃ­da inesperado")
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
	
	return diskTotalGB, diskUsedGB, diskUsedPercent, diskAvailableGB, nil
}

// ConverterParaGB converte um valor de disco para GB
func ConverterParaGB(valor string) (float64, error) {
	// Remover qualquer caractere nÃ£o numÃ©rico no inÃ­cio da string
	for len(valor) > 0 && (valor[0] < '0' || valor[0] > '9') {
		valor = valor[1:]
	}
	
	if len(valor) == 0 {
		return 0, fmt.Errorf("valor invÃ¡lido")
	}
	
	// Encontrar o Ã­ndice do primeiro caractere nÃ£o numÃ©rico
	i := 0
	for i < len(valor) && ((valor[i] >= '0' && valor[i] <= '9') || valor[i] == '.') {
		i++
	}
	
	// Extrair o valor numÃ©rico e a unidade
	numStr := valor[:i]
	unit := ""
	if i < len(valor) {
		unit = strings.ToUpper(valor[i:])
	}
	
	// Converter o valor numÃ©rico para float
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
		return num, nil // Assumir que jÃ¡ estÃ¡ em GB se nÃ£o houver unidade
	}
}

// ColetarMetricas coleta todas as mÃ©tricas do sistema
func ColetarMetricas() (models.SystemMetrics, error) {
	metrics := models.SystemMetrics{
		Timestamp: time.Now(),
	}
	
	// Obter IP da mÃ¡quina
	ip, err := ObterIPMaquina()
	if err != nil {
		ip, _ = ObterIPLocal()
	}
	metrics.IP = ip
	
	// Coletar mÃ©tricas de CPU
	numCores, usedPercent, idlePercent, err := ColetarCPU()
	if err != nil {
		log.Printf("[VM] Erro ao coletar mÃ©tricas de CPU: %v", err)
	}
	
	// Coletar mÃ©tricas de CPU por nÃºcleo
	coreStats, err := ColetarCPUPorNucleo()
	if err != nil {
		log.Printf("[VM] Erro ao coletar mÃ©tricas de CPU por nÃºcleo: %v", err)
	}
	
	metrics.CPU = models.CPUMetrics{
		Cores:       numCores,
		UsedPercent: usedPercent,
		IdlePercent: idlePercent,
		CoreStats:   coreStats,
	}
	
	// Coletar mÃ©tricas de memÃ³ria
	totalGB, usedGB, usedPercentMem, availableGB, availablePercent, err := ColetarMemoria()
	if err != nil {
		log.Printf("[VM] Erro ao coletar mÃ©tricas de memÃ³ria: %v", err)
	}
	
	metrics.Memory = models.MemMetrics{
		TotalGB:          totalGB,
		UsedGB:           usedGB,
		UsedPercent:      usedPercentMem,
		AvailableGB:      availableGB,
		AvailablePercent: availablePercent,
	}
	
	// Coletar mÃ©tricas de disco
	totalGBDisk, usedGBDisk, usedPercentDisk, availableGBDisk, err := ColetarDisco()
	if err != nil {
		log.Printf("[VM] Erro ao coletar mÃ©tricas de disco: %v", err)
	}
	
	metrics.Disk = models.DiskMetrics{
		TotalGB:     totalGBDisk,
		UsedGB:      usedGBDisk,
		UsedPercent: usedPercentDisk,
		AvailableGB: availableGBDisk,
		FreePercent: 100 - usedPercentDisk,
	}
	
	return metrics, nil
}
