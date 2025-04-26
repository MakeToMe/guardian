package main

import (
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/MakeToMe/mtm_guardian/internal/api"
	"github.com/MakeToMe/mtm_guardian/internal/collector"
	"github.com/MakeToMe/mtm_guardian/internal/docker"
)

// Intervalos de coleta em segundos (valores padrão)
const (
	DefaultDockerInterval = 10 // Intervalo padrão para envio de estatísticas Docker (segundos)
	DefaultVMInterval     = 30 // Intervalo padrão para envio de métricas VM (segundos)
)

func main() {
	log.Printf("====================================================")
	log.Printf("Iniciando MTM Guardian - Serviço de coleta de métricas")
	log.Printf("====================================================")

	// Obter variáveis de ambiente
	apiEndpoint := os.Getenv("API_ENDPOINT")
	
	// Obter intervalos de coleta das variáveis de ambiente
	dockerIntervalStr := os.Getenv("DOCKER_INTERVAL")
	vmIntervalStr := os.Getenv("VM_INTERVAL")
	
	// Converter para inteiros e usar valores padrão se não estiverem definidos
	dockerInterval := DefaultDockerInterval
	vmInterval := DefaultVMInterval
	
	if dockerIntervalStr != "" {
		if val, err := strconv.Atoi(dockerIntervalStr); err == nil && val > 0 {
			dockerInterval = val
			log.Printf("Usando intervalo de coleta Docker configurado: %d segundos", dockerInterval)
		}
	}
	
	if vmIntervalStr != "" {
		if val, err := strconv.Atoi(vmIntervalStr); err == nil && val > 0 {
			vmInterval = val
			log.Printf("Usando intervalo de coleta VM configurado: %d segundos", vmInterval)
		}
	}

	if apiEndpoint == "" {
		log.Println("Aviso: Variável de ambiente API_ENDPOINT não configurada")
		log.Println("O serviço continuará funcionando, mas não enviará dados para a API")
	}

	// Inicializar cliente API
	apiClient := api.NewClient(apiEndpoint)

	// Obter IP da máquina
	ipMaquina, err := collector.ObterIPMaquina()
	if err != nil {
		log.Printf("Erro ao obter IP da máquina: %v. Usando IP local como fallback.", err)
		ipMaquina, _ = collector.ObterIPLocal()
	}
	log.Printf("IP da máquina: %s", ipMaquina)

	// O serviço agora foca exclusivamente na coleta de métricas e estatísticas
	log.Printf("====================================================")
	log.Printf("Endereço IP da máquina: %s", ipMaquina)
	log.Printf("Intervalo de coleta Docker: %d segundos", dockerInterval)
	log.Printf("Intervalo de coleta VM: %d segundos", vmInterval)
	log.Printf("Endpoint da API: %s", apiEndpoint)
	log.Printf("====================================================")
	


	// Canais para controle de encerramento
	done := make(chan bool)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Marcadores de tempo para controlar os intervalos
	ultimoEnvioDocker := time.Now().Add(-time.Duration(dockerInterval) * time.Second)
	ultimoEnvioVM := time.Now().Add(-time.Duration(vmInterval) * time.Second)

	// Goroutine para capturar sinais de encerramento
	go func() {
		sig := <-sigs
		log.Printf("Sinal recebido: %v", sig)
		done <- true
	}()

	// Loop principal de coleta
	log.Println("Iniciando loop de coleta de métricas...")
	for {
		select {
		case <-done:
			log.Println("Encerrando serviço...")
			return
		default:
			// Verificar se é hora de coletar e enviar estatísticas Docker
			if time.Since(ultimoEnvioDocker) >= time.Duration(dockerInterval)*time.Second {
				log.Println("====================================================")
				log.Println("[DOCKER] Iniciando coleta de estatísticas dos containers...")
				containers, err := docker.ColetarDockerStats()
				if err != nil {
					log.Printf("[DOCKER] ERRO na coleta de estatísticas: %v", err)
				} else {
					log.Printf("[DOCKER] Coletados dados de %d containers com sucesso", len(containers))
					
					// Processar estatísticas de rede
					networkStats := docker.ProcessarEstatisticasRede(containers)
					log.Printf("[DOCKER] Estatísticas de rede processadas com sucesso")
					
					// Enviar para a API
					if apiClient.IsConfigured() {
						log.Printf("[DOCKER] Enviando estatísticas para API: %s", apiEndpoint)
						err := apiClient.EnviarDockerStats(containers, networkStats, ipMaquina)
						if err != nil {
							log.Printf("[DOCKER] ERRO ao enviar estatísticas para API: %v", err)
						} else {
							log.Printf("[DOCKER] Estatísticas enviadas com sucesso para %s", apiEndpoint)
						}
					} else {
						log.Println("[DOCKER] API não configurada. Dados não foram enviados.")
					}
				}
				ultimoEnvioDocker = time.Now()
			}

			// Verificar se é hora de coletar e enviar métricas VM
			if time.Since(ultimoEnvioVM) >= time.Duration(vmInterval)*time.Second {
				log.Println("====================================================")
				log.Println("[VM] Iniciando coleta de métricas do sistema...")
				metricas, err := collector.ColetarMetricas()
				if err != nil {
					log.Printf("[VM] ERRO ao coletar métricas: %v", err)
				} else {
					log.Printf("[VM] Coleta de métricas realizada com sucesso")
					// Exibir métricas coletadas
					log.Printf("[VM] CPU: %d cores, %.2f%% usado, %.2f%% livre", 
						metricas.CPU.Cores, 
						metricas.CPU.UsedPercent, 
						metricas.CPU.IdlePercent)
					
					// Exibir métricas de CPU por núcleo
					log.Printf("[VM] Coletados dados de %d núcleos de CPU", len(metricas.CPU.CoreStats))
					for _, core := range metricas.CPU.CoreStats {
						log.Printf("[VM] CPU Core %d: %.2f%% usado, %.2f%% livre", 
							core.CoreID, 
							core.UsedPercent, 
							core.IdlePercent)
					}
					
					log.Printf("[VM] Memória: %.2fGB total, %.2fGB usada (%.2f%%)", 
						metricas.Memory.TotalGB, 
						metricas.Memory.UsedGB, 
						metricas.Memory.UsedPercent)
					
					log.Printf("[VM] Disco: %.2fGB total, %.2fGB usado (%.2f%%)", 
						metricas.Disk.TotalGB, 
						metricas.Disk.UsedGB, 
						metricas.Disk.UsedPercent)
					
					// Enviar para a API
					if apiClient.IsConfigured() {
						log.Printf("[VM] Enviando métricas para API: %s", apiEndpoint)
						err := apiClient.EnviarVMStats(metricas, ipMaquina)
						if err != nil {
							log.Printf("[VM] ERRO ao enviar métricas para API: %v", err)
						} else {
							log.Printf("[VM] Métricas enviadas com sucesso para %s", apiEndpoint)
						}
					} else {
						log.Println("[VM] API não configurada. Dados não foram enviados.")
					}
				}
				ultimoEnvioVM = time.Now()
			}

			// Aguardar um pouco antes do próximo ciclo
			time.Sleep(1 * time.Second)
		}
	}
}
