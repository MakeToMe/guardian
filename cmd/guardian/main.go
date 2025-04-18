package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/MakeToMe/mtm_guardian/internal/auth"
	"github.com/MakeToMe/mtm_guardian/internal/collector"
	"github.com/MakeToMe/mtm_guardian/internal/docker"
	"github.com/MakeToMe/mtm_guardian/internal/firewall"
	"github.com/MakeToMe/mtm_guardian/internal/supabase"
)

// Intervalos de coleta em segundos (valores padrão)
const (
	DefaultDockerInterval = 10 // Intervalo padrão para envio de estatísticas Docker (segundos)
	DefaultVMInterval     = 30 // Intervalo padrão para envio de métricas VM (segundos)
)

func main() {
	log.Printf("Iniciando MTM Guardian - Serviço de coleta de métricas e segurança...")

	// Obter variáveis de ambiente
	supabaseURL := os.Getenv("SUPABASE_URL")
	supabaseKey := os.Getenv("SUPABASE_KEY")
	
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

	if supabaseURL == "" || supabaseKey == "" {
		log.Println("Aviso: Variáveis de ambiente SUPABASE_URL e/ou SUPABASE_KEY não configuradas")
		log.Println("O serviço continuará funcionando, mas não enviará dados para o Supabase")
	}

	// Inicializar cliente Supabase
	supabaseClient := supabase.NewClient(supabaseURL, supabaseKey)
	
	// Inicializar store para IPs banidos
	banStore := supabase.NewBanStore(supabaseClient)

	// Obter IP da máquina
	ipMaquina, err := collector.ObterIPMaquina()
	if err != nil {
		log.Printf("Erro ao obter IP da máquina: %v. Usando IP local como fallback.", err)
		ipMaquina, _ = collector.ObterIPLocal()
	}
	log.Printf("IP da máquina: %s", ipMaquina)

	// Obter titular por IP
	titular, err := supabaseClient.ObterTitularPorIP(ipMaquina)
	if err != nil {
		log.Printf("Aviso: Não foi possível obter o titular para o IP %s: %v", ipMaquina, err)
	} else {
		log.Printf("Titular encontrado: %s", titular)
	}
	
	// Inicializar gerenciador de firewall
	firewallManager := firewall.NewFirewallManager(banStore)
	if err := firewallManager.Initialize(); err != nil {
		log.Printf("Aviso: Erro ao inicializar gerenciador de firewall: %v", err)
	} else {
		log.Printf("Gerenciador de firewall inicializado com sucesso")
	}
	
	// Inicializar monitor de autenticação
	authMonitor := auth.NewMonitor(func(ip string, attempts int, firstAttempt, lastAttempt time.Time) error {
		return firewallManager.RegisterBan(ip, attempts, firstAttempt, lastAttempt)
	})
	authMonitor.Start()
	defer authMonitor.Stop()
	


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
				log.Println("Coletando estatísticas do Docker...")
				containers, err := docker.ColetarDockerStats()
				if err != nil {
					log.Printf("Erro ao coletar estatísticas do Docker: %v", err)
				} else {
					log.Printf("Containers encontrados: %d", len(containers))
					
					// Processar estatísticas de rede
					networkStats := docker.ProcessarEstatisticasRede(containers)
					
					// Enviar para o Supabase
					if supabaseClient.IsConfigured() && titular != "" {
						err := supabaseClient.EnviarDockerStats(containers, networkStats, ipMaquina, titular)
						if err != nil {
							log.Printf("Erro ao enviar estatísticas do Docker para o Supabase: %v", err)
						} else {
							log.Println("Estatísticas do Docker enviadas com sucesso para o Supabase")
						}
					}
				}
				ultimoEnvioDocker = time.Now()
			}

			// Verificar se é hora de coletar e enviar métricas VM
			if time.Since(ultimoEnvioVM) >= time.Duration(vmInterval)*time.Second {
				log.Println("Coletando métricas da VM...")
				metricas, err := collector.ColetarMetricas()
				if err != nil {
					log.Printf("Erro ao coletar métricas da VM: %v", err)
				} else {
					// Exibir métricas coletadas
					fmt.Printf("CPU: %d cores, %.2f%% usado, %.2f%% livre\n", 
						metricas.CPU.Cores, 
						metricas.CPU.UsedPercent, 
						metricas.CPU.IdlePercent)
					
					fmt.Printf("Memória: %.2fGB total, %.2fGB usada (%.2f%%)\n", 
						metricas.Memory.TotalGB, 
						metricas.Memory.UsedGB, 
						metricas.Memory.UsedPercent)
					
					fmt.Printf("Disco: %.2fGB total, %.2fGB usado (%.2f%%)\n", 
						metricas.Disk.TotalGB, 
						metricas.Disk.UsedGB, 
						metricas.Disk.UsedPercent)
					
					// Enviar para o Supabase
					if supabaseClient.IsConfigured() && titular != "" {
						err := supabaseClient.EnviarVMStats(metricas, ipMaquina, titular)
						if err != nil {
							log.Printf("Erro ao enviar métricas da VM para o Supabase: %v", err)
						} else {
							log.Println("Métricas da VM enviadas com sucesso para o Supabase")
						}
					}
				}
				ultimoEnvioVM = time.Now()
			}

			// Aguardar um pouco antes do próximo ciclo
			time.Sleep(1 * time.Second)
		}
	}
}
