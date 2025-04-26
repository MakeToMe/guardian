package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/MakeToMe/mtm_guardian/internal/collector"
)

func main() {
	log.Println("Iniciando programa de depuração para o MTM Guardian")

	// Verificar se o endpoint da API foi fornecido
	apiEndpoint := os.Getenv("API_ENDPOINT")
	if apiEndpoint == "" {
		log.Println("Variável de ambiente API_ENDPOINT não definida. Usando http://localhost:3000/api como padrão.")
		apiEndpoint = "http://localhost:3000/api"
	}

	// Coletar métricas
	log.Println("Coletando métricas do sistema...")
	metricas, err := collector.ColetarMetricas()
	if err != nil {
		log.Fatalf("Erro ao coletar métricas: %v", err)
	}

	// Obter IP da máquina
	log.Println("Obtendo IP da máquina...")
	ipMaquina, err := collector.ObterIPMaquina()
	if err != nil {
		log.Printf("Erro ao obter IP da máquina: %v. Usando IP local como fallback.", err)
		ipMaquina, _ = collector.ObterIPLocal()
	}
	log.Printf("IP da máquina: %s", ipMaquina)

	// Exibir informações sobre as métricas coletadas
	log.Printf("Métricas coletadas:")
	log.Printf("- CPU: %d cores, %.2f%% usado, %.2f%% livre", metricas.CPU.Cores, metricas.CPU.UsedPercent, metricas.CPU.IdlePercent)
	log.Printf("- Memória: %.2f GB total, %.2f GB usada (%.2f%%)", metricas.Memory.TotalGB, metricas.Memory.UsedGB, metricas.Memory.UsedPercent)
	log.Printf("- Disco: %.2f GB total, %.2f GB usado (%.2f%%)", metricas.Disk.TotalGB, metricas.Disk.UsedGB, metricas.Disk.UsedPercent)
	
	// Exibir informações sobre os núcleos de CPU
	log.Printf("Núcleos de CPU: %d", len(metricas.CPU.CoreStats))
	for i, core := range metricas.CPU.CoreStats {
		if i < 5 { // Limitar a exibição aos primeiros 5 núcleos
			log.Printf("  - Core %d: %.2f%% usado, %.2f%% livre", core.CoreID, core.UsedPercent, core.IdlePercent)
		}
	}
	
	// Preparar os dados para envio
	dados := map[string]interface{}{
		"ip":                ipMaquina,
		"mem_total":         metricas.Memory.TotalGB,
		"mem_usada":         metricas.Memory.UsedGB,
		"mem_usada_p":       metricas.Memory.UsedPercent,
		"mem_disponivel":    metricas.Memory.AvailableGB,
		"mem_disponivel_p":  metricas.Memory.AvailablePercent,
		"cpu_total":         metricas.CPU.Cores,
		"cpu_usada":         metricas.CPU.UsedPercent,
		"cpu_livre":         metricas.CPU.IdlePercent,
		"disco_total":       metricas.Disk.TotalGB,
		"disco_usado":       metricas.Disk.UsedGB,
		"disco_livre":       metricas.Disk.AvailableGB,
		"disco_uso_p":       metricas.Disk.UsedPercent,
		"disco_livre_p":     metricas.Disk.FreePercent,
		"timestamp":         time.Now().Format(time.RFC3339),
	}
	
	// Adicionar métricas de CPU por núcleo, se disponíveis
	if len(metricas.CPU.CoreStats) > 0 {
		log.Printf("Adicionando informações de %d núcleos de CPU", len(metricas.CPU.CoreStats))
		coreStatsJSON := []map[string]interface{}{}
		for _, core := range metricas.CPU.CoreStats {
			coreStatsJSON = append(coreStatsJSON, map[string]interface{}{
				"core_id":      core.CoreID,
				"used_percent": core.UsedPercent,
				"idle_percent": core.IdlePercent,
			})
		}
		dados["cpu_cores"] = coreStatsJSON
	} else {
		log.Printf("AVISO: Nenhuma informação de núcleo de CPU disponível")
	}

	// Converter dados para JSON com indentação para facilitar a leitura
	jsonData, err := json.MarshalIndent(dados, "", "  ")
	if err != nil {
		log.Fatalf("Erro ao converter dados para JSON: %v", err)
	}

	// Salvar JSON em um arquivo para análise
	err = ioutil.WriteFile("debug_payload.json", jsonData, 0644)
	if err != nil {
		log.Printf("Erro ao salvar JSON em arquivo: %v", err)
	} else {
		log.Println("JSON salvo em debug_payload.json")
	}

	// Exibir tamanho do JSON
	log.Printf("Tamanho do JSON: %d bytes", len(jsonData))

	// Perguntar se o usuário deseja enviar os dados para a API
	fmt.Println("\nDeseja enviar os dados para a API? (s/n)")
	var resposta string
	fmt.Scanln(&resposta)

	if resposta == "s" || resposta == "S" {
		// Criar requisição HTTP
		endpoint := fmt.Sprintf("%s/vm_stats", apiEndpoint)
		log.Printf("Enviando dados para: %s", endpoint)
		
		req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
		if err != nil {
			log.Fatalf("Erro ao criar requisição HTTP: %v", err)
		}

		// Configurar headers
		req.Header.Set("Content-Type", "application/json")

		// Criar cliente HTTP com timeout
		client := &http.Client{Timeout: 30 * time.Second}

		// Enviar requisição
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Erro ao enviar requisição HTTP: %v", err)
		}
		defer resp.Body.Close()

		// Ler resposta
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("Erro ao ler resposta: %v", err)
		}

		// Verificar resposta
		log.Printf("Resposta da API: Status %d", resp.StatusCode)
		log.Printf("Corpo da resposta: %s", string(respBody))

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			log.Fatalf("Erro ao enviar dados para a API: código de status %d", resp.StatusCode)
		} else {
			log.Println("Dados enviados com sucesso para a API!")
		}
	} else {
		log.Println("Operação cancelada pelo usuário.")
	}
}
