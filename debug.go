package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/MakeToMe/mtm_guardian/internal/collector"
)

func main() {
	// Coletar métricas
	metricas, err := collector.ColetarMetricas()
	if err != nil {
		log.Fatalf("Erro ao coletar métricas: %v", err)
	}

	// Obter IP da máquina
	ipMaquina, err := collector.ObterIPMaquina()
	if err != nil {
		log.Printf("Erro ao obter IP da máquina: %v. Usando IP local como fallback.", err)
		ipMaquina, _ = collector.ObterIPLocal()
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
		// Converter CoreStats para um formato adequado para JSON
		coreStatsJSON := []map[string]interface{}{}
		for _, core := range metricas.CPU.CoreStats {
			coreStatsJSON = append(coreStatsJSON, map[string]interface{}{
				"core_id":      core.CoreID,
				"used_percent": core.UsedPercent,
				"idle_percent": core.IdlePercent,
			})
		}
		dados["cpu_cores"] = coreStatsJSON
	}
	
	// Converter dados para JSON com indentação para facilitar a leitura
	jsonData, err := json.MarshalIndent(dados, "", "  ")
	if err != nil {
		log.Fatalf("Erro ao converter dados para JSON: %v", err)
	}

	// Salvar JSON em um arquivo para análise
	err = ioutil.WriteFile("debug_payload.json", jsonData, 0644)
	if err != nil {
		log.Fatalf("Erro ao salvar JSON em arquivo: %v", err)
	}

	// Imprimir JSON no console
	fmt.Println("JSON a ser enviado para a API:")
	fmt.Println(string(jsonData))
	
	// Verificar se os campos cpu_cores e processes estão presentes
	fmt.Println("\nVerificando campos críticos:")
	fmt.Printf("Campo cpu_cores presente: %v\n", dados["cpu_cores"] != nil)
	
	// Se os campos estiverem ausentes, imprimir informações de debug
	if dados["cpu_cores"] == nil {
		coreStats, err := collector.ColetarCPUPorNucleo()
		fmt.Printf("Resultado de ColetarCPUPorNucleo: %v, erro: %v\n", len(coreStats), err)
	}
	
	log.Println("JSON salvo em debug_payload.json")
}
