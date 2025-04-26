package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/MakeToMe/mtm_guardian/internal/models"
)

// Client representa um cliente para a API de métricas
type Client struct {
	BaseURL string
}

// NewClient cria um novo cliente para a API de métricas
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
	}
}

// IsConfigured verifica se o cliente está configurado corretamente
func (c *Client) IsConfigured() bool {
	return c.BaseURL != ""
}

// EnviarVMStats envia métricas da VM para a API
func (c *Client) EnviarVMStats(metricas models.SystemMetrics, ipMaquina string) error {
	if !c.IsConfigured() {
		return fmt.Errorf("cliente API não configurado")
	}

	log.Printf("Preparando envio de VM stats para a API...")

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
		"processes":         []map[string]interface{}{}, // Garantir que o campo processes sempre exista, mesmo que vazio
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
	
	// Converter dados para JSON
	jsonData, err := json.Marshal(dados)
	if err != nil {
		return fmt.Errorf("erro ao converter dados para JSON: %v", err)
	}
	
	// Log do JSON que está sendo enviado para debug
	log.Printf("Enviando JSON para API: %s", string(jsonData))

	// Criar requisição HTTP
	endpoint := fmt.Sprintf("%s/vm_stats", c.BaseURL)
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("erro ao criar requisição HTTP: %v", err)
	}

	// Configurar headers
	req.Header.Set("Content-Type", "application/json")

	// Enviar requisição
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("erro ao enviar requisição HTTP: %v", err)
	}
	defer resp.Body.Close()

	// Verificar resposta
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		// Ler o corpo da resposta para obter mais detalhes sobre o erro
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("Resposta de erro da API: %s", string(respBody))
		return fmt.Errorf("erro ao enviar dados para a API: código de status %d", resp.StatusCode)
	}

	log.Printf("Métricas da VM enviadas com sucesso para a API (status: %d)", resp.StatusCode)
	return nil
}

// EnviarDockerStats envia estatísticas do Docker para a API
func (c *Client) EnviarDockerStats(containers []models.ContainerStats, networkStats models.NetworkStats, ipMaquina string) error {
	if !c.IsConfigured() {
		return fmt.Errorf("cliente API não configurado")
	}

	log.Printf("Preparando envio de estatísticas do Docker para a API...")

	// Preparar os dados para envio
	dados := map[string]interface{}{
		"ip":        ipMaquina,
		"stats":     containers,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	// Converter dados para JSON
	jsonData, err := json.Marshal(dados)
	if err != nil {
		return fmt.Errorf("erro ao converter dados para JSON: %v", err)
	}
	
	// Log do JSON que está sendo enviado para debug
	log.Printf("Enviando JSON para API: %s", string(jsonData))

	// Criar requisição HTTP
	endpoint := fmt.Sprintf("%s/docker_stats", c.BaseURL)
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("erro ao criar requisição HTTP: %v", err)
	}

	// Configurar headers
	req.Header.Set("Content-Type", "application/json")

	// Enviar requisição
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("erro ao enviar requisição HTTP: %v", err)
	}
	defer resp.Body.Close()

	// Verificar resposta
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		// Ler o corpo da resposta para obter mais detalhes sobre o erro
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("Resposta de erro da API: %s", string(respBody))
		return fmt.Errorf("erro ao enviar dados para a API: código de status %d", resp.StatusCode)
	}

	log.Printf("Estatísticas do Docker enviadas com sucesso para a API (status: %d)", resp.StatusCode)
	return nil
}
