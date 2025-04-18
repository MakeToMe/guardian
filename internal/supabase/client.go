package supabase

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MakeToMe/mtm_guardian/internal/models"
)

// Client representa um cliente para o Supabase
type Client struct {
	URL string
	Key string
}

// NewClient cria um novo cliente Supabase
func NewClient(supabaseURL, supabaseKey string) *Client {
	return &Client{
		URL: supabaseURL,
		Key: supabaseKey,
	}
}

// IsConfigured verifica se o cliente está configurado corretamente
func (c *Client) IsConfigured() bool {
	return c.URL != "" && c.Key != ""
}

// ObterTitularPorIP consulta o titular (UUID) correspondente ao IP da máquina na tabela servidores
func (c *Client) ObterTitularPorIP(ipMaquina string) (string, error) {
	if !c.IsConfigured() {
		log.Printf("[DEBUG] ERRO: Cliente Supabase não configurado para consultar titular")
		return "", fmt.Errorf("cliente Supabase não configurado")
	}

	log.Printf("[DEBUG] Consultando titular para o IP: %s", ipMaquina)

	// Configurar o endpoint para a tabela servidores
	baseURL := strings.TrimSuffix(c.URL, "/")
	endpoint := fmt.Sprintf("%s/rest/v1/mtm/servidores", baseURL) // Usar schema mtm explicitamente
	log.Printf("[DEBUG] Endpoint para consulta de titular: %s", endpoint)

	// Configurar headers com o schema mtm
	headers := map[string]string{
		"apikey":         c.Key,
		"Authorization":  fmt.Sprintf("Bearer %s", c.Key),
		"Accept-Profile": "mtm", // Especificar o schema mtm
		"Content-Type":   "application/json",
		"Accept":         "application/json",
	}
	log.Printf("[DEBUG] Headers configurados para consulta de titular")

	// Configurar parâmetros da consulta
	params := url.Values{}
	params.Add("ip", fmt.Sprintf("eq.%s", ipMaquina))
	params.Add("select", "uid,titular")
	log.Printf("[DEBUG] Parâmetros da consulta: ip=eq.%s, select=uid,titular", ipMaquina)

	// Construir a URL completa com os parâmetros
	reqURL := fmt.Sprintf("%s?%s", endpoint, params.Encode())
	log.Printf("[DEBUG] URL completa para consulta de titular: %s", reqURL)

	// Criar e enviar a requisição
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("erro ao criar requisição: %v", err)
	}

	// Adicionar headers
	for key, value := range headers {
		req.Header.Add(key, value)
	}

	// Enviar a requisição
	log.Printf("[DEBUG] Enviando requisição para consultar titular")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[DEBUG] ERRO: Falha ao enviar requisição para consultar titular: %v", err)
		return "", fmt.Errorf("erro ao enviar requisição: %v", err)
	}
	log.Printf("[DEBUG] Resposta recebida. Status: %d %s", resp.StatusCode, resp.Status)
	defer resp.Body.Close()

	// Verificar o status da resposta
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[DEBUG] ERRO: Resposta com status %d ao consultar titular. Corpo: %s", resp.StatusCode, string(body))
		return "", fmt.Errorf("erro ao consultar titular. Status: %d, Resposta: %s", resp.StatusCode, string(body))
	}

	// Ler e decodificar a resposta
	var data []struct {
		UID     string `json:"uid"`
		Titular string `json:"titular"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[DEBUG] ERRO: Falha ao ler resposta ao consultar titular: %v", err)
		return "", fmt.Errorf("erro ao ler resposta: %v", err)
	}
	log.Printf("[DEBUG] Corpo da resposta: %s", string(body))

	err = json.Unmarshal(body, &data)
	if err != nil {
		log.Printf("[DEBUG] ERRO: Falha ao decodificar resposta ao consultar titular: %v", err)
		return "", fmt.Errorf("erro ao decodificar resposta: %v", err)
	}

	// Verificar se encontrou algum resultado
	if len(data) == 0 {
		log.Printf("[DEBUG] AVISO: Nenhum servidor encontrado com o IP: %s", ipMaquina)
		// Usar um UUID padrão válido quando não encontrar o servidor
		return "00000000-0000-0000-0000-000000000000", nil
	}

	// Retornar o titular
	titular := data[0].Titular
	log.Printf("[DEBUG] Titular encontrado com sucesso: %s", titular)
	return titular, nil
}

// EnviarDockerStats envia estatísticas do Docker para o Supabase
func (c *Client) EnviarDockerStats(containers []models.ContainerStats, networkStats models.NetworkStats, ipMaquina, titular string) error {
	if !c.IsConfigured() {
		return fmt.Errorf("cliente Supabase não configurado")
	}

	log.Printf("Preparando envio de Docker stats para o Supabase...")

	// No formato antigo, enviamos diretamente a lista de containers
	// sem a estrutura aninhada com network, timestamp, etc.
	dados := map[string]interface{}{
		"ip":      ipMaquina,
		"titular": titular,
		"stats":   containers, // Enviar diretamente a lista de containers no formato antigo
	}

	// Tentar diferentes abordagens para enviar os dados
	return c.enviarParaTabela(dados, "docker_stats")
}

// EnviarVMStats envia métricas da VM para o Supabase
func (c *Client) EnviarVMStats(metricas models.SystemMetrics, ipMaquina, titular string) error {
	if !c.IsConfigured() {
		return fmt.Errorf("cliente Supabase não configurado")
	}

	log.Printf("Preparando envio de VM stats para o Supabase...")

	// Preparar os dados para envio
	dados := map[string]interface{}{
		"ip":             ipMaquina,
		"titular":        titular,
		"mem_total":      metricas.Memory.TotalGB,
		"mem_usada":      metricas.Memory.UsedGB,
		"mem_usada_p":    metricas.Memory.UsedPercent,
		"mem_disponivel": metricas.Memory.AvailableGB,
		"mem_disponivel_p": metricas.Memory.AvailablePercent,
		"cpu_total":      metricas.CPU.Cores,
		"cpu_usada":      metricas.CPU.UsedPercent,
		"cpu_livre":      metricas.CPU.IdlePercent,
		"disco_total":    metricas.Disk.TotalGB,
		"disco_usado":    metricas.Disk.UsedGB,
		"disco_livre":    metricas.Disk.AvailableGB,
		"disco_uso_p":    metricas.Disk.UsedPercent,
		"disco_livre_p":  metricas.Disk.FreePercent,
	}

	// Tentar diferentes abordagens para enviar os dados
	return c.enviarParaTabela(dados, "vm_stats")
}

// enviarParaTabela tenta diferentes abordagens para enviar dados para uma tabela do Supabase
func (c *Client) enviarParaTabela(dados map[string]interface{}, tabela string) error {
	log.Printf("[DEBUG] Iniciando envio de dados para tabela '%s' no Supabase", tabela)
	
	// Abordagem 1: Tentar com Content-Profile
	baseURL := strings.TrimSuffix(c.URL, "/")
	endpoint1 := fmt.Sprintf("%s/rest/v1/%s", baseURL, tabela)
	log.Printf("[DEBUG] Tentativa 1: Endpoint: %s", endpoint1)
	
	// Verificar se a tabela é banned_ips e adicionar o schema mtm explicitamente
	if tabela == "banned_ips" {
		// Usar o endpoint correto para a tabela banned_ips
		endpoint1 = fmt.Sprintf("%s/rest/v1/banned_ips", baseURL)
		log.Printf("[DEBUG] Tabela banned_ips detectada, usando endpoint sem schema explícito: %s", endpoint1)
	}

	headers1 := map[string]string{
		"apikey":          c.Key,
		"Authorization":   fmt.Sprintf("Bearer %s", c.Key),
		"Content-Type":    "application/json",
		"Prefer":          "return=minimal",
		"Content-Profile": "mtm", // Tentar com Content-Profile
	}
	log.Printf("[DEBUG] Tentativa 1: Headers: apikey=...%s, Content-Profile=mtm", c.Key[len(c.Key)-5:])

	log.Printf("[DEBUG] Executando Tentativa 1 para tabela '%s'", tabela)
	err1 := c.enviarRequest(endpoint1, headers1, dados)
	if err1 == nil {
		log.Printf("[DEBUG] Dados enviados com sucesso para %s (Tentativa 1)!", tabela)
		return nil
	}
	log.Printf("[DEBUG] Tentativa 1 falhou: %v", err1)

	// Abordagem 2: Tentar com ambos Content-Profile e Accept-Profile
	log.Printf("[DEBUG] Tentativa 2: Endpoint: %s (com Content-Profile e Accept-Profile)", endpoint1)
	headers2 := map[string]string{
		"apikey":          c.Key,
		"Authorization":   fmt.Sprintf("Bearer %s", c.Key),
		"Content-Type":    "application/json",
		"Prefer":          "return=minimal",
		"Content-Profile": "mtm",
		"Accept-Profile":  "mtm",
	}
	log.Printf("[DEBUG] Tentativa 2: Headers: apikey=...%s, Content-Profile=mtm, Accept-Profile=mtm", c.Key[len(c.Key)-5:])

	log.Printf("[DEBUG] Executando Tentativa 2 para tabela '%s'", tabela)
	err2 := c.enviarRequest(endpoint1, headers2, dados)
	if err2 == nil {
		log.Printf("[DEBUG] Dados enviados com sucesso para %s (Tentativa 2)!", tabela)
		return nil
	}
	log.Printf("[DEBUG] Tentativa 2 falhou: %v", err2)

	// Abordagem 3: Tentar com o endpoint explícito para o schema mtm
	endpoint3 := fmt.Sprintf("%s/rest/v1/mtm/%s", baseURL, tabela)
	log.Printf("[DEBUG] Tentativa 3: Endpoint: %s (com schema explícito)", endpoint3)

	headers3 := map[string]string{
		"apikey":        c.Key,
		"Authorization": fmt.Sprintf("Bearer %s", c.Key),
		"Content-Type":  "application/json",
		"Prefer":        "return=minimal",
	}
	log.Printf("[DEBUG] Tentativa 3: Headers: apikey=...%s, sem perfil", c.Key[len(c.Key)-5:])

	log.Printf("[DEBUG] Executando Tentativa 3 para tabela '%s'", tabela)
	err3 := c.enviarRequest(endpoint3, headers3, dados)
	if err3 == nil {
		log.Printf("[DEBUG] Dados enviados com sucesso para %s (Tentativa 3)!", tabela)
		return nil
	}
	log.Printf("[DEBUG] Tentativa 3 falhou: %v", err3)

	// Se todas as tentativas falharem, retornar um erro com detalhes
	log.Printf("[DEBUG] ERRO: Todas as tentativas falharam ao enviar dados para tabela '%s'", tabela)
	return fmt.Errorf("falha ao enviar dados para %s: %v, %v, %v", tabela, err1, err2, err3)
}

// enviarRequest envia uma requisição HTTP POST para o endpoint especificado
func (c *Client) enviarRequest(endpoint string, headers map[string]string, dados interface{}) error {
	log.Printf("[DEBUG] Preparando requisição para endpoint: %s", endpoint)
	
	// Serializar os dados para JSON
	jsonData, err := json.Marshal(dados)
	if err != nil {
		log.Printf("[DEBUG] ERRO: Falha ao serializar dados: %v", err)
		return fmt.Errorf("erro ao serializar dados: %v", err)
	}
	log.Printf("[DEBUG] Dados serializados: %s", string(jsonData))

	// Criar a requisição
	log.Printf("[DEBUG] Criando requisição POST para: %s", endpoint)
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("[DEBUG] ERRO: Falha ao criar requisição: %v", err)
		return fmt.Errorf("erro ao criar requisição: %v", err)
	}

	// Adicionar headers
	for key, value := range headers {
		req.Header.Add(key, value)
	}

	// Enviar a requisição
	log.Printf("[DEBUG] Enviando requisição HTTP POST...")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[DEBUG] ERRO: Falha ao enviar requisição: %v", err)
		return fmt.Errorf("erro ao enviar requisição: %v", err)
	}
	log.Printf("[DEBUG] Resposta recebida. Status: %d %s", resp.StatusCode, resp.Status)
	defer resp.Body.Close()

	// Verificar o status da resposta
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[DEBUG] ERRO: Resposta com status %d. Corpo: %s", resp.StatusCode, string(body))
		return fmt.Errorf("erro na resposta. Status: %d, Corpo: %s", resp.StatusCode, string(body))
	}

	log.Printf("[DEBUG] Requisição bem-sucedida. Status: %d %s", resp.StatusCode, resp.Status)
	return nil
}
