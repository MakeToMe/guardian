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

	"github.com/MakeToMe/mtm_guardian/internal/collector"
	"github.com/MakeToMe/mtm_guardian/internal/models"
)

// BanStore implementa a interface SupabaseStore para gerenciar IPs banidos
type BanStore struct {
	client *Client
}

// NewBanStore cria um novo armazenamento para IPs banidos
func NewBanStore(client *Client) *BanStore {
	return &BanStore{
		client: client,
	}
}

// RegisterBannedIP registra um IP banido no Supabase
func (bs *BanStore) RegisterBannedIP(ip string, attempts int, firstAttempt, lastAttempt time.Time) error {
	log.Printf("[DEBUG] Iniciando registro do IP %s no Supabase (tentativas: %d, primeira: %s, última: %s)", 
		ip, attempts, firstAttempt.Format("15:04:05"), lastAttempt.Format("15:04:05"))
	
	// Verificar se o cliente está configurado
	if !bs.client.IsConfigured() {
		log.Printf("[DEBUG] ERRO: Cliente Supabase não configurado. URL: '%s', Key: '%s'", 
			bs.client.URL, bs.client.Key[:10]+"...")
		return fmt.Errorf("cliente Supabase não configurado")
	}
	
	log.Printf("[DEBUG] Cliente Supabase configurado corretamente. URL: %s", bs.client.URL)

	// Obter informações da máquina
	ipMaquina, err := collector.ObterIPMaquina()
	if err != nil {
		return fmt.Errorf("erro ao obter IP da máquina: %v", err)
	}

	// Obter o titular da máquina
	log.Printf("[DEBUG] Tentando obter titular para o IP %s", ipMaquina)
	titular, err := bs.client.ObterTitularPorIP(ipMaquina)
	if err != nil {
		log.Printf("[DEBUG] AVISO: Não foi possível obter o titular para o IP %s: %v", ipMaquina, err)
		// Usar um UUID padrão válido quando não conseguir obter o titular
		titular = "00000000-0000-0000-0000-000000000000" // UUID padrão válido
		log.Printf("[DEBUG] Usando UUID padrão para titular: %s", titular)
	} else {
		log.Printf("[DEBUG] Titular obtido com sucesso: %s", titular)
	}

	// Verificar se o IP já está banido no Supabase
	log.Printf("[DEBUG] Verificando se o IP %s já está banido no Supabase", ip)
	
	// Agora podemos verificar diretamente usando a coluna ip_banido
	// Construir a URL para a consulta
	query := fmt.Sprintf("ip_banido=eq.%s", url.QueryEscape(ip))
	// Tentar com o schema mtm explicitamente
	endpointURL := fmt.Sprintf("%s/rest/v1/mtm/banned_ips?%s", bs.client.URL, query)

	// Configurar headers
	headers := map[string]string{
		"apikey":        bs.client.Key,
		"Authorization": fmt.Sprintf("Bearer %s", bs.client.Key),
	}

	// Configurar a requisição
	req, err := http.NewRequest("GET", endpointURL, nil)
	if err != nil {
		return fmt.Errorf("erro ao criar requisição para verificar IP banido: %v", err)
	}

	// Adicionar headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Enviar requisição
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("erro ao enviar requisição para verificar IP banido: %v", err)
	}
	defer resp.Body.Close()

	// Verificar resposta
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("erro ao consultar IPs banidos, status: %d, resposta: %s", resp.StatusCode, string(body))
	}

	// Ler resposta
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("erro ao ler resposta: %v", err)
	}

	// Se o corpo da resposta for vazio ou "[]", não há IPs banidos
	if len(body) == 0 || string(body) == "[]" {
		// Tentar sem o schema mtm
		altEndpointURL := fmt.Sprintf("%s/rest/v1/banned_ips?%s", bs.client.URL, query)

		// Configurar headers
		headers := map[string]string{
			"apikey":          bs.client.Key,
			"Authorization":   fmt.Sprintf("Bearer %s", bs.client.Key),
			"Content-Type":    "application/json",
			"Accept":          "application/json",
			"Content-Profile": "mtm",
			"Accept-Profile":  "mtm",
		}

		// Configurar a requisição
		req, err := http.NewRequest("GET", altEndpointURL, nil)
		if err != nil {
			return fmt.Errorf("erro ao criar requisição para verificar IP banido: %v", err)
		}

		// Adicionar headers
		for key, value := range headers {
			req.Header.Set(key, value)
		}

		// Enviar requisição
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("erro ao enviar requisição para verificar IP banido: %v", err)
		}
		defer resp.Body.Close()

		// Verificar resposta
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("erro ao consultar IPs banidos, status: %d, resposta: %s", resp.StatusCode, string(body))
		}

		// Ler resposta
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("erro ao ler resposta: %v", err)
		}

		// Se o corpo da resposta for vazio ou "[]", não há IPs banidos
		if len(body) == 0 || string(body) == "[]" {
			// Se chegou até aqui, o IP não está banido
			log.Printf("[DEBUG] IP %s não está banido no Supabase. Prosseguindo com o registro.", ip)
		} else {
			// Se chegou até aqui, o IP já está banido
			log.Printf("[DEBUG] IP %s já está banido no Supabase. Não será criado um novo registro.", ip)
			return nil
		}
	} else {
		// Se chegou até aqui, o IP já está banido
		log.Printf("[DEBUG] IP %s já está banido no Supabase. Não será criado um novo registro.", ip)
		return nil
	}

	// Preparar dados para inserção
	log.Printf("[DEBUG] Preparando dados para inserção do IP %s no Supabase", ip)
	
	// Formatar datas no formato ISO 8601 para compatibilidade com o Supabase
	firstAttemptStr := firstAttempt.Format(time.RFC3339)
	lastAttemptStr := lastAttempt.Format(time.RFC3339)
	log.Printf("[DEBUG] Datas formatadas: first_attempt=%s, last_attempt=%s", firstAttemptStr, lastAttemptStr)
	
	// Primeiro, vamos verificar se existe um servidor com o IP que estamos tentando banir
	log.Printf("[DEBUG] Verificando se existe um servidor com o IP %s para obter o servidor_id", ip)
	
	// Consultar o servidor_id para o IP que está sendo banido
	servidorID, err := bs.obterServidorIDPorIP(ip)
	if err != nil {
		log.Printf("[DEBUG] AVISO: Não foi possível obter o servidor_id para o IP %s: %v", ip, err)
		// Continuar sem o servidor_id, já que pode não ser obrigatório
	}
	
	// Preparar os dados conforme a estrutura real da tabela
	dados := map[string]interface{}{
		"titular":       titular,
		"reason":        fmt.Sprintf("Múltiplas tentativas de login falhas (%d tentativas)", attempts),
		"source":        "auto",
		"attempts":      attempts,
		"first_attempt": firstAttemptStr,
		"last_attempt":  lastAttemptStr,
		"active":        true,
		"servidor_ip":   ipMaquina, // IP do servidor que está banindo
		"ip_banido":     ip,        // Usar a nova coluna ip_banido
	}
	
	// Adicionar o servidor_id se foi encontrado
	if servidorID != "" {
		dados["servidor_id"] = servidorID
		log.Printf("[DEBUG] Adicionado servidor_id %s para o IP banido %s", servidorID, ip)
	}
	
	log.Printf("[DEBUG] Dados preparados com a nova coluna ip_banido para o IP %s", ip)
	
	log.Printf("[DEBUG] Dados preparados: %+v", dados)

	// Usar o método enviarParaTabela do cliente Supabase que já está funcionando para outras tabelas
	log.Printf("[DEBUG] Enviando dados do IP %s para a tabela banned_ips no Supabase", ip)
	
	// Usar o método enviarParaTabela com a ordem correta dos parâmetros (dados, tabela)
	err = bs.client.enviarParaTabela(dados, "mtm/banned_ips")
	if err != nil {
		log.Printf("[DEBUG] AVISO: Falha ao registrar IP %s no Supabase com schema mtm: %v", ip, err)
		// Tentar sem o schema mtm, mas com os headers de perfil
		err = bs.client.enviarParaTabela(dados, "banned_ips")
		if err != nil {
			log.Printf("[DEBUG] ERRO: Falha ao registrar IP %s no Supabase: %v", ip, err)
			return fmt.Errorf("falha ao registrar IP banido: %v", err)
		}
	}

	log.Printf("[DEBUG] IP %s registrado com sucesso no Supabase", ip)
	return nil
}

// DeactivateBannedIP marca um IP como inativo no Supabase
func (bs *BanStore) DeactivateBannedIP(ip string) error {
	// Verificar se o cliente está configurado
	if !bs.client.IsConfigured() {
		return fmt.Errorf("cliente Supabase não configurado")
	}

	// Preparar dados para atualização
	dados := map[string]interface{}{
		"active": false,
	}

	// Configurar o endpoint para a tabela banned_ips
	baseURL := strings.TrimSuffix(bs.client.URL, "/")
	endpoint := fmt.Sprintf("%s/rest/v1/banned_ips?ip=eq.%s&active=eq.true", baseURL, url.QueryEscape(ip))

	// Configurar headers
	headers := map[string]string{
		"apikey":         bs.client.Key,
		"Authorization":  fmt.Sprintf("Bearer %s", bs.client.Key),
		"Content-Type":   "application/json",
		"Prefer":         "return=minimal",
	}

	// Criar requisição PATCH
	jsonData, err := json.Marshal(dados)
	if err != nil {
		return fmt.Errorf("erro ao serializar dados: %v", err)
	}

	req, err := http.NewRequest("PATCH", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("erro ao criar requisição: %v", err)
	}

	// Adicionar headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Enviar requisição
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("erro ao enviar requisição: %v", err)
	}
	defer resp.Body.Close()

	// Verificar resposta
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("erro ao desativar IP banido, status: %d, resposta: %s", resp.StatusCode, string(body))
	}

	log.Printf("IP %s marcado como inativo no Supabase", ip)
	return nil
}

// GetActiveBannedIPs obtém a lista de IPs banidos ativos
func (bs *BanStore) GetActiveBannedIPs() ([]models.BannedIP, error) {
	// Verificar se o cliente está configurado
	if !bs.client.IsConfigured() {
		return nil, fmt.Errorf("cliente Supabase não configurado")
	}

	// Configurar o endpoint para a tabela banned_ips
	baseURL := strings.TrimSuffix(bs.client.URL, "/")
	endpoint := fmt.Sprintf("%s/rest/v1/mtm/banned_ips?active=eq.true&select=*", baseURL)

	// Configurar headers
	headers := map[string]string{
		"apikey":        bs.client.Key,
		"Authorization": fmt.Sprintf("Bearer %s", bs.client.Key),
	}

	// Criar requisição GET
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("erro ao criar requisição: %v", err)
	}

	// Adicionar headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Enviar requisição
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("erro ao enviar requisição: %v", err)
	}
	defer resp.Body.Close()

	// Verificar resposta
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("erro ao consultar IPs banidos, status: %d, resposta: %s", resp.StatusCode, string(body))
	}

	// Decodificar resposta
	var bannedIPs []models.BannedIP
	if err := json.NewDecoder(resp.Body).Decode(&bannedIPs); err != nil {
		return nil, fmt.Errorf("erro ao decodificar resposta: %v", err)
	}

	return bannedIPs, nil
}

// obterServidorIDPorIP consulta o servidor_id correspondente ao IP na tabela servidores
func (bs *BanStore) obterServidorIDPorIP(ip string) (string, error) {
	log.Printf("[DEBUG] Consultando servidor_id para o IP: %s", ip)
	
	// Configurar o endpoint para a tabela servidores
	baseURL := strings.TrimSuffix(bs.client.URL, "/")
	endpoint := fmt.Sprintf("%s/rest/v1/mtm/servidores", baseURL) // Usar schema mtm explicitamente
	log.Printf("[DEBUG] Endpoint para consulta de servidor: %s", endpoint)
	
	// Configurar headers
	headers := map[string]string{
		"apikey":         bs.client.Key,
		"Authorization":  fmt.Sprintf("Bearer %s", bs.client.Key),
		"Accept-Profile": "mtm", // Especificar o schema mtm
		"Content-Type":   "application/json",
		"Accept":         "application/json",
	}
	
	// Configurar parâmetros da consulta
	params := url.Values{}
	params.Add("ip", fmt.Sprintf("eq.%s", ip))
	params.Add("select", "uid")
	
	// Construir a URL completa com os parâmetros
	reqURL := fmt.Sprintf("%s?%s", endpoint, params.Encode())
	log.Printf("[DEBUG] URL completa para consulta de servidor: %s", reqURL)
	
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
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[DEBUG] ERRO: Falha ao enviar requisição para consultar servidor: %v", err)
		return "", fmt.Errorf("erro ao enviar requisição: %v", err)
	}
	defer resp.Body.Close()
	
	// Verificar o status da resposta
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[DEBUG] ERRO: Resposta com status %d ao consultar servidor. Corpo: %s", resp.StatusCode, string(body))
		return "", fmt.Errorf("erro ao consultar servidor. Status: %d, Resposta: %s", resp.StatusCode, string(body))
	}
	
	// Ler e decodificar a resposta
	var data []struct {
		UID string `json:"uid"`
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[DEBUG] ERRO: Falha ao ler resposta ao consultar servidor: %v", err)
		return "", fmt.Errorf("erro ao ler resposta: %v", err)
	}
	
	err = json.Unmarshal(body, &data)
	if err != nil {
		log.Printf("[DEBUG] ERRO: Falha ao decodificar resposta ao consultar servidor: %v", err)
		return "", fmt.Errorf("erro ao decodificar resposta: %v", err)
	}
	
	// Verificar se encontrou algum resultado
	if len(data) == 0 {
		log.Printf("[DEBUG] AVISO: Nenhum servidor encontrado com o IP: %s", ip)
		return "", nil
	}
	
	// Retornar o UID do servidor
	servidorID := data[0].UID
	log.Printf("[DEBUG] Servidor encontrado com sucesso para o IP %s: %s", ip, servidorID)
	return servidorID, nil
}

// RegisterFirewallType registra um tipo de firewall no Supabase
func (bs *BanStore) RegisterFirewallType(firewallType string) error {
	// Verificar se o cliente está configurado
	if !bs.client.IsConfigured() {
		return fmt.Errorf("cliente Supabase não configurado")
	}

	// Obter informações da máquina
	ipMaquina, err := collector.ObterIPMaquina()
	if err != nil {
		return fmt.Errorf("erro ao obter IP da máquina: %v", err)
	}

	// Obter o titular da máquina
	titular, err := bs.client.ObterTitularPorIP(ipMaquina)
	if err != nil {
		log.Printf("Aviso: Não foi possível obter o titular para o IP %s: %v", ipMaquina, err)
		titular = "00000000-0000-0000-0000-000000000000" // UUID padrão válido
	}

	// Preparar dados para inserção
	dados := map[string]interface{}{
		"port":          22, // Porta SSH padrão
		"protocol":      "tcp",
		"action":        "allow",
		"description":   fmt.Sprintf("Regra padrão para firewall do tipo %s", firewallType),
		"source":        "0.0.0.0/0",
		"active":        true,
		"priority":      100,
		"titular":       titular,
		"firewall_type": firewallType,
		"servidor_ip":   ipMaquina, // Incluir o IP do servidor para facilitar a renderização no frontend
	}

	// Usar o método enviarParaTabela do cliente Supabase que já está funcionando para outras tabelas
	err = bs.client.enviarParaTabela(dados, "firewall_rules")
	if err != nil {
		return fmt.Errorf("erro ao registrar tipo de firewall: %v", err)
	}

	log.Printf("Tipo de firewall '%s' registrado com sucesso na tabela firewall_rules", firewallType)
	return nil
}

// verificarRegraExistente verifica se já existe uma regra para o IP e tipo de firewall especificados
func (bs *BanStore) verificarRegraExistente(ip, firewallType string) (bool, error) {
	if !bs.client.IsConfigured() {
		return false, fmt.Errorf("cliente Supabase não configurado")
	}

	// Configurar o endpoint para consultar a tabela firewall_rules
	baseURL := strings.TrimSuffix(bs.client.URL, "/")
	// Consultar por IP e tipo de firewall
	query := fmt.Sprintf("servidor_ip=eq.%s&firewall_type=eq.%s", ip, firewallType)
	endpoint := fmt.Sprintf("%s/rest/v1/firewall_rules?%s", baseURL, query)

	// Configurar headers
	headers := map[string]string{
		"apikey":          bs.client.Key,
		"Authorization":   fmt.Sprintf("Bearer %s", bs.client.Key),
		"Content-Type":    "application/json",
		"Accept":          "application/json",
		"Content-Profile": "mtm",
		"Accept-Profile":  "mtm",
	}

	// Criar requisição GET
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("erro ao criar requisição: %v", err)
	}

	// Adicionar headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Enviar requisição
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("erro ao enviar requisição: %v", err)
	}
	defer resp.Body.Close()

	// Verificar resposta
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("erro ao consultar regras de firewall, status: %d, resposta: %s", resp.StatusCode, string(body))
	}

	// Ler resposta
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("erro ao ler resposta: %v", err)
	}

	// Se o corpo da resposta for vazio ou "[]", não há regras
	if len(body) == 0 || string(body) == "[]" {
		return false, nil
	}

	// Se chegou até aqui, há pelo menos uma regra
	return true, nil
}

// verificarIPBanido verifica se um IP já está banido e ativo
func (bs *BanStore) verificarIPBanido(ip string) (bool, error) {
	if !bs.client.IsConfigured() {
		return false, fmt.Errorf("cliente Supabase não configurado")
	}

	// Configurar o endpoint para consultar a tabela banned_ips
	baseURL := strings.TrimSuffix(bs.client.URL, "/")
	// Consultar por IP e active=true
	query := fmt.Sprintf("ip=eq.%s&active=eq.true", ip)
	endpoint := fmt.Sprintf("%s/rest/v1/banned_ips?%s", baseURL, query)

	// Configurar headers
	headers := map[string]string{
		"apikey":          bs.client.Key,
		"Authorization":   fmt.Sprintf("Bearer %s", bs.client.Key),
		"Content-Type":    "application/json",
		"Accept":          "application/json",
		"Content-Profile": "mtm",
		"Accept-Profile":  "mtm",
	}

	// Criar requisição GET
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("erro ao criar requisição: %v", err)
	}

	// Adicionar headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Enviar requisição
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("erro ao enviar requisição: %v", err)
	}
	defer resp.Body.Close()

	// Verificar resposta
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("erro ao consultar IPs banidos, status: %d, resposta: %s", resp.StatusCode, string(body))
	}

	// Ler resposta
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("erro ao ler resposta: %v", err)
	}

	// Se o corpo da resposta for vazio ou "[]", não há IPs banidos
	if len(body) == 0 || string(body) == "[]" {
		return false, nil
	}

	// Se chegou até aqui, o IP já está banido
	return true, nil
}
