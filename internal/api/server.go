package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/MakeToMe/mtm_guardian/internal/auth"
	"github.com/MakeToMe/mtm_guardian/internal/firewall"
)

// Server representa o servidor da API
type Server struct {
	firewallManager *firewall.FirewallManager
	authMonitor     *auth.Monitor
	port            string
}

// NewServer cria um novo servidor de API
func NewServer(firewallManager *firewall.FirewallManager, authMonitor *auth.Monitor, port string) *Server {
	return &Server{
		firewallManager: firewallManager,
		authMonitor:     authMonitor,
		port:            port,
	}
}

// Start inicia o servidor da API
func (s *Server) Start() error {
	// Configurar rotas
	http.HandleFunc("/api/unban", s.handleUnban)
	http.HandleFunc("/api/health", s.handleHealth)
	http.HandleFunc("/api/banned-ips", s.handleListBannedIPs)
	http.HandleFunc("/api/process-history", s.handleProcessHistory)

	// Iniciar servidor
	log.Printf("Iniciando servidor API na porta %s", s.port)
	return http.ListenAndServe(":"+s.port, nil)
}

// UnbanRequest representa uma solicitação para desbanir um IP
type UnbanRequest struct {
	IP string `json:"ip"`
}

// APIResponse representa uma resposta da API
type APIResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// handleUnban processa solicitações para desbanir IPs
func (s *Server) handleUnban(w http.ResponseWriter, r *http.Request) {
	// Verificar método HTTP
	if r.Method != http.MethodPost {
		sendJSONResponse(w, http.StatusMethodNotAllowed, APIResponse{
			Success: false,
			Message: "Método não permitido. Use POST.",
		})
		return
	}

	// Decodificar solicitação
	var req UnbanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Erro ao decodificar solicitação: " + err.Error(),
		})
		return
	}

	// Validar IP
	if req.IP == "" {
		sendJSONResponse(w, http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "IP não fornecido",
		})
		return
	}

	// Verificar se o IP está banido
	if !s.firewallManager.IsIPBanned(req.IP) {
		sendJSONResponse(w, http.StatusOK, APIResponse{
			Success: true,
			Message: "IP não está banido",
		})
		return
	}

	// Desbanir IP
	if err := s.firewallManager.UnbanIP(req.IP); err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Erro ao desbanir IP: " + err.Error(),
		})
		return
	}

	// Responder com sucesso
	sendJSONResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Message: "IP desbanido com sucesso",
	})
}

// handleHealth verifica a saúde do serviço
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	sendJSONResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Message: "Serviço funcionando normalmente",
	})
}

// sendJSONResponse envia uma resposta JSON
func sendJSONResponse(w http.ResponseWriter, statusCode int, response interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// handleListBannedIPs lista os IPs banidos no firewall
func (s *Server) handleListBannedIPs(w http.ResponseWriter, r *http.Request) {
	// Verificar método HTTP
	if r.Method != http.MethodGet {
		sendJSONResponse(w, http.StatusMethodNotAllowed, APIResponse{
			Success: false,
			Message: "Método não permitido",
		})
		return
	}
	
	// Obter lista de IPs banidos
	output, err := s.firewallManager.ListBannedIPs()
	if err != nil {
		log.Printf("Erro ao listar IPs banidos: %v", err)
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Erro ao listar IPs banidos: " + err.Error(),
		})
		return
	}
	
	// Enviar resposta
	sendJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "IPs banidos listados com sucesso",
		"data": output,
	})
}

// handleProcessHistory processa o histórico de tentativas falhas de login
func (s *Server) handleProcessHistory(w http.ResponseWriter, r *http.Request) {
	// Verificar método HTTP
	if r.Method != http.MethodPost {
		sendJSONResponse(w, http.StatusMethodNotAllowed, APIResponse{
			Success: false,
			Message: "Método não permitido",
		})
		return
	}
	
	// Verificar se o monitor de autenticação está disponível
	if s.authMonitor == nil {
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Monitor de autenticação não disponível",
		})
		return
	}
	
	// Processar histórico
	err := s.authMonitor.ProcessLoginHistory()
	if err != nil {
		log.Printf("Erro ao processar histórico de login: %v", err)
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Erro ao processar histórico de login: " + err.Error(),
		})
		return
	}
	
	// Enviar resposta
	sendJSONResponse(w, http.StatusOK, APIResponse{
			Success: true,
			Message: "Histórico de login processado com sucesso",
		})
}
