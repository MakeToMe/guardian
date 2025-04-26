package api

import (
	"encoding/json"
	"log"
	"net/http"
)

// Server representa o servidor da API
// Nota: As funcionalidades de firewall e banimento foram removidas e serão implementadas em um serviço separado
type Server struct {
	port string
}

// NewServer cria um novo servidor de API
func NewServer(port string) *Server {
	return &Server{
		port: port,
	}
}

// Start inicia o servidor da API
func (s *Server) Start() error {
	// Configurar rotas
	http.HandleFunc("/api/health", s.handleHealth)

	// Iniciar servidor
	log.Printf("Iniciando servidor API na porta %s", s.port)
	return http.ListenAndServe(":"+s.port, nil)
}

// Nota: Tipos e handlers relacionados ao firewall e banimento foram removidos
// Serão implementados no módulo separado de firewall

// APIResponse representa uma resposta da API
type APIResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// Nota: Os handlers relacionados ao firewall e banimento foram removidos

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

// Nota: Os handlers relacionados ao firewall e banimento foram removidos

// Nota: Os handlers relacionados ao firewall e banimento foram removidos
