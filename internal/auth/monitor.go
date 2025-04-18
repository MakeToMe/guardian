package auth

import (
	"bufio"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MakeToMe/mtm_guardian/internal/collector"
	"github.com/MakeToMe/mtm_guardian/internal/models"
)

const (
	// Número máximo de tentativas antes do banimento
	MaxAttempts = 3
	
	// Intervalo de tempo para considerar tentativas (60 segundos)
	AttemptInterval = 60 * time.Second
	
	// Caminho do arquivo de log de autenticação
	AuthLogPath = "/var/log/auth.log"
	
	// Caminho alternativo para sistemas que usam journalctl
	JournalLogCmd = "journalctl -u sshd -n 1000 --no-pager"
)

// Monitor monitora os logs de autenticação para detectar tentativas de login falhas
type Monitor struct {
	IPAttempts     map[string]*models.IPAttempt
	mu             sync.Mutex
	banCallback    func(string, int, time.Time, time.Time) error
	isWindows      bool
	lastProcessed  time.Time
	stopChan       chan struct{}
}

// NewMonitor cria um novo monitor de logs de autenticação
func NewMonitor(banCallback func(string, int, time.Time, time.Time) error) *Monitor {
	return &Monitor{
		IPAttempts:    make(map[string]*models.IPAttempt),
		banCallback:   banCallback,
		isWindows:     isWindowsOS(),
		lastProcessed: time.Now().Add(-1 * time.Hour), // Começar processando logs da última hora
		stopChan:      make(chan struct{}),
	}
}

// Start inicia o monitoramento de logs
func (m *Monitor) Start() {
	go m.monitorLoop()
}

// Stop para o monitoramento de logs
func (m *Monitor) Stop() {
	close(m.stopChan)
}

// monitorLoop é o loop principal de monitoramento
func (m *Monitor) monitorLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.checkLogs()
		case <-m.stopChan:
			return
		}
	}
}

// checkLogs verifica os logs de autenticação
func (m *Monitor) checkLogs() {
	log.Printf("[DEBUG] Verificando logs de autenticação...")
	if m.isWindows {
		// No Windows, usamos o Event Log
		log.Printf("[DEBUG] Sistema operacional Windows detectado, verificando Event Log")
		m.checkWindowsEventLog()
	} else {
		// No Linux, usamos comandos shell para ler os logs diretamente do host
		log.Printf("[DEBUG] Sistema operacional Linux detectado, usando comandos shell para ler logs")
		
		// Primeiro verificar quais arquivos de log existem
		log.Printf("[DEBUG] Verificando quais arquivos de log estão disponíveis")
		comando := "ls -la /var/log/ | grep -E 'auth.log|secure|syslog'"
		output, err := collector.ExecutarComando(comando)
		if err == nil {
			log.Printf("[DEBUG] Arquivos de log encontrados:\n%s", output)
		} else {
			log.Printf("[DEBUG] Erro ao listar arquivos de log: %v", err)
		}
		
		// Tentar ler auth.log sem sudo primeiro
		log.Printf("[DEBUG] Tentando ler auth.log sem sudo")
		comando = "grep \"Failed password\" /var/log/auth.log 2>/dev/null"
		output, err = collector.ExecutarComando(comando)
		
		if err != nil || len(output) == 0 {
			// Tentar com sudo
			log.Printf("[DEBUG] Tentando ler auth.log com sudo")
			comando = "sudo grep \"Failed password\" /var/log/auth.log 2>/dev/null"
			output, err = collector.ExecutarComando(comando)
			
			if err != nil || len(output) == 0 {
				// Tentar auth.log.1 (arquivo rotacionado)
				log.Printf("[DEBUG] Tentando ler arquivo rotacionado auth.log.1")
				comando = "grep \"Failed password\" /var/log/auth.log.1 2>/dev/null || sudo grep \"Failed password\" /var/log/auth.log.1 2>/dev/null"
				output, err = collector.ExecutarComando(comando)
				
				if err != nil || len(output) == 0 {
					// Tentar secure (CentOS/RHEL)
					log.Printf("[DEBUG] Tentando ler arquivo secure (CentOS/RHEL)")
					comando = "grep \"Failed password\" /var/log/secure 2>/dev/null || sudo grep \"Failed password\" /var/log/secure 2>/dev/null"
					output, err = collector.ExecutarComando(comando)
					
					if err != nil || len(output) == 0 {
						// Tentar syslog (alternativo)
						log.Printf("[DEBUG] Tentando ler arquivo syslog")
						comando = "grep \"Failed password\" /var/log/syslog 2>/dev/null || sudo grep \"Failed password\" /var/log/syslog 2>/dev/null"
						output, err = collector.ExecutarComando(comando)
						
						if err != nil || len(output) == 0 {
							// Tentar journalctl como último recurso
							log.Printf("[DEBUG] Nenhum arquivo de log encontrado, tentando journalctl")
							m.checkJournalctl()
							return
						}
					}
				}
			}
		}
		
		// Processar a saída do comando grep
		log.Printf("[DEBUG] Logs encontrados, processando %d bytes", len(output))
		linhas := strings.Split(string(output), "\n")
		linhasProcessadas := 0
		linhasRelevantes := 0
		
		for _, linha := range linhas {
			if linha == "" {
				continue
			}
			
			linhasProcessadas++
			linhasRelevantes++
			log.Printf("[DEBUG] Linha relevante encontrada: %s", linha)
			m.processLogLine(linha)
		}
		
		log.Printf("[DEBUG] Processamento concluído. Processadas %d linhas, todas relevantes", linhasProcessadas)
		
		// Verificar IPs com mais de 3 tentativas usando shell
		log.Printf("[DEBUG] Verificando IPs com mais de 3 tentativas falhas...")
		comando = "sudo grep \"Failed password\" /var/log/auth.log /var/log/auth.log.1 | grep -oE \"\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b\" | sort | uniq -c | sort -nr"
		output, err = collector.ExecutarComando(comando)
		
		if err == nil {
			log.Printf("[DEBUG] Resultado da contagem de tentativas por IP:\n%s", string(output))
			
			// Processar os resultados e banir IPs com mais de 3 tentativas
			m.banIPsWithMultipleAttempts(string(output))
		} else {
			log.Printf("[DEBUG] Erro ao contar tentativas por IP: %v", err)
		}
	}
	
	// Limpar tentativas antigas
	m.cleanupOldAttempts()
}

// checkAuthLog verifica o arquivo auth.log no Linux
func (m *Monitor) checkAuthLog() {
	log.Printf("[DEBUG] Tentando abrir arquivo de log de autenticação: %s", AuthLogPath)
	file, err := os.Open(AuthLogPath)
	if err != nil {
		log.Printf("Erro ao abrir arquivo de log: %v", err)
		return
	}
	defer file.Close()

	log.Printf("[DEBUG] Arquivo de log aberto com sucesso, iniciando leitura")
	linhasProcessadas := 0
	linhasRelevantes := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		linhasProcessadas++
		
		// Verificar se a linha contém padrões de tentativa de login falha antes de processar
		contemPadrao := strings.Contains(line, "Failed password") || 
			strings.Contains(line, "Invalid user") ||
			strings.Contains(line, "authentication failure") ||
			strings.Contains(line, "Failed none") ||
			strings.Contains(line, "Connection closed by invalid user") ||
			strings.Contains(line, "Connection reset by invalid user") ||
			strings.Contains(line, "Disconnected from invalid user")
		
		if contemPadrao {
			linhasRelevantes++
			log.Printf("[DEBUG] Linha relevante encontrada: %s", line)
		}
		
		m.processLogLine(line)
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Erro ao ler arquivo de log: %v", err)
	}
	
	log.Printf("[DEBUG] Leitura do arquivo de log concluída. Processadas %d linhas, %d relevantes", linhasProcessadas, linhasRelevantes)
}

// checkJournalctl verifica logs via journalctl
func (m *Monitor) checkJournalctl() {
	log.Printf("[DEBUG] Tentando obter logs via journalctl")
	
	// Verificar se journalctl está disponível
	comando := "which journalctl || command -v journalctl"
	output, err := collector.ExecutarComando(comando)
	if err != nil || len(output) == 0 {
		log.Printf("[DEBUG] journalctl não encontrado no sistema: %v", err)
		return
	}
	
	// Tentar primeiro sem sudo
	log.Printf("[DEBUG] Tentando executar journalctl sem sudo")
	comando = "journalctl -u ssh -n 1000 --no-pager --since=\"2 days ago\" 2>/dev/null"
	output, err = collector.ExecutarComando(comando)
	
	// Se falhar, tentar com sudo
	if err != nil || len(output) == 0 {
		log.Printf("[DEBUG] Erro ao executar journalctl sem sudo: %v. Tentando com sudo...", err)
		comando = "sudo journalctl -u ssh -n 1000 --no-pager --since=\"2 days ago\" 2>/dev/null"
		log.Printf("[DEBUG] Executando comando no shell do host: %s", comando)
		output, err = collector.ExecutarComando(comando)
		
		if err != nil || len(output) == 0 {
			log.Printf("[DEBUG] Erro ao executar journalctl com ssh: %v. Tentando com sshd...", err)
			// Tentar com sshd em vez de ssh
			comando = "sudo journalctl -u sshd -n 1000 --no-pager --since=\"2 days ago\" 2>/dev/null"
			output, err = collector.ExecutarComando(comando)
			
			if err != nil || len(output) == 0 {
				log.Printf("[DEBUG] Erro ao executar journalctl com sshd: %v. Tentando sem filtro de unidade...", err)
				// Tentar sem especificar a unidade, apenas filtrando por "Failed password"
				comando = "sudo journalctl --grep=\"Failed password\" -n 1000 --no-pager --since=\"2 days ago\" 2>/dev/null"
				output, err = collector.ExecutarComando(comando)
				
				if err != nil || len(output) == 0 {
					// Última tentativa: procurar por qualquer log relacionado a SSH
					log.Printf("[DEBUG] Erro ao executar journalctl sem filtro de unidade: %v. Tentando com grep para SSH...", err)
					comando = "sudo journalctl | grep -i ssh 2>/dev/null"
					output, err = collector.ExecutarComando(comando)
					
					if err != nil || len(output) == 0 {
						log.Printf("[DEBUG] Todas as tentativas de obter logs via journalctl falharam")
						return
					}
				}
			}
		}
	}
	
	log.Printf("[DEBUG] Logs obtidos via journalctl, processando %d bytes", len(output))
	
	// Processar cada linha do output
	linhas := strings.Split(string(output), "\n")
	linhasProcessadas := 0
	linhasRelevantes := 0
	
	for _, linha := range linhas {
		if strings.Contains(linha, "Failed password") {
			linhasRelevantes++
			log.Printf("[DEBUG] Linha relevante encontrada via journalctl: %s", linha)
		}
		
		m.processLogLine(linha)
		linhasProcessadas++
	}
	
	log.Printf("[DEBUG] Processamento de logs via journalctl concluído. Processadas %d linhas, %d relevantes", linhasProcessadas, linhasRelevantes)
	
	// Verificar IPs com mais de 3 tentativas usando journalctl
	log.Printf("[DEBUG] Verificando IPs com mais de 3 tentativas falhas via journalctl...")
	comando = "sudo journalctl -u ssh -u sshd --since=\"2 days ago\" | grep \"Failed password\" | grep -oE \"\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b\" | sort | uniq -c | sort -nr"
	output, err = collector.ExecutarComando(comando)
	
	if err == nil && len(output) > 0 {
		log.Printf("[DEBUG] Resultado da contagem de tentativas por IP via journalctl:\n%s", string(output))
		
		// Processar os resultados e banir IPs com mais de 3 tentativas
		m.banIPsWithMultipleAttempts(string(output))
	} else {
		log.Printf("[DEBUG] Erro ao contar tentativas por IP via journalctl: %v", err)
	}
}

// checkAlternativeLog verifica um arquivo de log alternativo
func (m *Monitor) checkAlternativeLog(logPath string) {
	log.Printf("[DEBUG] Tentando abrir arquivo de log alternativo: %s", logPath)
	file, err := os.Open(logPath)
	if err != nil {
		log.Printf("[DEBUG] Erro ao abrir arquivo de log alternativo %s: %v", logPath, err)
		return
	}
	defer file.Close()

	log.Printf("[DEBUG] Arquivo de log alternativo %s aberto com sucesso, iniciando leitura", logPath)
	linhasProcessadas := 0
	linhasRelevantes := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		linhasProcessadas++
		
		// Verificar se a linha contém padrões de tentativa de login falha antes de processar
		contemPadrao := strings.Contains(line, "Failed password") || 
			strings.Contains(line, "Invalid user") ||
			strings.Contains(line, "authentication failure") ||
			strings.Contains(line, "Failed none") ||
			strings.Contains(line, "Connection closed by invalid user") ||
			strings.Contains(line, "Connection reset by invalid user") ||
			strings.Contains(line, "Disconnected from invalid user")
		
		if contemPadrao {
			linhasRelevantes++
			log.Printf("[DEBUG] Linha relevante encontrada em %s: %s", logPath, line)
		}
		
		m.processLogLine(line)
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[DEBUG] Erro ao ler arquivo de log alternativo %s: %v", logPath, err)
	}
	
	log.Printf("[DEBUG] Leitura do arquivo de log alternativo %s concluída. Processadas %d linhas, %d relevantes", logPath, linhasProcessadas, linhasRelevantes)
}

// checkWindowsEventLog verifica o Event Log no Windows
func (m *Monitor) checkWindowsEventLog() {
	// Implementação para Windows usando a API do Event Log
	// Omitido para simplificar
}

// banIPsWithMultipleAttempts processa a saída do comando de contagem e bane IPs com mais de 3 tentativas
func (m *Monitor) banIPsWithMultipleAttempts(output string) {
	log.Printf("[DEBUG] Processando IPs com múltiplas tentativas para banimento...")
	
	// Processar cada linha do output
	linhas := strings.Split(output, "\n")
	for _, linha := range linhas {
		// Ignorar linhas vazias
		if strings.TrimSpace(linha) == "" {
			continue
		}
		
		// Extrair contagem e IP
		parts := strings.Fields(linha)
		if len(parts) < 2 {
			log.Printf("[DEBUG] Formato de linha inválido: %s", linha)
			continue
		}
		
		// Primeira parte é a contagem, segunda parte é o IP
		contagemStr := parts[0]
		ip := parts[1]
		
		// Converter contagem para inteiro
		contagem, err := strconv.Atoi(contagemStr)
		if err != nil {
			log.Printf("[DEBUG] Erro ao converter contagem '%s' para inteiro: %v", contagemStr, err)
			continue
		}
		
		// Verificar se a contagem é maior ou igual a 3
		if contagem >= 3 {
			log.Printf("[DEBUG] IP %s tem %d tentativas falhas, iniciando processo de banimento", ip, contagem)
			
			// Criar registros de tentativas para este IP
			// Não precisamos criar timestamps simulados, apenas registrar as tentativas
			
			// Registrar as tentativas e banir o IP
			m.recordFailedAttempt(ip)
			m.recordFailedAttempt(ip)
			m.recordFailedAttempt(ip)
			
			log.Printf("[DEBUG] IP %s banido com sucesso após %d tentativas detectadas", ip, contagem)
		} else {
			log.Printf("[DEBUG] IP %s tem apenas %d tentativas, abaixo do limite para banimento", ip, contagem)
		}
	}
	
	log.Printf("[DEBUG] Processamento de IPs com múltiplas tentativas concluído")
}

// processLogLine processa uma linha de log
func (m *Monitor) processLogLine(line string) {
	// Verificar se a linha contém uma tentativa de login falha
	// Ampliamos os padrões para detectar mais tipos de falhas
	padraoEncontrado := ""
	if strings.Contains(line, "Failed password") {
		padraoEncontrado = "Failed password"
	} else if strings.Contains(line, "Invalid user") {
		padraoEncontrado = "Invalid user"
	} else if strings.Contains(line, "authentication failure") {
		padraoEncontrado = "authentication failure"
	} else if strings.Contains(line, "Failed none") {
		padraoEncontrado = "Failed none"
	} else if strings.Contains(line, "Connection closed by invalid user") {
		padraoEncontrado = "Connection closed by invalid user"
	} else if strings.Contains(line, "Connection reset by invalid user") {
		padraoEncontrado = "Connection reset by invalid user"
	} else if strings.Contains(line, "Disconnected from invalid user") {
		padraoEncontrado = "Disconnected from invalid user"
	}
	
	if padraoEncontrado != "" {
		// Extrair o IP da linha
		ip := extractIPFromLogLine(line)
		if ip != "" {
			log.Printf("Detectada tentativa de login falha do IP: %s (Padrão: %s)", ip, padraoEncontrado)
			m.recordFailedAttempt(ip)
		} else {
			log.Printf("[DEBUG] Padrão de falha encontrado (%s), mas não foi possível extrair o IP da linha: %s", padraoEncontrado, line)
		}
	}
}

// extractIPFromLogLine extrai o endereço IP de uma linha de log
func extractIPFromLogLine(line string) string {
	// Regex para encontrar endereços IPv4 em diferentes formatos de log
	// Primeiro tenta encontrar o padrão "from IP" que é comum em logs SSH
	re1 := regexp.MustCompile(`from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	matches := re1.FindStringSubmatch(line)
	if len(matches) > 1 {
		return matches[1] // O grupo de captura é o IP
	}
	
	// Se não encontrar no padrão anterior, tenta um padrão mais genérico
	re2 := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	matches = re2.FindStringSubmatch(line)
	if len(matches) > 0 {
		return matches[0]
	}
	
	return ""
}

// recordFailedAttempt registra uma tentativa de login falha
func (m *Monitor) recordFailedAttempt(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	now := time.Now()
	
	// Obter ou criar registro de tentativas para este IP
	attempt, exists := m.IPAttempts[ip]
	if !exists {
		log.Printf("[DEBUG] Primeira tentativa de login falha detectada para o IP: %s", ip)
		attempt = &models.IPAttempt{
			IP:        ip,
			Attempts:  0,
			FirstSeen: now,
		}
		m.IPAttempts[ip] = attempt
	}
	
	// Incrementar contagem de tentativas
	attempt.Attempts++
	log.Printf("[DEBUG] IP %s: Tentativa %d/%d (Primeira: %s, Última: %s, Intervalo: %v)", 
		ip, attempt.Attempts, MaxAttempts, 
		attempt.FirstSeen.Format("15:04:05"), 
		now.Format("15:04:05"),
		now.Sub(attempt.FirstSeen))
	
	attempt.LastSeen = now
	
	// Verificar se deve banir
	if !attempt.Banned && 
	   attempt.Attempts >= MaxAttempts && 
	   now.Sub(attempt.FirstSeen) <= AttemptInterval {
		
		log.Printf("[DEBUG] Iniciando processo de banimento para IP %s (%d tentativas em %v)", 
			ip, attempt.Attempts, now.Sub(attempt.FirstSeen))
		
		attempt.Banned = true
		attempt.BanTime = now
		
		// Chamar callback para banir o IP
		if m.banCallback != nil {
			log.Printf("[DEBUG] Chamando callback de banimento para IP %s", ip)
			if err := m.banCallback(ip, attempt.Attempts, attempt.FirstSeen, attempt.LastSeen); err != nil {
				log.Printf("Erro ao banir IP %s: %v", ip, err)
			} else {
				log.Printf("IP %s banido após %d tentativas em %v", 
					ip, attempt.Attempts, now.Sub(attempt.FirstSeen))
			}
		} else {
			log.Printf("[DEBUG] Callback de banimento não está configurado para IP %s", ip)
		}
	} else if attempt.Banned {
		log.Printf("[DEBUG] IP %s já está banido, ignorando nova tentativa", ip)
	} else if attempt.Attempts < MaxAttempts {
		log.Printf("[DEBUG] IP %s ainda não atingiu o limite de tentativas (%d/%d)", ip, attempt.Attempts, MaxAttempts)
	} else if now.Sub(attempt.FirstSeen) > AttemptInterval {
		log.Printf("[DEBUG] Intervalo de tempo excedido para IP %s (%v > %v)", ip, now.Sub(attempt.FirstSeen), AttemptInterval)
	}
}

// cleanupOldAttempts limpa tentativas antigas
func (m *Monitor) cleanupOldAttempts() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	now := time.Now()
	for ip, attempt := range m.IPAttempts {
		// Se não estiver banido e a última tentativa foi há mais de 1 hora, remover
		if !attempt.Banned && now.Sub(attempt.LastSeen) > time.Hour {
			delete(m.IPAttempts, ip)
		}
	}
}

// ProcessLoginHistory processa o histórico de tentativas falhas de login e registra no Supabase
// Pode ser chamado manualmente para processar logs antigos
func (m *Monitor) ProcessLoginHistory() error {
	log.Printf("[DEBUG] Processando histórico de tentativas falhas de login...")
	
	// Comando para contar tentativas falhas por IP
	var comando string
	if m.isWindows {
		// No Windows, não temos um comando equivalente
		log.Printf("[DEBUG] Processamento de histórico não suportado no Windows")
		return nil
	} else {
		// No Linux, usar grep, sort, uniq para contar tentativas por IP
		comando = "grep \"Failed password\" /var/log/auth.log | grep -oE \"\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b\" | sort | uniq -c | sort -nr"
	}
	
	log.Printf("[DEBUG] Executando comando: %s", comando)
	output, err := collector.ExecutarComando(comando)
	if err != nil {
		log.Printf("[DEBUG] Erro ao executar comando: %v", err)
		return err
	}
	
	log.Printf("[DEBUG] Processando resultado do comando (%d bytes)", len(output))
	
	// Processar resultado e banir IPs com mais de 3 tentativas
	m.banIPsWithMultipleAttempts(output)
	
	return nil
}



// isWindowsOS verifica se o sistema operacional é Windows
func isWindowsOS() bool {
	return os.PathSeparator == '\\' && os.PathListSeparator == ';'
}
