package firewall

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/MakeToMe/mtm_guardian/internal/collector"
	"github.com/MakeToMe/mtm_guardian/internal/models"
)

// FirewallManager gerencia as regras de firewall do sistema
type FirewallManager struct {
	mu            sync.Mutex
	isWindows     bool
	bannedIPs     map[string]bool
	supabaseStore SupabaseStore
	firewallType  string // Tipo de firewall em uso: "windows", "iptables", "ufw", "firewalld", etc.
	manageFirewall bool // Se devemos gerenciar o firewall ou não
}

// SupabaseStore define a interface para interagir com o Supabase
type SupabaseStore interface {
	RegisterBannedIP(ip string, attempts int, firstAttempt, lastAttempt time.Time) error
	DeactivateBannedIP(ip string) error
	GetActiveBannedIPs() ([]models.BannedIP, error)
	RegisterFirewallType(firewallType string) error
}

// NewFirewallManager cria uma nova instância do gerenciador de firewall
func NewFirewallManager(store SupabaseStore) *FirewallManager {
	// Verificar se o gerenciamento de firewall está ativado
	manageFirewall := true
	if os.Getenv("MANAGE_FIREWALL") == "false" {
		manageFirewall = false
	}

	return &FirewallManager{
		isWindows:     runtime.GOOS == "windows",
		bannedIPs:     make(map[string]bool),
		supabaseStore: store,
		manageFirewall: manageFirewall,
	}
}

// getServerIP obtém o IP do servidor
func (fm *FirewallManager) getServerIP() (string, error) {
	// Executar comando para obter o IP público
	cmd := exec.Command("curl", "-s", "ifconfig.me")
	output, err := cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		return strings.TrimSpace(string(output)), nil
	}
	
	// Tentar com outro serviço
	cmd = exec.Command("curl", "-s", "icanhazip.com")
	output, err = cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		return strings.TrimSpace(string(output)), nil
	}
	
	// Tentar obter o IP local
	cmd = exec.Command("hostname", "-I")
	output, err = cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		// Pegar o primeiro IP da lista
		ips := strings.Fields(string(output))
		if len(ips) > 0 {
			return ips[0], nil
		}
	}
	
	// Se tudo falhar, tentar com a interface de rede
	if !fm.isWindows {
		cmd = exec.Command("ip", "route", "get", "1.1.1.1")
		output, err = cmd.CombinedOutput()
		if err == nil {
			// Extrair o IP da saída
			re := regexp.MustCompile(`src\s+([0-9\.]+)`)
			matches := re.FindStringSubmatch(string(output))
			if len(matches) > 1 {
				return matches[1], nil
			}
		}
	}
	
	return "", fmt.Errorf("não foi possível obter o IP do servidor")
}

// Initialize inicializa o gerenciador de firewall
func (fm *FirewallManager) Initialize() error {
	// Obter IP da máquina para registrar na tabela de firewall_rules
	serverIP, err := fm.getServerIP()
	if err != nil {
		log.Printf("Aviso: Erro ao obter IP do servidor: %v", err)
		serverIP = "0.0.0.0" // Fallback
	}
	log.Printf("IP do servidor: %s", serverIP)

	// Verificar se devemos gerenciar o firewall
	if !fm.shouldManageFirewall() {
		log.Printf("Gerenciamento de firewall desativado por configuração. Usando firewall existente.")
		
		// Mesmo com o gerenciamento desativado, vamos detectar o tipo de firewall
		existingFirewalls, err := fm.detectExistingFirewalls()
		if err != nil {
			log.Printf("Aviso: Erro ao detectar firewalls existentes: %v", err)
		}
		
		if len(existingFirewalls) > 0 {
			fm.firewallType = existingFirewalls[0]
			log.Printf("Firewall detectado: %s (apenas para registro)", fm.firewallType)
			
			// Registrar o tipo de firewall no Supabase mesmo com gerenciamento desativado
			if err := fm.supabaseStore.RegisterFirewallType(fm.firewallType); err != nil {
				log.Printf("Aviso: Erro ao registrar tipo de firewall no Supabase: %v", err)
			} else {
				log.Printf("Tipo de firewall '%s' registrado no Supabase", fm.firewallType)
			}
		} else {
			log.Printf("Nenhum firewall detectado")
			// Registrar como 'unknown' no Supabase
			if err := fm.supabaseStore.RegisterFirewallType("unknown"); err != nil {
				log.Printf("Aviso: Erro ao registrar tipo de firewall 'unknown' no Supabase: %v", err)
			} else {
				log.Printf("Tipo de firewall 'unknown' registrado no Supabase")
			}
		}
		
		return nil
	}

	// Verificar se existe algum firewall ativo no sistema
	existingFirewalls, err := fm.detectExistingFirewalls()
	if err != nil {
		log.Printf("Aviso: Erro ao detectar firewalls existentes: %v", err)
	}

	if len(existingFirewalls) > 0 {
		log.Printf("Firewalls existentes detectados: %v", existingFirewalls)
		log.Printf("Usando firewall existente em vez de instalar um novo")
		fm.firewallType = existingFirewalls[0]
		
		// Se o firewall estiver disponível mas não ativo, vamos ativá-lo
		if fm.firewallType == "ufw" || fm.firewallType == "iptables" {
			log.Printf("Firewall de borda %s detectado, verificando se está ativo", fm.firewallType)
			
			// Verificar se o firewall está ativo
			firewallAtivo := false
			if fm.firewallType == "ufw" {
				cmd := exec.Command("ufw", "status")
				output, err := cmd.CombinedOutput()
				if err == nil && strings.Contains(string(output), "Status: active") {
					firewallAtivo = true
				}
			} else if fm.firewallType == "iptables" {
				cmd := exec.Command("iptables", "-L", "-n")
				output, err := cmd.CombinedOutput()
				if err == nil && !strings.Contains(string(output), "Chain INPUT (policy ACCEPT)\nChain FORWARD (policy ACCEPT)\nChain OUTPUT (policy ACCEPT)") {
					firewallAtivo = true
				}
			}
			
			// Se não estiver ativo, vamos ativá-lo
			if !firewallAtivo {
				log.Printf("Firewall %s não está ativo, ativando...", fm.firewallType)
				if err := fm.enableFirewall(); err != nil {
					log.Printf("Erro ao ativar firewall %s: %v", fm.firewallType, err)
				} else {
					log.Printf("Firewall %s ativado com sucesso", fm.firewallType)
				}
			}
		}
		
		// Registrar o tipo de firewall no Supabase
		if err := fm.supabaseStore.RegisterFirewallType(fm.firewallType); err != nil {
			log.Printf("Aviso: Erro ao registrar tipo de firewall no Supabase: %v", err)
		} else {
			log.Printf("Tipo de firewall '%s' registrado no Supabase", fm.firewallType)
		}
		
		return nil
	}

	// Verificar se o firewall está disponível
	fwStatus, err := fm.checkFirewallStatus()
	if err != nil {
		return fmt.Errorf("erro ao verificar status do firewall: %v", err)
	}

	// Se o firewall estiver desativado, tentar ativá-lo
	if !fwStatus.Available {
		log.Printf("Firewall não disponível. Tentando instalar/ativar...")
		if err := fm.enableFirewall(); err != nil {
			return fmt.Errorf("erro ao ativar firewall: %v", err)
		}
	} else if !fwStatus.Enabled {
		log.Printf("Firewall disponível, mas desativado. Ativando...")
		if err := fm.enableFirewall(); err != nil {
			return fmt.Errorf("erro ao ativar firewall: %v", err)
		}
	} else {
		log.Printf("Firewall já está ativo e configurado")
		fm.firewallType = fwStatus.Type
		
		// Registrar o tipo de firewall no Supabase
		if err := fm.supabaseStore.RegisterFirewallType(fm.firewallType); err != nil {
			log.Printf("Aviso: Erro ao registrar tipo de firewall no Supabase: %v", err)
		} else {
			log.Printf("Tipo de firewall '%s' registrado no Supabase", fm.firewallType)
		}
	}

	// Iniciar monitoramento de desbanimentos
	go fm.startUnbanMonitor()

	// Carregar IPs banidos do Supabase
	bannedIPs, err := fm.supabaseStore.GetActiveBannedIPs()
	if err != nil {
		log.Printf("Erro ao carregar IPs banidos do Supabase: %v", err)
	} else {
		// Aplicar banimentos existentes
		for _, bannedIP := range bannedIPs {
			if err := fm.BanIP(bannedIP.IP); err != nil {
				log.Printf("Erro ao aplicar banimento existente para IP %s: %v", bannedIP.IP, err)
			} else {
				fm.bannedIPs[bannedIP.IP] = true
			}
		}
		log.Printf("Carregados %d IPs banidos do Supabase", len(bannedIPs))
	}

	return nil
}

// FirewallStatus representa o status do firewall
type FirewallStatus struct {
	Available bool
	Enabled   bool
	Type      string // "windows", "iptables", "ufw", etc.
}

// checkFirewallStatus verifica se o firewall está disponível e ativado
func (fm *FirewallManager) checkFirewallStatus() (FirewallStatus, error) {
	status := FirewallStatus{
		Available: false,
		Enabled:   false,
	}

	if fm.isWindows {
		// No Windows, verificamos o Windows Firewall
		cmd := exec.Command("netsh", "advfirewall", "show", "currentprofile")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return status, fmt.Errorf("erro ao verificar Windows Firewall: %v", err)
		}

		// Verificar se o firewall está disponível e ativado
		outputStr := string(output)
		status.Available = true
		status.Type = "windows"
		status.Enabled = strings.Contains(outputStr, "State                      ON") ||
			strings.Contains(outputStr, "Estado                     ATIVADO")
	} else {
		// No Linux, primeiro tentamos o firewalld (mais comum em CentOS/RHEL)
		cmd := exec.Command("firewall-cmd", "--state")
		if err := cmd.Run(); err == nil {
			status.Available = true
			status.Type = "firewalld"
			status.Enabled = true
			return status, nil
		}

		// Tentar UFW (mais comum em Ubuntu/Debian)
		cmd = exec.Command("ufw", "status")
		output, err := cmd.CombinedOutput()
		if err == nil {
			status.Available = true
			status.Type = "ufw"
			status.Enabled = strings.Contains(string(output), "Status: active")
			return status, nil
		}

		// Por último, tentar iptables diretamente
		cmd = exec.Command("iptables", "-L")
		if err := cmd.Run(); err == nil {
			status.Available = true
			status.Type = "iptables"
			status.Enabled = true
			return status, nil
		}
	}

	return status, nil
}

// BanIP bane um endereço IP
func (fm *FirewallManager) BanIP(ip string) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	
	log.Printf("[DEBUG] BanIP: Verificando se o IP %s já está banido", ip)
	// Verificar se o IP já está banido
	if _, exists := fm.bannedIPs[ip]; exists {
		log.Printf("[DEBUG] BanIP: IP %s já está banido, ignorando", ip)
		return nil // IP já está banido
	}
	
	// Se não estamos gerenciando o firewall, apenas registrar o IP
	if !fm.shouldManageFirewall() {
		log.Printf("[DEBUG] BanIP: Gerenciamento de firewall desativado (MANAGE_FIREWALL=%v). Apenas registrando IP %s como banido.", fm.manageFirewall, ip)
		fm.bannedIPs[ip] = true
		return nil
	}
	
	log.Printf("[DEBUG] BanIP: Gerenciamento de firewall ativado (MANAGE_FIREWALL=%v). Prosseguindo com banimento do IP %s", fm.manageFirewall, ip)
	
	var cmd *exec.Cmd
	
	// Verificar se o firewall está ativo
	log.Printf("[DEBUG] BanIP: Verificando se o firewall está ativo antes de banir IP %s", ip)
	var checkFirewallCmd string
	var enableFirewallCmd string
	
	// Usar o tipo de firewall detectado
	log.Printf("[DEBUG] BanIP: Usando firewall tipo '%s' para banir IP %s", fm.firewallType, ip)
	switch fm.firewallType {
	case "windows":
		// Windows Firewall
		ruleName := fmt.Sprintf("MTM-Guardian-Block-%s", ip)
		log.Printf("[DEBUG] BanIP: Criando regra '%s' no Windows Firewall", ruleName)
		checkFirewallCmd = "netsh advfirewall show currentprofile"
		enableFirewallCmd = "netsh advfirewall set currentprofile state on"
		cmd = exec.Command(
			"netsh", "advfirewall", "firewall", "add", "rule",
			"name=" + ruleName,
			"dir=in",
			"action=block",
			"remoteip=" + ip,
		)
	
	case "firewalld":
		// Firewalld
		log.Printf("[DEBUG] BanIP: Adicionando regra no firewalld para bloquear IP %s", ip)
		checkFirewallCmd = "firewall-cmd --state"
		enableFirewallCmd = "systemctl start firewalld"
		cmd = exec.Command(
			"firewall-cmd", "--permanent", "--add-rich-rule=",
			fmt.Sprintf("rule family=ipv4 source address=%s drop", ip),
		)
		
	case "ufw":
		// UFW
		log.Printf("[DEBUG] BanIP: Adicionando regra no UFW para bloquear IP %s", ip)
		checkFirewallCmd = "ufw status | grep Status"
		enableFirewallCmd = "ufw --force enable"
		cmd = exec.Command(
			"ufw", "deny", "from", ip, "to", "any",
		)
		
	default:
		// Padrão: iptables
		log.Printf("[DEBUG] BanIP: Usando iptables (padrão) para bloquear IP %s", ip)
		checkFirewallCmd = "iptables -L | grep Chain"
		enableFirewallCmd = "iptables -P INPUT ACCEPT"
		// Monta o comando exatamente como validado: nsenter -t 1 -n iptables -A INPUT -s <IP> -j DROP
		// Executa diretamente, sem sudo, sh -c ou nsenter duplo
		cmd = exec.Command("nsenter", "-t", "1", "-n", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
		// Comentário: NÃO adicionar sudo ou sh -c. O comando funciona limpo como root.
	}
	
	// Verificar se o firewall está ativo
	if !fm.isWindows {
		log.Printf("[DEBUG] BanIP: Verificando status do firewall com comando: %s", checkFirewallCmd)
		checkOutput, checkErr := collector.ExecutarComando("sudo " + checkFirewallCmd)
		if checkErr != nil {
			log.Printf("[DEBUG] BanIP: Erro ao verificar status do firewall: %v - %s", checkErr, checkOutput)
			// Tentar ativar o firewall
			log.Printf("[DEBUG] BanIP: Tentando ativar o firewall com comando: %s", enableFirewallCmd)
			enableOutput, enableErr := collector.ExecutarComando("sudo " + enableFirewallCmd)
			if enableErr != nil {
				log.Printf("[DEBUG] BanIP: Erro ao ativar o firewall: %v - %s", enableErr, enableOutput)
			} else {
				log.Printf("[DEBUG] BanIP: Firewall ativado com sucesso: %s", enableOutput)
			}
		} else {
			log.Printf("[DEBUG] BanIP: Status do firewall: %s", checkOutput)
		}
	}
	
	// Mostrar o comando que será executado
	cmdStr := strings.Join(cmd.Args, " ")
	log.Printf("[DEBUG] BanIP: Executando comando: %s", cmdStr)
	
	// Adicionar sudo se não for Windows e o comando não começar com sudo
	if !fm.isWindows && !strings.HasPrefix(cmdStr, "sudo ") {
		cmdStr = "sudo " + cmdStr
		log.Printf("[DEBUG] BanIP: Adicionando sudo ao comando: %s", cmdStr)
	}
	
	// Usar nsenter para executar o comando no namespace do host
	if !fm.isWindows {
		// Modificar o comando para usar nsenter e garantir que seja executado no namespace do host
		originalCmd := cmdStr
		cmdStr = fmt.Sprintf("sudo nsenter -t 1 -n %s", originalCmd)
		log.Printf("[DEBUG] BanIP: Modificando comando para usar nsenter: %s", cmdStr)
	}
	
	// Adicionar comando para salvar as regras do iptables se for Linux
	if !fm.isWindows && fm.firewallType == "iptables" {
		log.Printf("[DEBUG] BanIP: Adicionando comando para salvar as regras do iptables")
		defer func() {
			// Usar nsenter para salvar as regras no namespace do host
			saveCmd := "sudo nsenter -t 1 -n sudo sh -c 'iptables-save > /etc/iptables/rules.v4 || iptables-save > /etc/iptables.rules'"
			log.Printf("[DEBUG] BanIP: Tentando salvar regras com comando: %s", saveCmd)
			saveOutput, saveErr := collector.ExecutarComando(saveCmd)
			if saveErr != nil {
				log.Printf("[DEBUG] BanIP: Erro ao salvar regras do iptables: %v - %s", saveErr, saveOutput)
				// Tentar método alternativo
				saveCmd2 := "sudo nsenter -t 1 -n sudo iptables-save | sudo nsenter -t 1 -n sudo tee /etc/iptables.rules"
				log.Printf("[DEBUG] BanIP: Tentando método alternativo: %s", saveCmd2)
				saveOutput2, saveErr2 := collector.ExecutarComando(saveCmd2)
				if saveErr2 != nil {
					log.Printf("[DEBUG] BanIP: Erro ao salvar regras do iptables (método alternativo): %v - %s", saveErr2, saveOutput2)
					// Tentar um terceiro método
					saveCmd3 := "sudo iptables-save"
					log.Printf("[DEBUG] BanIP: Apenas mostrando as regras: %s", saveCmd3)
					saveOutput3, _ := collector.ExecutarComando(saveCmd3)
					log.Printf("[DEBUG] BanIP: Regras atuais do iptables:\n%s", saveOutput3)
				} else {
					log.Printf("[DEBUG] BanIP: Regras do iptables salvas com sucesso (método alternativo): %s", saveOutput2)
				}
			} else {
				log.Printf("[DEBUG] BanIP: Regras do iptables salvas com sucesso: %s", saveOutput)
			}
		}()
	}
	
	// Usar collector.ExecutarComando para executar o comando no shell do host
	output, err := collector.ExecutarComando(cmdStr)
	if err != nil {
		log.Printf("[DEBUG] BanIP: Erro ao executar comando '%s': %v - %s", cmdStr, err, output)
		return fmt.Errorf("erro ao executar comando para banir IP: %v - %s", err, output)
	}
	
	// Verificar se a regra foi realmente aplicada
	if !fm.isWindows {
		checkCmd := "sudo nsenter -t 1 -n sudo iptables -L INPUT -n | grep " + ip
		log.Printf("[DEBUG] BanIP: Verificando se a regra foi aplicada: %s", checkCmd)
		checkOutput, checkErr := collector.ExecutarComando(checkCmd)
		if checkErr != nil || !strings.Contains(checkOutput, ip) {
			log.Printf("[DEBUG] BanIP: AVISO - A regra pode não ter sido aplicada corretamente: %v - %s", checkErr, checkOutput)
			// Tentar aplicar a regra diretamente com um método alternativo
			altCmd := fmt.Sprintf("echo '%s' | sudo nsenter -t 1 -n sudo bash", cmdStr)
			log.Printf("[DEBUG] BanIP: Tentando método alternativo: %s", altCmd)
			altOutput, altErr := collector.ExecutarComando(altCmd)
			if altErr != nil {
				log.Printf("[DEBUG] BanIP: Erro ao aplicar regra com método alternativo: %v - %s", altErr, altOutput)
			} else {
				log.Printf("[DEBUG] BanIP: Regra aplicada com método alternativo: %s", altOutput)
			}
		} else {
			log.Printf("[DEBUG] BanIP: Regra verificada e aplicada corretamente: %s", checkOutput)
		}
	}
	
	log.Printf("[DEBUG] BanIP: Comando executado com sucesso. Saída: %s", string(output))
	
	// Marcar IP como banido localmente
	fm.bannedIPs[ip] = true
	log.Printf("[DEBUG] BanIP: IP %s marcado como banido localmente", ip)
	
	log.Printf("IP %s banido com sucesso", ip)
	return nil
}

// ListBannedIPs lista todos os IPs atualmente banidos no firewall
func (fm *FirewallManager) ListBannedIPs() (string, error) {
	log.Printf("[DEBUG] Listando IPs banidos no firewall %s", fm.firewallType)
	
	var cmdStr string
	
	switch fm.firewallType {
	case "iptables":
		// Listar regras de bloqueio no iptables
		cmdStr = "sudo iptables -L INPUT -n | grep DROP"
		log.Printf("[DEBUG] Executando comando: %s", cmdStr)
		output, err := collector.ExecutarComando(cmdStr)
		if err != nil {
			log.Printf("[DEBUG] Erro ao listar IPs banidos no iptables: %v", err)
			return "", err
		}
		return output, nil
		
	case "ufw":
		// Listar regras de bloqueio no UFW
		cmdStr = "sudo ufw status | grep DENY"
		log.Printf("[DEBUG] Executando comando: %s", cmdStr)
		output, err := collector.ExecutarComando(cmdStr)
		if err != nil {
			log.Printf("[DEBUG] Erro ao listar IPs banidos no UFW: %v", err)
			return "", err
		}
		return output, nil
		
	case "windows":
		// Listar regras de bloqueio no Windows Firewall
		cmdStr = "netsh advfirewall firewall show rule name=all | findstr /C:\"MTM Guardian Block\" /C:\"Block IP\""
		output, err := collector.ExecutarComando(cmdStr)
		if err != nil {
			log.Printf("[DEBUG] Erro ao listar IPs banidos no Windows Firewall: %v", err)
			return "", err
		}
		return output, nil
		
	default:
		return "", fmt.Errorf("tipo de firewall não suportado: %s", fm.firewallType)
	}
}

// UnbanIP remove o banimento de um endereço IP
func (fm *FirewallManager) UnbanIP(ip string) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	
	// Verificar se o IP está banido
	if _, exists := fm.bannedIPs[ip]; !exists {
		return nil // IP não está banido
	}
	
	// Se não estamos gerenciando o firewall, apenas remover o registro do IP
	if !fm.shouldManageFirewall() {
		log.Printf("Gerenciamento de firewall desativado. Apenas removendo registro do IP %s.", ip)
		delete(fm.bannedIPs, ip)
		
		// Atualizar o status no Supabase
		if err := fm.supabaseStore.DeactivateBannedIP(ip); err != nil {
			log.Printf("Erro ao desativar IP %s no Supabase: %v", ip, err)
		}
		
		return nil
	}
	
	var cmd *exec.Cmd
	
	// Usar o tipo de firewall detectado
	switch fm.firewallType {
	case "windows":
		// Windows Firewall
		ruleName := fmt.Sprintf("MTM-Guardian-Block-%s", ip)
		cmd = exec.Command(
			"netsh", "advfirewall", "firewall", "delete", "rule",
			"name=" + ruleName,
		)
	
	case "firewalld":
		// Firewalld
		cmd = exec.Command(
			"firewall-cmd", "--permanent", "--remove-rich-rule=",
			fmt.Sprintf("rule family=ipv4 source address=%s drop", ip),
		)
		
	case "ufw":
		// UFW
		cmd = exec.Command(
			"ufw", "delete", "deny", "from", ip, "to", "any",
		)
		
	default:
		// Padrão: iptables
		// Monta o comando exatamente como validado: nsenter -t 1 -n iptables -D INPUT -s <IP> -j DROP
		// Executa diretamente, sem sudo, sh -c ou nsenter duplo
		cmd = exec.Command("nsenter", "-t", "1", "-n", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
		// Comentário: NÃO adicionar sudo ou sh -c. O comando funciona limpo como root.
	}
	
	// Mostrar o comando que será executado
	cmdStr := strings.Join(cmd.Args, " ")
	log.Printf("[DEBUG] UnbanIP: Executando comando: %s", cmdStr)
	
	// Usar collector.ExecutarComando para executar o comando no shell do host
	output, err := collector.ExecutarComando(cmdStr)
	if err != nil {
		log.Printf("[DEBUG] UnbanIP: Erro ao executar comando: %v - %s", err, output)
		return fmt.Errorf("erro ao desbanir IP %s: %v - %s", ip, err, output)
	}
	
	log.Printf("[DEBUG] UnbanIP: Comando executado com sucesso. Saída: %s", output)
	
	// Remover IP da lista de banidos localmente
	delete(fm.bannedIPs, ip)
	
	// Atualizar o status no Supabase
	if err := fm.supabaseStore.DeactivateBannedIP(ip); err != nil {
		log.Printf("Erro ao desativar IP %s no Supabase: %v", ip, err)
	}
	
	log.Printf("IP %s desbanido com sucesso", ip)
	return nil
}

// RegisterBan registra um banimento no Supabase e aplica a regra de firewall
func (fm *FirewallManager) RegisterBan(ip string, attempts int, firstAttempt, lastAttempt time.Time) error {
	log.Printf("[DEBUG] Iniciando processo de banimento para IP %s (%d tentativas entre %s e %s)", 
		ip, attempts, firstAttempt.Format("15:04:05"), lastAttempt.Format("15:04:05"))
	
	// Verificar se o firewall está sendo gerenciado
	if !fm.shouldManageFirewall() {
		log.Printf("[DEBUG] Gerenciamento de firewall desativado (MANAGE_FIREWALL=false). O IP %s será registrado, mas não será banido no firewall.", ip)
	} else {
		log.Printf("[DEBUG] Gerenciamento de firewall ativado (MANAGE_FIREWALL=true). Tentando banir IP %s no firewall %s.", ip, fm.firewallType)
	}
	
	// Banir o IP no firewall
	log.Printf("[DEBUG] Chamando BanIP para o IP %s", ip)
	if err := fm.BanIP(ip); err != nil {
		log.Printf("[DEBUG] Erro ao banir IP %s no firewall: %v", ip, err)
		return err
	}
	log.Printf("[DEBUG] IP %s banido com sucesso no firewall", ip)
	
	// Registrar no Supabase
	log.Printf("[DEBUG] Registrando IP %s no Supabase", ip)
	if err := fm.supabaseStore.RegisterBannedIP(ip, attempts, firstAttempt, lastAttempt); err != nil {
		log.Printf("Erro ao registrar IP banido no Supabase: %v", err)
		return err
	}
	log.Printf("[DEBUG] IP %s registrado com sucesso no Supabase", ip)
	
	return nil
}

// IsIPBanned verifica se um IP está banido
func (fm *FirewallManager) IsIPBanned(ip string) bool {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	
	_, exists := fm.bannedIPs[ip]
	return exists
}

// shouldManageFirewall verifica se devemos gerenciar o firewall
func (fm *FirewallManager) shouldManageFirewall() bool {
	return fm.manageFirewall
}

// enableFirewall ativa o firewall do sistema e adiciona regra padrão para SSH
func (fm *FirewallManager) enableFirewall() error {
	if fm.isWindows {
		// Ativar Windows Firewall
		cmdStr := "netsh advfirewall set allprofiles state on"
		log.Printf("[DEBUG] enableFirewall: Executando comando: %s", cmdStr)
		output, err := collector.ExecutarComando(cmdStr)
		if err != nil {
			log.Printf("[DEBUG] enableFirewall: Erro ao executar comando: %v - %s", err, output)
			return fmt.Errorf("erro ao ativar Windows Firewall: %v - %s", err, output)
		}
		
		// Adicionar regra para SSH (porta 22)
		cmdStr = "netsh advfirewall firewall add rule name=SSH dir=in action=allow protocol=TCP localport=22"
		log.Printf("[DEBUG] enableFirewall: Executando comando: %s", cmdStr)
		output, err = collector.ExecutarComando(cmdStr)
		if err != nil {
			log.Printf("Aviso: Erro ao adicionar regra para SSH: %v - %s", err, output)
		} else {
			log.Printf("Regra para SSH (porta 22) adicionada com sucesso ao Windows Firewall")
		}
		
		fm.firewallType = "windows"
		return nil
	}
	
	// Linux - tentar ativar o firewall de borda
	if fm.firewallType == "ufw" || fm.firewallType == "" {
		// Verificar se o UFW está instalado
		cmdStr := "which ufw"
		log.Printf("[DEBUG] enableFirewall: Verificando se UFW está instalado: %s", cmdStr)
		output, err := collector.ExecutarComando(cmdStr)
		if err == nil && len(output) > 0 {
			// UFW está instalado, vamos ativá-lo
			
			// Primeiro, adicionar regra para SSH (porta 22)
			cmdStr = "ufw allow 22/tcp"
			log.Printf("[DEBUG] enableFirewall: Executando comando: %s", cmdStr)
			output, err = collector.ExecutarComando(cmdStr)
			if err != nil {
				log.Printf("Aviso: Erro ao adicionar regra para SSH no UFW: %v - %s", err, output)
			} else {
				log.Printf("Regra para SSH (porta 22) adicionada com sucesso ao UFW")
			}
			
			// Ativar o UFW sem precisar de confirmação
			cmdStr = "ufw --force enable"
			log.Printf("[DEBUG] enableFirewall: Executando comando: %s", cmdStr)
			output, err = collector.ExecutarComando(cmdStr)
			if err != nil {
				return fmt.Errorf("erro ao ativar UFW: %v - %s", err, output)
			}
			
			log.Printf("UFW ativado com sucesso")
			fm.firewallType = "ufw"
			return nil
		}
	}
	
	// Se UFW não estiver disponível ou falhar, tentar iptables
	if fm.firewallType == "iptables" || fm.firewallType == "" {
		// Verificar se o iptables está instalado
		cmdStr := "which iptables"
		log.Printf("[DEBUG] enableFirewall: Verificando se iptables está instalado: %s", cmdStr)
		output, err := collector.ExecutarComando(cmdStr)
		if err == nil && len(output) > 0 {
			// iptables está instalado, vamos configurá-lo
			
			// Adicionar regra para SSH (porta 22)
			cmdStr = "iptables -A INPUT -p tcp --dport 22 -j ACCEPT"
			log.Printf("[DEBUG] enableFirewall: Executando comando: %s", cmdStr)
			output, err = collector.ExecutarComando(cmdStr)
			if err != nil {
				log.Printf("Aviso: Erro ao adicionar regra para SSH no iptables: %v - %s", err, output)
			} else {
				log.Printf("Regra para SSH (porta 22) adicionada com sucesso ao iptables")
			}
			
			// Configurar política padrão para aceitar conexões
			cmdStr = "iptables -P INPUT ACCEPT"
			log.Printf("[DEBUG] enableFirewall: Executando comando: %s", cmdStr)
			output, err = collector.ExecutarComando(cmdStr)
			if err != nil {
				log.Printf("Aviso: Erro ao configurar política padrão do iptables: %v - %s", err, output)
			}
			
			// Salvar as regras para persistir após reinicialização
			// Verificar qual sistema de persistência está disponível
			cmdStr = "which iptables-save"
			log.Printf("[DEBUG] enableFirewall: Verificando se iptables-save está instalado: %s", cmdStr)
			output, err = collector.ExecutarComando(cmdStr)
			if err == nil && len(output) > 0 {
				cmdStr = "iptables-save"
				log.Printf("[DEBUG] enableFirewall: Executando comando: %s", cmdStr)
				output, err = collector.ExecutarComando(cmdStr)
				if err != nil {
					log.Printf("Aviso: Erro ao salvar regras do iptables: %v - %s", err, output)
				}
			}
			
			log.Printf("iptables configurado com sucesso")
			fm.firewallType = "iptables"
			return nil
		}
	}
	
	return fmt.Errorf("nenhum firewall disponível para ativar")
}

// detectExistingFirewalls detecta firewalls existentes no sistema
func (fm *FirewallManager) detectExistingFirewalls() ([]string, error) {
	var existingFirewalls []string
	var availableFirewalls []string

	if fm.isWindows {
		// Verificar Windows Firewall
		cmd := exec.Command("netsh", "advfirewall", "show", "currentprofile")
		output, err := cmd.CombinedOutput()
		if err == nil && strings.Contains(string(output), "State") {
			existingFirewalls = append(existingFirewalls, "windows")
		}
		
		// Verificar outros firewalls de terceiros no Windows
		// Verificar se o serviço do Windows Defender está em execução
		cmd = exec.Command("sc", "query", "WinDefend")
		output, err = cmd.CombinedOutput()
		if err == nil && strings.Contains(string(output), "RUNNING") {
			existingFirewalls = append(existingFirewalls, "defender")
		}
		
		// Verificar outros firewalls comuns (McAfee, Norton, etc.)
		commonFirewalls := []string{
			"McAfeeFireSvc",
			"Norton Firewall",
			"ESET Firewall",
			"Kaspersky",
			"Avast",
		}
		
		for _, fw := range commonFirewalls {
			cmd = exec.Command("sc", "query", fw)
			output, err = cmd.CombinedOutput()
			if err == nil && strings.Contains(string(output), "RUNNING") {
				existingFirewalls = append(existingFirewalls, strings.ToLower(fw))
			}
		}
	} else {
		// Linux - verificar diferentes firewalls
		
		// Verificar firewalld
		cmd := exec.Command("systemctl", "status", "firewalld")
		output, err := cmd.CombinedOutput()
		if err == nil {
			if strings.Contains(string(output), "active (running)") {
				existingFirewalls = append(existingFirewalls, "firewalld")
			}
			if strings.Contains(string(output), "loaded") {
				availableFirewalls = append(availableFirewalls, "firewalld")
			}
		}
		
		// Verificar UFW - tanto instalado quanto ativo
		cmd = exec.Command("which", "ufw")
		if err := cmd.Run(); err == nil {
			// UFW está instalado
			availableFirewalls = append(availableFirewalls, "ufw")
			
			// Verificar se está ativo
			cmd = exec.Command("ufw", "status")
			output, err = cmd.CombinedOutput()
			if err == nil {
				log.Printf("Status do UFW: %s", string(output))
				if strings.Contains(string(output), "Status: active") {
					existingFirewalls = append(existingFirewalls, "ufw")
				}
			}
		}
		
		// Verificar iptables - tanto disponível quanto com regras
		cmd = exec.Command("which", "iptables")
		if err := cmd.Run(); err == nil {
			// iptables está disponível
			availableFirewalls = append(availableFirewalls, "iptables")
			
			// Verificar se há regras definidas
			cmd = exec.Command("iptables", "-L", "-n", "-v")
			output, err = cmd.CombinedOutput()
			if err == nil {
				log.Printf("Status do iptables: %s", string(output))
				// Verificar se há regras além das padrão
				hasRules := !strings.Contains(string(output), "Chain INPUT (policy ACCEPT)\nChain FORWARD (policy ACCEPT)\nChain OUTPUT (policy ACCEPT)")
				if hasRules {
					existingFirewalls = append(existingFirewalls, "iptables")
				}
			}
		}
		
		// Verificar outros firewalls comuns no Linux
		otherFirewalls := []string{
			"csf",         // ConfigServer Firewall
			"shorewall",   // Shorewall
			"ipset",       // IPset
			"nftables",    // nftables
			"pf",          // Packet Filter (BSD)
		}
		
		for _, fw := range otherFirewalls {
			cmd = exec.Command("which", fw)
			if err := cmd.Run(); err == nil {
				// O firewall está instalado
				availableFirewalls = append(availableFirewalls, fw)
				
				// Verificar se o serviço está em execução
				cmd = exec.Command("systemctl", "status", fw)
				output, err = cmd.CombinedOutput()
				if err == nil && strings.Contains(string(output), "active (running)") {
					existingFirewalls = append(existingFirewalls, fw)
				}
			}
		}
	}
	
	// Se não encontramos nenhum firewall ativo, mas temos disponíveis, retornamos os disponíveis
	if len(existingFirewalls) == 0 && len(availableFirewalls) > 0 {
		log.Printf("Nenhum firewall ativo encontrado, mas os seguintes estão disponíveis: %v", availableFirewalls)
		return availableFirewalls, nil
	}
	
	return existingFirewalls, nil
}

// startUnbanMonitor inicia o monitoramento periódico para desbanir IPs
func (fm *FirewallManager) startUnbanMonitor() {
	log.Printf("Iniciando monitoramento de desbanimentos a cada 60 segundos")
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	
	for {
		<-ticker.C
		fm.checkForUnbans()
	}
}

// checkForUnbans verifica se há IPs para desbanir
func (fm *FirewallManager) checkForUnbans() {
	// Obter lista atual de IPs banidos ativos do Supabase
	activeBannedIPs, err := fm.supabaseStore.GetActiveBannedIPs()
	if err != nil {
		log.Printf("Erro ao consultar IPs banidos ativos: %v", err)
		return
	}
	
	// Mapear IPs ativos para verificação rápida
	activeMap := make(map[string]bool)
	for _, bannedIP := range activeBannedIPs {
		activeMap[bannedIP.IP] = true
	}
	
	// Verificar IPs que estão banidos localmente mas não estão mais ativos no Supabase
	fm.mu.Lock()
	var toUnban []string
	for ip := range fm.bannedIPs {
		if !activeMap[ip] {
			toUnban = append(toUnban, ip)
		}
	}
	fm.mu.Unlock()
	
	// Desbanir IPs
	for _, ip := range toUnban {
		log.Printf("Desbanindo IP %s que foi marcado como inativo no Supabase", ip)
		if err := fm.UnbanIP(ip); err != nil {
			log.Printf("Erro ao desbanir IP %s: %v", ip, err)
		}
	}
}
