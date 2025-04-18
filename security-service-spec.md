# Especificação do Serviço de Segurança para Dashboard MTM

## Visão Geral

Este documento detalha a especificação para um novo serviço de segurança em Go que será integrado ao dashboard MTM. O serviço será responsável por gerenciar o firewall e implementar um sistema de banimento de IPs para proteger as VMs gerenciadas pelo painel.

## Objetivos

1. Verificar e instalar firewall nas VMs
2. Exibir e gerenciar regras de firewall (portas abertas/fechadas)
3. Implementar sistema próprio de detecção e banimento de IPs maliciosos
4. Permitir desbanimento de IPs via interface do dashboard
5. Integrar com o sistema existente de monitoramento e autenticação

## Tecnologias

- **Linguagem**: Go (Golang)
- **Containerização**: Docker
- **Orquestração**: Docker Swarm via Portainer
- **Banco de Dados**: Supabase (PostgreSQL)
- **Frontend**: Next.js com design neomórfico existente
- **API**: REST para comunicação entre frontend e serviço Go

## Arquitetura

### Componentes Principais

1. **Serviço Go em Container Docker**:
   - Implantado em todas as VMs via Docker Swarm
   - Acesso privilegiado para gerenciar firewall do host
   - API REST para receber comandos do frontend
   - Monitoramento contínuo de logs de autenticação

2. **Tabelas no Supabase**:
   - `mtm.firewall_rules`: Armazenar regras de firewall
   - `mtm.banned_ips`: Armazenar IPs banidos e motivos

3. **Integração com Frontend**:
   - Nova seção "Segurança" no dashboard
   - Visualização e gerenciamento de regras de firewall
   - Visualização e desbanimento de IPs

### Fluxo de Dados

1. O serviço Go obtém o IP da VM onde está rodando
2. Consulta a tabela `mtm.servidores` para obter o ID do servidor e o UUID do titular
3. Verifica e configura o firewall do host
4. Monitora logs de autenticação para detectar tentativas de invasão
5. Adiciona regras de firewall para banir IPs suspeitos
6. Registra todas as ações no Supabase com referência ao titular
7. O frontend consulta as APIs para exibir o status e permitir gerenciamento

## Implementação do Serviço Go

### Estrutura do Projeto

```
security-service/
├── cmd/
│   └── server/
│       └── main.go         # Ponto de entrada do serviço
├── internal/
│   ├── api/                # Implementação da API REST
│   ├── auth/               # Monitoramento de logs de autenticação
│   ├── firewall/           # Gerenciamento de regras de firewall
│   ├── models/             # Estruturas de dados
│   └── supabase/           # Cliente para comunicação com Supabase
├── Dockerfile              # Configuração para build do container
├── go.mod                  # Dependências Go
└── go.sum                  # Checksums das dependências
```

### Principais Componentes do Código

#### Serviço Principal

```go
type SecurityService struct {
    SupabaseURL      string
    SupabaseKey      string
    ServerIP         string
    ServerID         string
    TitularID        string
    RefreshInterval  time.Duration
    IPAttempts       map[string]*IPAttempt
    mu               sync.Mutex
}

func NewSecurityService() (*SecurityService, error) {
    // Obtém o IP da máquina
    ip, err := getServerIP()
    if err != nil {
        return nil, err
    }
    
    // Inicializa o serviço
    service := &SecurityService{
        SupabaseURL:     os.Getenv("SUPABASE_URL"),
        SupabaseKey:     os.Getenv("SUPABASE_KEY"),
        ServerIP:        ip,
        RefreshInterval: 60 * time.Second,
        IPAttempts:      make(map[string]*IPAttempt),
    }
    
    // Busca o ID do servidor e o titular com base no IP
    if err := service.fetchServerInfo(); err != nil {
        return nil, err
    }
    
    return service, nil
}
```

#### Monitoramento de Logs

```go
func (s *SecurityService) monitorAuthLog() {
    // Abre o arquivo de log em modo de leitura contínua
    t, err := tail.TailFile("/var/log/auth.log", tail.Config{Follow: true})
    if err != nil {
        log.Fatal(err)
    }
    
    for line := range t.Lines {
        // Analisa a linha para tentativas de login SSH
        if strings.Contains(line.Text, "Failed password for") {
            ip := extractIPFromLogLine(line.Text)
            if ip != "" {
                s.recordFailedAttempt(ip)
            }
        }
    }
}

func (s *SecurityService) recordFailedAttempt(ip string) {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    // Incrementa contagem de tentativas
    attempt, exists := s.IPAttempts[ip]
    if !exists {
        attempt = &IPAttempt{
            IP:        ip,
            Attempts:  0,
            FirstSeen: time.Now(),
        }
    }
    
    attempt.Attempts++
    attempt.LastSeen = time.Now()
    s.IPAttempts[ip] = attempt
    
    // Verifica se deve banir
    if attempt.Attempts >= MAX_ATTEMPTS && !attempt.Banned {
        s.banIP(ip)
        attempt.Banned = true
        attempt.BanTime = time.Now()
        
        // Registra no Supabase
        s.recordBanInSupabase(ip, "ssh", attempt.Attempts)
    }
}
```

#### Gerenciamento de Firewall

```go
func (s *SecurityService) setupFirewall() error {
    // Verifica se o UFW está instalado
    installed := checkIfCommandExists("ufw")
    
    if !installed {
        // Instala o UFW
        log.Println("Instalando UFW...")
        if err := executeCommand("apt-get", "update"); err != nil {
            return err
        }
        
        if err := executeCommand("apt-get", "install", "-y", "ufw"); err != nil {
            return err
        }
        
        log.Println("UFW instalado com sucesso")
    }
    
    // Verifica se o UFW está ativo
    output, err := executeCommandWithOutput("ufw", "status")
    if err == nil && !strings.Contains(output, "Status: active") {
        log.Println("Ativando UFW...")
        if err := executeCommand("ufw", "--force", "enable"); err != nil {
            return err
        }
        log.Println("UFW ativado com sucesso")
    }
    
    // Configura regras padrão
    if err := executeCommand("ufw", "default", "deny", "incoming"); err != nil {
        return err
    }
    
    if err := executeCommand("ufw", "default", "allow", "outgoing"); err != nil {
        return err
    }
    
    // Permite SSH
    if err := executeCommand("ufw", "allow", "ssh"); err != nil {
        return err
    }
    
    // Permite a porta da API do serviço
    if err := executeCommand("ufw", "allow", fmt.Sprintf("%d/tcp", API_PORT)); err != nil {
        return err
    }
    
    // Carrega regras existentes do Supabase
    return s.loadFirewallRulesFromSupabase()
}

func (s *SecurityService) banIP(ip string) error {
    log.Printf("Banindo IP %s", ip)
    
    // Adiciona regra ao firewall
    cmd := exec.Command("ufw", "deny", "from", ip, "to", "any")
    if err := cmd.Run(); err != nil {
        log.Printf("Erro ao banir IP %s: %v", ip, err)
        return err
    }
    
    log.Printf("IP %s banido com sucesso", ip)
    return nil
}

func (s *SecurityService) unbanIP(ip string) error {
    log.Printf("Desbanindo IP %s", ip)
    
    // Remove regra do firewall
    cmd := exec.Command("ufw", "delete", "deny", "from", ip, "to", "any")
    if err := cmd.Run(); err != nil {
        log.Printf("Erro ao desbanir IP %s: %v", ip, err)
        return err
    }
    
    // Atualiza o estado em memória
    s.mu.Lock()
    if attempt, exists := s.IPAttempts[ip]; exists {
        attempt.Banned = false
        s.IPAttempts[ip] = attempt
    }
    s.mu.Unlock()
    
    // Atualiza o Supabase
    if err := s.updateUnbanInSupabase(ip); err != nil {
        log.Printf("Erro ao atualizar status de desbanimento no Supabase: %v", err)
        return err
    }
    
    log.Printf("IP %s desbanido com sucesso", ip)
    return nil
}
```

#### API REST

```go
func (s *SecurityService) startHTTPServer() {
    router := mux.NewRouter()
    
    // Endpoints de status
    router.HandleFunc("/api/security/status", s.handleStatus).Methods("GET")
    
    // Endpoints de firewall
    router.HandleFunc("/api/security/firewall/rules", s.handleFirewallRules).Methods("GET")
    router.HandleFunc("/api/security/firewall/add", s.handleAddFirewallRule).Methods("POST")
    router.HandleFunc("/api/security/firewall/remove", s.handleRemoveFirewallRule).Methods("POST")
    
    // Endpoints de banimento
    router.HandleFunc("/api/security/bans", s.handleBannedIPs).Methods("GET")
    router.HandleFunc("/api/security/unban", s.handleUnbanIP).Methods("POST")
    
    // Middleware de autenticação
    router.Use(s.authMiddleware)
    
    // Inicia o servidor
    log.Printf("Iniciando servidor na porta %d", API_PORT)
    log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", API_PORT), router))
}

func (s *SecurityService) authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Obtém o token do cabeçalho Authorization
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Não autorizado", http.StatusUnauthorized)
            return
        }
        
        // Remove o prefixo "Bearer "
        tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
        
        // Valida o token
        valid, userID := s.validateToken(tokenString)
        if !valid {
            http.Error(w, "Token inválido", http.StatusUnauthorized)
            return
        }
        
        // Verifica se o usuário tem permissão para acessar este servidor
        if !s.userHasAccess(userID) {
            http.Error(w, "Acesso negado", http.StatusForbidden)
            return
        }
        
        // Adiciona o ID do usuário ao contexto da requisição
        ctx := context.WithValue(r.Context(), "userID", userID)
        
        // Chama o próximo handler com o contexto atualizado
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

#### Integração com Supabase

```go
func (s *SecurityService) fetchServerInfo() error {
    // Consulta a tabela de servidores para obter o ID e o titular
    query := fmt.Sprintf(`
        SELECT uid, titular 
        FROM mtm.servidores 
        WHERE ip = '%s'
    `, s.ServerIP)
    
    // Executa a consulta no Supabase
    resp, err := s.supabaseClient.Rpc("execute_sql", map[string]interface{}{
        "query": query,
    }).Execute()
    
    if err != nil {
        return fmt.Errorf("erro ao consultar informações do servidor: %v", err)
    }
    
    var result []struct {
        UID     string `json:"uid"`
        Titular string `json:"titular"`
    }
    
    if err := json.Unmarshal(resp.Data, &result); err != nil {
        return fmt.Errorf("erro ao decodificar resposta: %v", err)
    }
    
    if len(result) == 0 {
        return fmt.Errorf("servidor com IP %s não encontrado", s.ServerIP)
    }
    
    // Armazena os IDs
    s.ServerID = result[0].UID
    s.TitularID = result[0].Titular
    
    log.Printf("Servidor identificado: ID=%s, Titular=%s", s.ServerID, s.TitularID)
    return nil
}

func (s *SecurityService) recordBanInSupabase(ip string, reason string, attempts int) error {
    data := map[string]interface{}{
        "servidor_id": s.ServerID,
        "titular":     s.TitularID,
        "ip":          ip,
        "motivo":      reason,
        "tentativas":  attempts,
    }
    
    _, err := s.supabaseClient.From("banned_ips").Insert(data).Execute()
    if err != nil {
        return fmt.Errorf("erro ao registrar banimento no Supabase: %v", err)
    }
    
    return nil
}
```

## Dockerfile

```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o security-service ./cmd/server

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y ufw curl && \
    apt-get clean

WORKDIR /root/
COPY --from=builder /app/security-service .

# Variáveis de ambiente
ENV SUPABASE_URL=""
ENV SUPABASE_KEY=""
ENV API_PORT=8443
ENV MAX_ATTEMPTS=5
ENV BAN_DURATION=86400

EXPOSE 8443
CMD ["./security-service"]
```

## Integração com o Frontend

### Novas Páginas no Dashboard

1. **Página de Segurança**:
   - Visão geral do status de segurança de todas as VMs
   - Estatísticas de tentativas de invasão
   - Acesso às configurações de firewall e IPs banidos

2. **Configuração de Firewall**:
   - Visualização de regras atuais
   - Adição/remoção de regras
   - Presets para configurações comuns

3. **Gerenciamento de IPs Banidos**:
   - Lista de IPs banidos com motivo e data
   - Opção para desbanir IPs
   - Histórico de banimentos

### Exemplo de Componente React

```jsx
function FirewallRules() {
  const { profile } = useAuth();
  const [rules, setRules] = useState([]);
  const [newRule, setNewRule] = useState({ port: '', protocol: 'tcp', action: 'allow' });
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [selectedServer, setSelectedServer] = useState(null);
  const [servers, setServers] = useState([]);
  
  useEffect(() => {
    if (profile?.uid) {
      fetchServers();
    }
  }, [profile]);
  
  useEffect(() => {
    if (selectedServer) {
      fetchRules(selectedServer.uid);
    }
  }, [selectedServer]);
  
  const fetchServers = async () => {
    setIsLoading(true);
    try {
      const response = await fetch('/api/servidores');
      const data = await response.json();
      setServers(data || []);
      if (data && data.length > 0) {
        setSelectedServer(data[0]);
      }
    } catch (error) {
      toast.error('Erro ao buscar servidores');
    } finally {
      setIsLoading(false);
    }
  };
  
  const fetchRules = async (serverId) => {
    setIsLoading(true);
    try {
      const response = await fetch(`/api/security/firewall/rules?server=${serverId}`);
      const data = await response.json();
      setRules(data || []);
    } catch (error) {
      toast.error('Erro ao buscar regras do firewall');
    } finally {
      setIsLoading(false);
    }
  };
  
  const handleRefresh = useCallback(async () => {
    if (!selectedServer) return;
    
    setIsRefreshing(true);
    try {
      await fetchRules(selectedServer.uid);
      toast.success('Regras de firewall atualizadas com sucesso');
    } catch (error) {
      toast.error('Erro ao atualizar regras de firewall');
    } finally {
      setIsRefreshing(false);
    }
  }, [selectedServer]);
  
  const addRule = async () => {
    if (!selectedServer) return;
    
    try {
      await fetch('/api/security/firewall/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          serverId: selectedServer.uid,
          ...newRule
        })
      });
      
      await fetchRules(selectedServer.uid);
      toast.success('Regra adicionada com sucesso');
      setNewRule({ port: '', protocol: 'tcp', action: 'allow' });
    } catch (error) {
      toast.error('Erro ao adicionar regra');
    }
  };
  
  const removeRule = async (ruleId) => {
    if (!selectedServer) return;
    
    try {
      await fetch('/api/security/firewall/remove', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          serverId: selectedServer.uid,
          ruleId
        })
      });
      
      await fetchRules(selectedServer.uid);
      toast.success('Regra removida com sucesso');
    } catch (error) {
      toast.error('Erro ao remover regra');
    }
  };
  
  // Renderização do componente...
}
```

### API Routes no Next.js

```javascript
// pages/api/security/firewall/rules.js
import { createServerSupabaseClient } from '@supabase/auth-helpers-nextjs';

export default async function handler(req, res) {
  const supabase = createServerSupabaseClient({ req, res });
  
  // Verifica autenticação
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) {
    return res.status(401).json({ error: 'Não autenticado' });
  }
  
  const { server } = req.query;
  if (!server) {
    return res.status(400).json({ error: 'ID do servidor não fornecido' });
  }
  
  try {
    // Verifica se o usuário tem acesso ao servidor
    const { data: serverData, error: serverError } = await supabase
      .from('servidores')
      .select('*')
      .eq('uid', server)
      .eq('titular', session.user.id)
      .single();
      
    if (serverError || !serverData) {
      return res.status(403).json({ error: 'Acesso negado a este servidor' });
    }
    
    // Obtém o endpoint do serviço de segurança
    const { data: endpoints, error: endpointsError } = await supabase
      .from('security_endpoints')
      .select('*')
      .eq('servidor_id', server)
      .eq('status', 'online')
      .single();
      
    if (endpointsError || !endpoints) {
      return res.status(404).json({ error: 'Serviço de segurança não encontrado para este servidor' });
    }
    
    // Faz requisição ao serviço de segurança
    const securityUrl = `http://${endpoints.ip}:${endpoints.porta}/api/security/firewall/rules`;
    const response = await fetch(securityUrl, {
      headers: {
        'Authorization': `Bearer ${session.access_token}`
      }
    });
    
    if (!response.ok) {
      throw new Error(`Erro ao comunicar com serviço de segurança: ${response.statusText}`);
    }
    
    const rules = await response.json();
    return res.status(200).json(rules);
  } catch (error) {
    console.error('Erro ao buscar regras de firewall:', error);
    return res.status(500).json({ error: 'Erro ao buscar regras de firewall' });
  }
}
```

## Modelo de Dados

### Tabelas no Supabase

```sql
-- Tabela de endpoints de segurança
CREATE TABLE mtm.security_endpoints (
  id SERIAL PRIMARY KEY,
  servidor_id UUID REFERENCES mtm.servidores(uid),
  ip TEXT NOT NULL,
  porta INTEGER NOT NULL DEFAULT 8443,
  status TEXT DEFAULT 'online',
  ultima_verificacao TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  token_acesso TEXT NOT NULL
);

-- Tabela de regras do firewall
CREATE TABLE mtm.firewall_rules (
  id SERIAL PRIMARY KEY,
  servidor_id UUID REFERENCES mtm.servidores(uid),
  titular UUID NOT NULL,
  porta INTEGER,
  protocolo TEXT, -- 'tcp', 'udp', etc.
  acao TEXT, -- 'allow', 'deny'
  origem TEXT DEFAULT 'any',
  destino TEXT DEFAULT 'any',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Tabela de IPs banidos
CREATE TABLE mtm.banned_ips (
  id SERIAL PRIMARY KEY,
  servidor_id UUID REFERENCES mtm.servidores(uid),
  titular UUID NOT NULL,
  ip TEXT NOT NULL,
  motivo TEXT,
  tentativas INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  desbanido BOOLEAN DEFAULT FALSE,
  desbanido_em TIMESTAMP WITH TIME ZONE
);
```

## Considerações de Segurança

1. **Autenticação e Autorização**:
   - Validação de tokens JWT para todas as requisições
   - Verificação de propriedade do servidor para cada operação
   - Permissões específicas para administradores

2. **Proteção contra Ataques**:
   - Rate limiting para evitar abuso da API
   - Validação rigorosa de entradas para prevenir injeção de comandos
   - Logs detalhados para auditoria

3. **Comunicação Segura**:
   - HTTPS para todas as comunicações entre frontend e serviços
   - Tokens de acesso com tempo de expiração curto
   - Renovação segura de tokens

## Implantação

1. **Build do Container**:
   ```bash
   docker build -t mtm/security-service:latest .
   ```

2. **Implantação via Portainer**:
   - Adicionar a imagem ao registry
   - Configurar o stack no Docker Swarm
   - Definir variáveis de ambiente necessárias

3. **Monitoramento**:
   - Logs centralizados para todos os containers
   - Alertas para eventos de segurança importantes
   - Dashboard de status para todos os serviços

## Próximos Passos

1. Implementar o serviço Go conforme especificado
2. Criar as tabelas necessárias no Supabase
3. Desenvolver os componentes de frontend
4. Integrar com o sistema de autenticação existente
5. Testar em ambiente de desenvolvimento
6. Implantar em produção via Docker Swarm

## Conclusão

Este serviço de segurança em Go proporcionará uma camada adicional de proteção para as VMs gerenciadas pelo dashboard MTM, com gerenciamento centralizado de firewall e detecção/banimento de tentativas de invasão. A integração com o sistema existente garantirá uma experiência de usuário consistente e segura.
