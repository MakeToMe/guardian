# MTM Guardian

MTM Guardian é um serviço de observabilidade e segurança para o painel MTM, desenvolvido em Go. Ele coleta métricas do sistema e estatísticas de containers Docker, enviando-as para o Supabase para visualização no painel MTM.

## Funcionalidades

- Coleta de métricas do sistema:
  - CPU (cores, uso, ociosidade)
  - Memória (total, uso, disponível)
  - Disco (total, uso, disponível)
- Coleta de estatísticas de containers Docker:
  - Uso de CPU e memória por container
  - Estatísticas de rede (entrada/saída)
  - Número de processos
- Envio de dados para o Supabase
- Identificação automática do titular pelo IP da VM

## Estrutura do Projeto

```
mtm_guardian/
├── cmd/
│   └── guardian/
│       └── main.go         # Ponto de entrada do serviço
├── internal/
│   ├── collector/          # Coleta de métricas do sistema
│   ├── docker/             # Coleta de estatísticas do Docker
│   ├── models/             # Estruturas de dados
│   └── supabase/           # Cliente para comunicação com Supabase
├── Dockerfile              # Configuração para build do container
├── go.mod                  # Dependências Go
└── go.sum                  # Checksums das dependências
```

## Requisitos

- Go 1.16 ou superior
- Docker (para coleta de estatísticas de containers)
- Acesso ao Supabase

## Variáveis de Ambiente

- `SUPABASE_URL`: URL do projeto Supabase
- `SUPABASE_KEY`: Chave de API do Supabase

## Construção e Execução

### Localmente

```bash
# Inicializar o módulo Go (se ainda não existir go.mod)
go mod init github.com/MakeToMe/mtm_guardian

# Baixar dependências
go mod tidy

# Compilar
go build -o mtm_guardian ./cmd/guardian

# Executar
./mtm_guardian
```

### Com Docker

```bash
# Construir a imagem
docker build -t mtm/guardian:latest .

# Executar o container
docker run -d \
  --name mtm_guardian \
  -e SUPABASE_URL="sua-url-do-supabase" \
  -e SUPABASE_KEY="sua-chave-do-supabase" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  mtm/guardian:latest
```

## Implantação

Para implantar o MTM Guardian em suas VMs:

1. Construa a imagem Docker
2. Envie para um registro Docker
3. Execute o container em cada VM com as variáveis de ambiente apropriadas

## Próximos Passos

- Implementação do módulo de segurança para:
  - Verificação e instalação de firewall
  - Gerenciamento de regras de firewall
  - Detecção e banimento de IPs maliciosos
  - Desbanimento de IPs via interface do dashboard

## Licença

Proprietário - MakeToMe
