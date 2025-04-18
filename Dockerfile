FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copiar os arquivos de módulos Go
COPY go.mod ./
COPY go.sum ./

# Baixar as dependências
RUN go mod download

# Copiar o código-fonte
COPY . .

# Compilar a aplicação
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o mtm_guardian ./cmd/guardian

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y sysstat coreutils procps curl gnupg lsb-release iptables ufw sudo grep && \
    # Adicionar repositório do Docker
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    # Instalar apenas o cliente Docker (não o daemon), ferramentas de firewall e utilitários para logs
    apt-get install -y docker-ce-cli openssh-client && \
    # Limpar cache
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copiar o binário compilado do estágio anterior
COPY --from=builder /app/mtm_guardian .

# Definir variáveis de ambiente padrão (não sensíveis)
ENV DOCKER_INTERVAL="10"
ENV VM_INTERVAL="20"
ENV MANAGE_FIREWALL="true"
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# As variáveis sensíveis devem ser passadas no momento da execução
# NÃO definir SUPABASE_URL e SUPABASE_KEY aqui por questões de segurança

# Nenhuma porta precisa ser exposta, pois não usamos mais API REST

# Executar a aplicação
CMD ["./mtm_guardian"]
