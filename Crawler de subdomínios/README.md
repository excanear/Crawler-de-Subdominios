# Subdomain Crawler

Um crawler avançado de subdomínios desenvolvido em Go que combina técnicas passivas e ativas para descoberta completa de subdomínios.

## 🚀 Características

### 🔍 Coleta Passiva
- **crt.sh**: Consulta certificados SSL/TLS públicos
- **HackerTarget**: API gratuita de descoberta de hosts
- **VirusTotal**: Integração com API (requer chave)
- **Extensível**: Fácil adição de novas fontes

### ⚡ Coleta Ativa
- **Força bruta DNS**: Resolução massiva de subdomínios
- **Permutação inteligente**: Geração automática de variações
- **Rate limiting**: Controle de velocidade para evitar bloqueios
- **Paralelização**: Múltiplos workers simultâneos

### 💾 Exportação
- **Wordlist (.txt)**: Lista simples para outras ferramentas
- **CSV detalhado**: Incluindo IPs, fontes e timestamps
- **Estatísticas**: Relatórios de análise completos

## 📦 Instalação

### Pré-requisitos
- Go 1.21 ou superior

### Compilação
```bash
# Clone ou baixe o projeto
cd subdomain-crawler

# Instalar dependências
go mod tidy

# Compilar
go build -o subdomain-crawler main.go

# No Windows
go build -o subdomain-crawler.exe main.go
```

## 🎯 Uso Básico

### Scan Completo (Passivo + Ativo)
```bash
./subdomain-crawler -d example.com
```

### Apenas Coleta Passiva
```bash
./subdomain-crawler -d example.com --passive-only
```

### Apenas Força Bruta
```bash
./subdomain-crawler -d example.com --active-only
```

### Com Wordlist Customizada
```bash
./subdomain-crawler -d example.com -w wordlists/custom.txt
```

## ⚙️ Opções Avançadas

### Configuração de Performance
```bash
# 50 workers, timeout de 10s, rate limit de 100ms
./subdomain-crawler -d example.com -w 50 -t 10 -r 100
```

### Configuração de Saída
```bash
# Diretório específico, apenas CSV, com timestamp
./subdomain-crawler -d example.com -o ./meus-resultados --format csv --timestamp
```

### Com API Keys
```bash
# VirusTotal API
./subdomain-crawler -d example.com --virustotal-key "sua-api-key-aqui"
```

## 📋 Parâmetros Completos

| Parâmetro | Descrição | Padrão |
|-----------|-----------|---------|
| `-d, --domain` | Domínio alvo (obrigatório) | - |
| `-o, --output-dir` | Diretório de saída | ./results |
| `--format` | Formato: txt, csv, both | both |
| `--timestamp` | Adicionar timestamp aos arquivos | true |
| `--passive-only` | Apenas coleta passiva | false |
| `--active-only` | Apenas coleta ativa | false |
| `-w, --workers` | Número de workers | 20 |
| `-t, --timeout` | Timeout DNS (segundos) | 5 |
| `-r, --rate-limit` | Rate limit (ms) | 50 |
| `--wordlist` | Wordlist customizada | - |
| `--virustotal-key` | API key VirusTotal | - |
| `-v, --verbose` | Saída verbosa | false |

## 📊 Saída de Exemplo

```
🎯 RESUMO DO SCAN - example.com
# Subdomain Crawler

Um crawler avançado de subdomínios desenvolvido em Go que combina técnicas passivas e ativas para descoberta completa de subdomínios.

> Versão atual: 1.0.0 — última atualização: 2025-11-01

## 🚀 O que este projeto faz

Resumo rápido:
- Coleta passiva (crt.sh, HackerTarget, VirusTotal)
- Coleta ativa (força bruta DNS com permutações)
- Exportação em Wordlist (.txt), CSV e relatório de estatísticas
- CLI configurável (flags para workers, timeout, rate-limit, etc.)

## 📦 Pré-requisitos

- Go 1.21 ou superior instalado e configurado no PATH

### Como verificar se o Go está instalado (Windows PowerShell)

```powershell
go version
```

Se o comando acima falhar, instale o Go pelo instalador oficial:

- Página oficial: https://golang.org/dl/
- Após instalar, feche e reabra o terminal para atualizar o PATH.

## 🛠️ Instalação e compilação (Windows)

Use o script `install.bat` incluído para facilitar:

```powershell
cd "c:\Users\Henry\OneDrive\Área de Trabalho\Crawler de subdomínios"
.\install.bat
```

O script faz:
- Verifica se o Go está disponível
- Executa `go mod tidy` para baixar dependências
- Compila `subdomain-crawler.exe`

Se preferir compilar manualmente:

```powershell
cd "c:\Users\Henry\OneDrive\Área de Trabalho\Crawler de subdomínios"
go mod tidy
go build -o subdomain-crawler.exe main.go
```

## 🎯 Uso rápido (exemplos)

- Scan completo (passivo + ativo):

```powershell
.\subdomain-crawler.exe -d example.com
```

- Apenas coleta passiva:

```powershell
.\subdomain-crawler.exe -d example.com --passive-only
```

- Força bruta (ativa) com wordlist customizada:

```powershell
.\subdomain-crawler.exe -d example.com --active-only --wordlist wordlists\basic.txt
```

Use `--help` para ver todas as flags:

```powershell
.\subdomain-crawler.exe --help
```

## ⚙️ Flags importantes

Principais flags (resumido):

- `-d, --domain` (obrigatório): domínio alvo
- `-o, --output-dir`: diretório de saída (padrão: `./results`)
- `--format`: `txt`, `csv` ou `both` (padrão: `both`)
- `--timestamp`: adicionar timestamp aos arquivos (padrão: `true`)
- `--passive-only`, `--active-only`: modos de execução
- `-w, --workers`: número de workers (padrão: `20`)
- `-t, --timeout`: timeout DNS em segundos (padrão: `5`)
- `-r, --rate-limit`: rate limit em ms (padrão: `50`)
- `--virustotal-key`: API key do VirusTotal (opcional)

Para a lista completa consulte `--help` ou a seção de parâmetros abaixo.

## 📋 Formatos de saída

- Wordlist (`.txt`) — lista simples de subdomínios
- CSV (`.csv`) — com colunas: Subdomain, IP, Source, Timestamp, HTTP_Status, Title, Technologies
- Relatório de estatísticas (`_stats.txt`)

Arquivos gerados por padrão em `./results` (configurável).

## ⚠️ APIs, limites e chaves

- `crt.sh`: sem limite explícito conhecido — use com moderação
- `HackerTarget`: API pública com limites por IP (pode bloquear se abusado)
- `VirusTotal`: requer API key; versão gratuita tem limites (ex.: 4 req/min)

Coloque chaves no `--virustotal-key` ou configure através do `config.example` para fluxos automatizados.

## 🐞 Troubleshooting rápido

- Erro "go não encontrado": instale o Go e reinicie o terminal.
- Erro ao baixar dependências: execute `go mod tidy` e verifique conexão de internet.
- Problemas de resolução DNS: aumente `-t, --timeout`.
- Muitos falsos negativos em brute-force: aumente `-r` (rate limit) e `-w` com cuidado.

## 📁 Estrutura do projeto

```
subdomain-crawler/
├── main.go              # Ponto de entrada
├── cmd/                 # CLI e comandos
│   └── root.go
├── pkg/                 # Bibliotecas principais
│   ├── passive/         # Coleta passiva
│   ├── active/          # Coleta ativa
│   └── output/          # Exportação
├── wordlists/           # Wordlists (ex.: basic.txt)
├── install.bat          # Script de instalação Windows
├── install.sh           # Script de instalação Unix
└── README.md
```

## Como contribuir

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/MinhaFeature`)
3. Commit suas mudanças (`git commit -m 'Add minha feature'`)
4. Push e abra um Pull Request

## Licença

MIT — veja o arquivo `LICENSE`.

## Aviso legal

Use esta ferramenta apenas em domínios que você possui ou tem permissão explícita para testar. O uso indevido pode violar leis locais e termos de serviço.
