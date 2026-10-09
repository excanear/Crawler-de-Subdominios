package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"subdomain-crawler/pkg/active"
	"subdomain-crawler/pkg/output"
	"subdomain-crawler/pkg/passive"
)

var (
	// Flags globais
	domain         string
	outputDir      string
	outputFormat   string
	passiveOnly    bool
	activeOnly     bool
	workers        int
	timeout        int
	rateLimit      int
	customWordlist string
	vtAPIKey       string
	verbose        bool
	timestamp      bool
)

// rootCmd representa o comando base
var rootCmd = &cobra.Command{
	Use:   "subdomain-crawler",
	Short: "Um crawler avançado de subdomínios com técnicas passivas e ativas",
	Long: `Subdomain Crawler é uma ferramenta completa para descoberta de subdomínios
que combina técnicas passivas (APIs públicas) e ativas (força bruta DNS).

Características:
• Coleta passiva através de múltiplas APIs (crt.sh, HackerTarget, etc.)
• Força bruta inteligente com permutação de subdomínios
• Exportação em múltiplos formatos (wordlist, CSV)
• Controle de taxa e paralelização
• Relatórios detalhados com estatísticas`,
	Example: `  # Scan básico com coleta passiva e ativa
  subdomain-crawler -d example.com

  # Apenas coleta passiva
  subdomain-crawler -d example.com --passive-only

  # Força bruta com wordlist customizada
  subdomain-crawler -d example.com --active-only -w custom_wordlist.txt

  # Scan com configurações avançadas
  subdomain-crawler -d example.com -w 50 -t 10 -r 100 --output-dir ./results`,
	Run: runScan,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Flags do domínio alvo
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domínio alvo para scan (obrigatório)")
	rootCmd.MarkFlagRequired("domain")

	// Flags de saída
	rootCmd.Flags().StringVarP(&outputDir, "output-dir", "o", "./results", "Diretório de saída")
	rootCmd.Flags().StringVar(&outputFormat, "format", "both", "Formato de saída: txt, csv, both")
	rootCmd.Flags().BoolVar(&timestamp, "timestamp", true, "Adicionar timestamp aos arquivos")

	// Flags de modo de operação
	rootCmd.Flags().BoolVar(&passiveOnly, "passive-only", false, "Executar apenas coleta passiva")
	rootCmd.Flags().BoolVar(&activeOnly, "active-only", false, "Executar apenas coleta ativa")

	// Flags de configuração ativa
	rootCmd.Flags().IntVarP(&workers, "workers", "w", 20, "Número de workers para força bruta")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "t", 5, "Timeout DNS em segundos")
	rootCmd.Flags().IntVarP(&rateLimit, "rate-limit", "r", 50, "Rate limit em ms entre requisições")
	rootCmd.Flags().StringVar(&customWordlist, "wordlist", "", "Caminho para wordlist customizada")

	// Flags de APIs
	rootCmd.Flags().StringVar(&vtAPIKey, "virustotal-key", "", "API key do VirusTotal")

	// Flags de controle
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Saída verbosa")
}

func runScan(cmd *cobra.Command, args []string) {
	// Configurar cores
	setupColors()

	// Validar flags
	if err := validateFlags(); err != nil {
		printError("Erro de validação: %v", err)
		os.Exit(1)
	}

	// Limpar e validar domínio
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !isValidDomain(domain) {
		printError("Domínio inválido: %s", domain)
		os.Exit(1)
	}

	printBanner()
	printConfig()

	var allResults []passive.SubdomainResult

	// Executar coleta passiva
	if !activeOnly {
		printSection("🔍 INICIANDO COLETA PASSIVA")
		passiveResults, err := runPassiveScan()
		if err != nil {
			printWarning("Erro na coleta passiva: %v", err)
		} else {
			allResults = append(allResults, passiveResults...)
			printSuccess("Coleta passiva concluída: %d subdomínios encontrados", len(passiveResults))
		}
	}

	// Executar coleta ativa
	if !passiveOnly {
		printSection("⚡ INICIANDO COLETA ATIVA")
		activeResults, err := runActiveScan()
		if err != nil {
			printWarning("Erro na coleta ativa: %v", err)
		} else {
			allResults = append(allResults, activeResults...)
			printSuccess("Coleta ativa concluída: %d subdomínios encontrados", len(activeResults))
		}
	}

	// Exportar resultados
	if len(allResults) > 0 {
		printSection("💾 EXPORTANDO RESULTADOS")
		if err := exportResults(allResults); err != nil {
			printError("Erro ao exportar resultados: %v", err)
			os.Exit(1)
		}
	} else {
		printWarning("Nenhum subdomínio encontrado")
	}
}

func runPassiveScan() ([]passive.SubdomainResult, error) {
	scanner := passive.NewPassiveScanner()
	
	// Adicionar VirusTotal se API key fornecida
	if vtAPIKey != "" {
		scanner.AddCollector(passive.NewVirusTotalCollector(vtAPIKey))
	}

	return scanner.Scan(domain)
}

func runActiveScan() ([]passive.SubdomainResult, error) {
	scanner := active.NewActiveScanner(workers, time.Duration(rateLimit)*time.Millisecond)
	
	var wordlist []string
	if customWordlist != "" {
		var err error
		wordlist, err = loadWordlistFromFile(customWordlist)
		if err != nil {
			return nil, fmt.Errorf("erro ao carregar wordlist: %v", err)
		}
		printInfo("Wordlist customizada carregada: %d palavras", len(wordlist))
	} else {
		wordlist = active.GetDefaultWordlist()
		printInfo("Usando wordlist padrão: %d palavras", len(wordlist))
	}

	return scanner.BruteForce(domain, wordlist)
}

func exportResults(results []passive.SubdomainResult) error {
	config := output.OutputConfig{
		OutputDir:    outputDir,
		BaseFilename: "",
		IncludeCSV:   outputFormat == "csv" || outputFormat == "both",
		IncludeTXT:   outputFormat == "txt" || outputFormat == "both",
		Timestamp:    timestamp,
	}

	manager := output.NewOutputManager(config)
	
	if err := manager.ExportResults(results, domain); err != nil {
		return err
	}

	// Exportar estatísticas
	return manager.ExportStatistics(results, domain)
}

func loadWordlistFromFile(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	var wordlist []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			wordlist = append(wordlist, line)
		}
	}

	return wordlist, nil
}

func validateFlags() error {
	if passiveOnly && activeOnly {
		return fmt.Errorf("--passive-only e --active-only são mutuamente exclusivos")
	}

	if workers < 1 || workers > 100 {
		return fmt.Errorf("número de workers deve estar entre 1 e 100")
	}

	if timeout < 1 || timeout > 60 {
		return fmt.Errorf("timeout deve estar entre 1 e 60 segundos")
	}

	if rateLimit < 10 || rateLimit > 5000 {
		return fmt.Errorf("rate limit deve estar entre 10 e 5000 ms")
	}

	if outputFormat != "txt" && outputFormat != "csv" && outputFormat != "both" {
		return fmt.Errorf("formato deve ser: txt, csv ou both")
	}

	if customWordlist != "" {
		if _, err := os.Stat(customWordlist); os.IsNotExist(err) {
			return fmt.Errorf("arquivo de wordlist não encontrado: %s", customWordlist)
		}
	}

	return nil
}

func isValidDomain(domain string) bool {
	if domain == "" || len(domain) > 255 {
		return false
	}
	
	// Regex básica para validar domínio
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
	}
	
	return true
}

// Funções de output colorido
func setupColors() {
	color.NoColor = false // Forçar cores mesmo no Windows
}

func printBanner() {
	banner := `
██╗   ██╗██╗   ██╗██████╗ ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗
██║   ██║██║   ██║██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║
██║   ██║██║   ██║██████╔╝██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║
██║   ██║██║   ██║██╔══██╗██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║
╚██████╔╝╚██████╔╝██████╔╝██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
 ╚═════╝  ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
                                                                              
 ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗                   
██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗                  
██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝                  
██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗                  
╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║                  
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝                  
`
	
	color.Cyan(banner)
	color.Yellow("        🚀 Subdomain Crawler - Versão 1.0.0")
	color.White("        Desenvolvido para descoberta completa de subdomínios\n")
}

func printConfig() {
	color.White("\n📋 CONFIGURAÇÃO DO SCAN")
	color.White("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("🎯 Domínio alvo: %s\n", color.GreenString(domain))
	fmt.Printf("📁 Diretório de saída: %s\n", outputDir)
	fmt.Printf("📄 Formato de saída: %s\n", outputFormat)
	
	if !passiveOnly && !activeOnly {
		fmt.Println("🔍 Modo: Coleta passiva + ativa")
	} else if passiveOnly {
		fmt.Println("🔍 Modo: Apenas coleta passiva")
	} else {
		fmt.Println("🔍 Modo: Apenas coleta ativa")
	}
	
	if !passiveOnly {
		fmt.Printf("👥 Workers: %d\n", workers)
		fmt.Printf("⏱️  Timeout DNS: %ds\n", timeout)
		fmt.Printf("🐌 Rate limit: %dms\n", rateLimit)
	}
	
	color.White("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
}

func printSection(text string) {
	color.Yellow("\n" + text)
	color.Yellow(strings.Repeat("─", len(text)))
}

func printSuccess(format string, args ...interface{}) {
	color.Green("[✓] "+format, args...)
}

func printError(format string, args ...interface{}) {
	color.Red("[✗] "+format, args...)
}

func printWarning(format string, args ...interface{}) {
	color.Yellow("[!] "+format, args...)
}

func printInfo(format string, args ...interface{}) {
	color.Cyan("[i] "+format, args...)
}