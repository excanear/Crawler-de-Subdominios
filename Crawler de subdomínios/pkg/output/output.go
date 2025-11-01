package output

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"subdomain-crawler/pkg/passive"
)

// OutputConfig configurações de saída
type OutputConfig struct {
	OutputDir    string
	BaseFilename string
	IncludeCSV   bool
	IncludeTXT   bool
	Timestamp    bool
}

// OutputManager gerencia a exportação dos resultados
type OutputManager struct {
	config OutputConfig
}

func NewOutputManager(config OutputConfig) *OutputManager {
	return &OutputManager{config: config}
}

// ExportResults exporta os resultados nos formatos especificados
func (om *OutputManager) ExportResults(results []passive.SubdomainResult, domain string) error {
	// Criar diretório de saída se não existir
	if err := os.MkdirAll(om.config.OutputDir, 0755); err != nil {
		return fmt.Errorf("erro ao criar diretório de saída: %v", err)
	}

	// Gerar nome base do arquivo
	baseFilename := om.generateBaseFilename(domain)

	// Remover duplicatas e ordenar
	uniqueResults := om.removeDuplicates(results)
	sort.Slice(uniqueResults, func(i, j int) bool {
		return uniqueResults[i].Subdomain < uniqueResults[j].Subdomain
	})

	var exportedFiles []string

	// Exportar como wordlist (TXT)
	if om.config.IncludeTXT {
		txtFile := filepath.Join(om.config.OutputDir, baseFilename+".txt")
		if err := om.exportWordlist(uniqueResults, txtFile); err != nil {
			return fmt.Errorf("erro ao exportar wordlist: %v", err)
		}
		exportedFiles = append(exportedFiles, txtFile)
	}

	// Exportar como CSV
	if om.config.IncludeCSV {
		csvFile := filepath.Join(om.config.OutputDir, baseFilename+".csv")
		if err := om.exportCSV(uniqueResults, csvFile); err != nil {
			return fmt.Errorf("erro ao exportar CSV: %v", err)
		}
		exportedFiles = append(exportedFiles, csvFile)
	}

	// Imprimir resumo
	om.printSummary(uniqueResults, exportedFiles, domain)

	return nil
}

// generateBaseFilename gera o nome base do arquivo
func (om *OutputManager) generateBaseFilename(domain string) string {
	baseFilename := om.config.BaseFilename
	if baseFilename == "" {
		baseFilename = strings.Replace(domain, ".", "_", -1) + "_subdomains"
	}

	if om.config.Timestamp {
		timestamp := time.Now().Format("20060102_150405")
		baseFilename += "_" + timestamp
	}

	return baseFilename
}

// exportWordlist exporta os subdomínios como wordlist
func (om *OutputManager) exportWordlist(results []passive.SubdomainResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Escrever header com informações
	fmt.Fprintf(file, "# Wordlist de subdomínios\n")
	fmt.Fprintf(file, "# Gerado em: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "# Total de subdomínios: %d\n", len(results))
	fmt.Fprintf(file, "#\n")

	// Escrever subdomínios
	for _, result := range results {
		fmt.Fprintln(file, result.Subdomain)
	}

	return nil
}

// exportCSV exporta os subdomínios como CSV com detalhes
func (om *OutputManager) exportCSV(results []passive.SubdomainResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Escrever header
	header := []string{"Subdomain", "IP", "Source", "Timestamp", "HTTP_Status", "Title", "Technologies"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Escrever dados
	for _, result := range results {
		record := []string{
			result.Subdomain,
			result.IP,
			result.Source,
			result.Timestamp.Format("2006-01-02 15:04:05"),
			"", // HTTP Status - pode ser preenchido por verificação adicional
			"", // Title - pode ser preenchido por verificação adicional
			"", // Technologies - pode ser preenchido por verificação adicional
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// removeDuplicates remove subdomínios duplicados
func (om *OutputManager) removeDuplicates(results []passive.SubdomainResult) []passive.SubdomainResult {
	seen := make(map[string]passive.SubdomainResult)
	
	for _, result := range results {
		if existing, exists := seen[result.Subdomain]; exists {
			// Manter o resultado com mais informações (IP, por exemplo)
			if result.IP != "" && existing.IP == "" {
				seen[result.Subdomain] = result
			}
		} else {
			seen[result.Subdomain] = result
		}
	}

	var unique []passive.SubdomainResult
	for _, result := range seen {
		unique = append(unique, result)
	}

	return unique
}

// printSummary imprime um resumo dos resultados
func (om *OutputManager) printSummary(results []passive.SubdomainResult, exportedFiles []string, domain string) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Printf("🎯 RESUMO DO SCAN - %s\n", domain)
	fmt.Println(strings.Repeat("=", 60))
	
	// Estatísticas gerais
	fmt.Printf("📊 Total de subdomínios únicos: %d\n", len(results))
	
	// Estatísticas por fonte
	sources := make(map[string]int)
	withIP := 0
	
	for _, result := range results {
		sources[result.Source]++
		if result.IP != "" {
			withIP++
		}
	}
	
	fmt.Printf("🌐 Subdomínios com IP resolvido: %d\n", withIP)
	fmt.Println("\n📋 Resultados por fonte:")
	
	for source, count := range sources {
		fmt.Printf("   • %s: %d subdomínios\n", source, count)
	}
	
	// Arquivos exportados
	fmt.Println("\n📁 Arquivos gerados:")
	for _, file := range exportedFiles {
		fmt.Printf("   • %s\n", file)
	}
	
	// Amostra de subdomínios
	fmt.Println("\n🔍 Amostra de subdomínios encontrados:")
	limit := 10
	if len(results) < limit {
		limit = len(results)
	}
	
	for i := 0; i < limit; i++ {
		result := results[i]
		if result.IP != "" {
			fmt.Printf("   • %s (%s)\n", result.Subdomain, result.IP)
		} else {
			fmt.Printf("   • %s\n", result.Subdomain)
		}
	}
	
	if len(results) > limit {
		fmt.Printf("   ... e mais %d subdomínios\n", len(results)-limit)
	}
	
	fmt.Println(strings.Repeat("=", 60))
}

// ExportStatistics exporta estatísticas detalhadas
func (om *OutputManager) ExportStatistics(results []passive.SubdomainResult, domain string) error {
	statsFile := filepath.Join(om.config.OutputDir, om.generateBaseFilename(domain)+"_stats.txt")
	
	file, err := os.Create(statsFile)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "RELATÓRIO DE ESTATÍSTICAS - %s\n", domain)
	fmt.Fprintf(file, "Gerado em: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "%s\n\n", strings.Repeat("=", 50))

	// Estatísticas gerais
	fmt.Fprintf(file, "ESTATÍSTICAS GERAIS\n")
	fmt.Fprintf(file, "Total de subdomínios: %d\n", len(results))

	// Contar por fonte
	sources := make(map[string]int)
	withIP := 0
	
	for _, result := range results {
		sources[result.Source]++
		if result.IP != "" {
			withIP++
		}
	}

	fmt.Fprintf(file, "Subdomínios com IP: %d\n", withIP)
	fmt.Fprintf(file, "Taxa de resolução: %.2f%%\n\n", float64(withIP)/float64(len(results))*100)

	// Resultados por fonte
	fmt.Fprintf(file, "RESULTADOS POR FONTE\n")
	for source, count := range sources {
		percentage := float64(count) / float64(len(results)) * 100
		fmt.Fprintf(file, "%s: %d (%.2f%%)\n", source, count, percentage)
	}

	// Análise de padrões de subdomínios
	fmt.Fprintf(file, "\nANÁLISE DE PADRÕES\n")
	patterns := om.analyzePatterns(results)
	for pattern, count := range patterns {
		if count > 1 {
			fmt.Fprintf(file, "Padrão '%s': %d ocorrências\n", pattern, count)
		}
	}

	fmt.Printf("[+] Estatísticas salvas em: %s\n", statsFile)
	return nil
}

// analyzePatterns analisa padrões comuns nos subdomínios
func (om *OutputManager) analyzePatterns(results []passive.SubdomainResult) map[string]int {
	patterns := make(map[string]int)
	
	for _, result := range results {
		subdomain := result.Subdomain
		parts := strings.Split(subdomain, ".")
		
		if len(parts) > 2 {
			// Analisar o primeiro nível (subdomínio principal)
			firstLevel := parts[0]
			
			// Padrões com números
			if strings.ContainsAny(firstLevel, "0123456789") {
				patterns["contém_números"]++
			}
			
			// Padrões com hífens
			if strings.Contains(firstLevel, "-") {
				patterns["contém_hífen"]++
			}
			
			// Padrões com underscore
			if strings.Contains(firstLevel, "_") {
				patterns["contém_underscore"]++
			}
			
			// Padrões de tamanho
			if len(firstLevel) > 10 {
				patterns["nome_longo"]++
			}
			
			if len(firstLevel) <= 3 {
				patterns["nome_curto"]++
			}
		}
	}
	
	return patterns
}