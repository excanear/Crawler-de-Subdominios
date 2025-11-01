package passive

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// SubdomainResult representa um subdomínio encontrado
type SubdomainResult struct {
	Subdomain string    `json:"subdomain"`
	Source    string    `json:"source"`
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip,omitempty"`
}

// PassiveCollector interface para coletores passivos
type PassiveCollector interface {
	Collect(domain string) ([]SubdomainResult, error)
	Name() string
}

// CrtShCollector coleta subdomínios do crt.sh
type CrtShCollector struct {
	client *http.Client
}

// NewCrtShCollector cria um novo coletor crt.sh
func NewCrtShCollector() *CrtShCollector {
	return &CrtShCollector{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *CrtShCollector) Name() string {
	return "crt.sh"
}

func (c *CrtShCollector) Collect(domain string) ([]SubdomainResult, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	
	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("erro ao consultar crt.sh: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh retornou status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("erro ao ler resposta: %v", err)
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}

	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("erro ao decodificar JSON: %v", err)
	}

	subdomains := make(map[string]bool)
	var results []SubdomainResult

	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name != "" && strings.HasSuffix(name, "."+domain) && !subdomains[name] {
				subdomains[name] = true
				results = append(results, SubdomainResult{
					Subdomain: name,
					Source:    c.Name(),
					Timestamp: time.Now(),
				})
			}
		}
	}

	return results, nil
}

// HackerTargetCollector coleta subdomínios do HackerTarget
type HackerTargetCollector struct {
	client *http.Client
}

func NewHackerTargetCollector() *HackerTargetCollector {
	return &HackerTargetCollector{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (h *HackerTargetCollector) Name() string {
	return "hackertarget"
}

func (h *HackerTargetCollector) Collect(domain string) ([]SubdomainResult, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	
	resp, err := h.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("erro ao consultar HackerTarget: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HackerTarget retornou status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("erro ao ler resposta: %v", err)
	}

	lines := strings.Split(string(body), "\n")
	var results []SubdomainResult

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "error") {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) >= 2 {
			subdomain := strings.TrimSpace(parts[0])
			ip := strings.TrimSpace(parts[1])
			
			if subdomain != "" && strings.HasSuffix(subdomain, "."+domain) {
				results = append(results, SubdomainResult{
					Subdomain: subdomain,
					Source:    h.Name(),
					Timestamp: time.Now(),
					IP:        ip,
				})
			}
		}
	}

	return results, nil
}

// VirusTotalCollector coleta subdomínios do VirusTotal (necessita API key)
type VirusTotalCollector struct {
	client *http.Client
	apiKey string
}

func NewVirusTotalCollector(apiKey string) *VirusTotalCollector {
	return &VirusTotalCollector{
		client: &http.Client{Timeout: 30 * time.Second},
		apiKey: apiKey,
	}
}

func (v *VirusTotalCollector) Name() string {
	return "virustotal"
}

func (v *VirusTotalCollector) Collect(domain string) ([]SubdomainResult, error) {
	if v.apiKey == "" {
		return nil, fmt.Errorf("API key do VirusTotal não configurada")
	}

	url := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s", v.apiKey, domain)
	
	resp, err := v.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("erro ao consultar VirusTotal: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("VirusTotal retornou status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("erro ao ler resposta: %v", err)
	}

	var vtResponse struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.Unmarshal(body, &vtResponse); err != nil {
		return nil, fmt.Errorf("erro ao decodificar JSON: %v", err)
	}

	var results []SubdomainResult
	for _, subdomain := range vtResponse.Subdomains {
		if subdomain != "" {
			results = append(results, SubdomainResult{
				Subdomain: subdomain,
				Source:    v.Name(),
				Timestamp: time.Now(),
			})
		}
	}

	return results, nil
}

// PassiveScanner orquestra a coleta passiva
type PassiveScanner struct {
	collectors []PassiveCollector
}

func NewPassiveScanner() *PassiveScanner {
	return &PassiveScanner{
		collectors: []PassiveCollector{
			NewCrtShCollector(),
			NewHackerTargetCollector(),
		},
	}
}

func (p *PassiveScanner) AddCollector(collector PassiveCollector) {
	p.collectors = append(p.collectors, collector)
}

func (p *PassiveScanner) Scan(domain string) ([]SubdomainResult, error) {
	var allResults []SubdomainResult
	seen := make(map[string]bool)

	for _, collector := range p.collectors {
		fmt.Printf("[+] Coletando de %s...\n", collector.Name())
		
		results, err := collector.Collect(domain)
		if err != nil {
			fmt.Printf("[!] Erro em %s: %v\n", collector.Name(), err)
			continue
		}

		for _, result := range results {
			if !seen[result.Subdomain] {
				seen[result.Subdomain] = true
				allResults = append(allResults, result)
			}
		}

		fmt.Printf("[+] %s: %d subdomínios encontrados\n", collector.Name(), len(results))
		
		// Pequena pausa entre requisições
		time.Sleep(1 * time.Second)
	}

	return allResults, nil
}

// CleanSubdomain remove caracteres inválidos e normaliza o subdomínio
func CleanSubdomain(subdomain string) string {
	// Remove espaços em branco
	subdomain = strings.TrimSpace(subdomain)
	
	// Remove caracteres especiais comuns
	subdomain = strings.Replace(subdomain, "*.", "", -1)
	
	// Valida formato de domínio
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !domainRegex.MatchString(subdomain) {
		return ""
	}
	
	return strings.ToLower(subdomain)
}