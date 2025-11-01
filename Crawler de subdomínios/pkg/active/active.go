package active

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"subdomain-crawler/pkg/passive"
)

// DNSResolver wrapper para resolução DNS
type DNSResolver struct {
	resolver *net.Resolver
	timeout  time.Duration
}

func NewDNSResolver(timeout time.Duration) *DNSResolver {
	return &DNSResolver{
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: timeout,
				}
				return d.DialContext(ctx, network, address)
			},
		},
		timeout: timeout,
	}
}

// ResolveSubdomain tenta resolver um subdomínio
func (d *DNSResolver) ResolveSubdomain(subdomain string) (*passive.SubdomainResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	// Tenta resolver A records
	ips, err := d.resolver.LookupIPAddr(ctx, subdomain)
	if err != nil {
		return nil, err
	}

	if len(ips) > 0 {
		return &passive.SubdomainResult{
			Subdomain: subdomain,
			Source:    "dns_bruteforce",
			Timestamp: time.Now(),
			IP:        ips[0].IP.String(),
		}, nil
	}

	return nil, fmt.Errorf("nenhum IP encontrado")
}

// SubdomainGenerator gera permutações de subdomínios
type SubdomainGenerator struct {
	wordlist []string
	domain   string
}

func NewSubdomainGenerator(domain string, wordlist []string) *SubdomainGenerator {
	return &SubdomainGenerator{
		wordlist: wordlist,
		domain:   domain,
	}
}

// GenerateSubdomains gera todas as permutações possíveis
func (sg *SubdomainGenerator) GenerateSubdomains() []string {
	var subdomains []string

	// Subdomínios básicos
	for _, word := range sg.wordlist {
		subdomain := fmt.Sprintf("%s.%s", word, sg.domain)
		subdomains = append(subdomains, subdomain)
	}

	// Permutações com números
	commonNumbers := []string{"1", "2", "3", "01", "02", "03", "10", "20", "30", "100", "200", "300"}
	for _, word := range sg.wordlist {
		for _, num := range commonNumbers {
			// word + number
			subdomain1 := fmt.Sprintf("%s%s.%s", word, num, sg.domain)
			subdomains = append(subdomains, subdomain1)
			
			// number + word
			subdomain2 := fmt.Sprintf("%s%s.%s", num, word, sg.domain)
			subdomains = append(subdomains, subdomain2)
		}
	}

	// Permutações com separadores
	separators := []string{"-", "_"}
	for _, word1 := range sg.wordlist {
		for _, word2 := range sg.wordlist {
			if word1 != word2 {
				for _, sep := range separators {
					subdomain := fmt.Sprintf("%s%s%s.%s", word1, sep, word2, sg.domain)
					subdomains = append(subdomains, subdomain)
				}
			}
		}
	}

	// Permutações com prefixos/sufixos comuns
	prefixes := []string{"dev", "test", "staging", "prod", "beta", "alpha", "demo"}
	suffixes := []string{"prod", "dev", "test", "staging", "backup", "old", "new"}
	
	for _, word := range sg.wordlist {
		for _, prefix := range prefixes {
			subdomain := fmt.Sprintf("%s-%s.%s", prefix, word, sg.domain)
			subdomains = append(subdomains, subdomain)
		}
		for _, suffix := range suffixes {
			subdomain := fmt.Sprintf("%s-%s.%s", word, suffix, sg.domain)
			subdomains = append(subdomains, subdomain)
		}
	}

	return subdomains
}

// ActiveScanner realiza varredura ativa de subdomínios
type ActiveScanner struct {
	resolver    *DNSResolver
	workers     int
	rateLimiter <-chan time.Time
}

func NewActiveScanner(workers int, rateLimit time.Duration) *ActiveScanner {
	return &ActiveScanner{
		resolver:    NewDNSResolver(5 * time.Second),
		workers:     workers,
		rateLimiter: time.Tick(rateLimit),
	}
}

// BruteForce realiza força bruta nos subdomínios
func (as *ActiveScanner) BruteForce(domain string, wordlist []string) ([]passive.SubdomainResult, error) {
	generator := NewSubdomainGenerator(domain, wordlist)
	subdomains := generator.GenerateSubdomains()

	fmt.Printf("[+] Gerando %d permutações de subdomínios...\n", len(subdomains))

	// Canal para subdomínios a serem testados
	subdomainChan := make(chan string, 100)
	
	// Canal para resultados
	resultChan := make(chan passive.SubdomainResult, 100)
	
	// Canal para indicar fim do trabalho
	done := make(chan bool)

	var wg sync.WaitGroup

	// Iniciar workers
	for i := 0; i < as.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			as.worker(subdomainChan, resultChan)
		}()
	}

	// Goroutine para coletar resultados
	var results []passive.SubdomainResult
	go func() {
		for result := range resultChan {
			results = append(results, result)
			fmt.Printf("[+] Encontrado: %s -> %s\n", result.Subdomain, result.IP)
		}
		done <- true
	}()

	// Enviar subdomínios para os workers
	go func() {
		defer close(subdomainChan)
		for _, subdomain := range subdomains {
			<-as.rateLimiter // Rate limiting
			subdomainChan <- subdomain
		}
	}()

	// Aguardar workers terminarem
	wg.Wait()
	close(resultChan)
	
	// Aguardar coleta de resultados
	<-done

	return results, nil
}

// worker processa subdomínios do canal
func (as *ActiveScanner) worker(subdomainChan <-chan string, resultChan chan<- passive.SubdomainResult) {
	for subdomain := range subdomainChan {
		if result, err := as.resolver.ResolveSubdomain(subdomain); err == nil {
			resultChan <- *result
		}
	}
}

// GetDefaultWordlist retorna uma wordlist padrão para força bruta
func GetDefaultWordlist() []string {
	return []string{
		// Subdomínios comuns
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2",
		"cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog",
		"pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new",
		"mysql", "old", "www1", "email", "beta", "bb", "smtp2", "stage", "secure", "www3",
		
		// Aplicações e serviços
		"api", "app", "cdn", "db", "web", "sql", "git", "svn", "ftp2", "backup",
		"dev", "staging", "prod", "production", "demo", "sandbox", "jenkins", "ci",
		"monitoring", "stats", "status", "health", "metrics", "logs", "kibana",
		
		// Departamentos
		"hr", "finance", "accounting", "sales", "marketing", "support", "helpdesk",
		"it", "tech", "engineering", "research", "legal", "compliance",
		
		// Geográficos
		"us", "eu", "asia", "na", "sa", "africa", "oceania", "global",
		"east", "west", "north", "south", "central",
		
		// Ambientes
		"local", "internal", "external", "public", "private", "secure", "testing",
		"qa", "uat", "preprod", "live", "stable", "experimental",
		
		// Protocolos e serviços
		"ssh", "sftp", "telnet", "ssl", "tls", "vpn", "proxy", "gateway",
		"router", "switch", "firewall", "dns", "dhcp", "ntp", "ldap",
		
		// Aplicações específicas
		"wordpress", "wp", "joomla", "drupal", "magento", "shopify",
		"confluence", "jira", "redmine", "gitlab", "github", "bitbucket",
		"docker", "k8s", "kubernetes", "grafana", "prometheus", "elk",
		
		// Números e variações
		"01", "02", "03", "1", "2", "3", "10", "20", "30", "100", "200", "300",
	}
}