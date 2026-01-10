package subdomain

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

type Result struct {
	Domain        string         `json:"domain"`
	Subdomains    []string       `json:"subdomains"`       // Validated subdomains (alive)
	AllSubdomains []string       `json:"all_subdomains"`   // All discovered before validation (for takeover check)
	Total         int            `json:"total"`
	TotalAll      int            `json:"total_all"`
	Sources       map[string]int `json:"sources"`
	Duration      time.Duration  `json:"duration"`
}

type Enumerator struct {
	cfg *config.Config
	c   *tools.Checker
}

func NewEnumerator(cfg *config.Config, checker *tools.Checker) *Enumerator {
	return &Enumerator{cfg: cfg, c: checker}
}

func (e *Enumerator) Enumerate(domain string) (*Result, error) {
	start := time.Now()
	result := &Result{Domain: domain, Sources: make(map[string]int)}

	var subs sync.Map
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Phase 1: Passive enumeration (parallel)
	fmt.Println("    [*] Passive enumeration...")
	tools := []struct {
		name string
		fn   func(string) []string
	}{
		{"subfinder", e.subfinder},
		{"assetfinder", e.assetfinder},
	}
	if e.c.IsInstalled("vita") {
		tools = append(tools, struct {
			name string
			fn   func(string) []string
		}{"vita", e.vita})
	}
	if e.c.IsInstalled("findomain") {
		tools = append(tools, struct {
			name string
			fn   func(string) []string
		}{"findomain", e.findomain})
	}
	// favirecon uses favicon hashes to find related domains
	if e.cfg.FaviconHash != "" && e.c.IsInstalled("favirecon") {
		tools = append(tools, struct {
			name string
			fn   func(string) []string
		}{"favirecon", e.favirecon})
	}

	for _, t := range tools {
		wg.Add(1)
		go func(name string, fn func(string) []string) {
			defer wg.Done()
			res := fn(domain)
			mu.Lock()
			result.Sources[name] = len(res)
			mu.Unlock()
			for _, s := range res {
				subs.Store(s, true)
			}
			fmt.Printf("        %s: %d\n", name, len(res))
		}(t.name, t.fn)
	}

	// 3rd party API enumeration (parallel with tools)
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("        [*] 3rd party APIs...")
		apiEnum := NewAPIEnumerator(domain)
		apiSubs, apiSources := apiEnum.Enumerate()
		mu.Lock()
		var totalAPI int
		for source, count := range apiSources {
			result.Sources["api_"+source] = count
			totalAPI += count
		}
		mu.Unlock()
		for _, s := range apiSubs {
			subs.Store(s, true)
		}
		fmt.Printf("        3rd_party_apis: %d (from %d sources)\n", len(apiSubs), len(apiSources))
	}()

	// NOTE: wayback/gau subdomain extraction moved to historic phase
	// Historic collector now extracts subdomains from URLs and feeds them back
	// This avoids running wayback/gau twice (once for subs, once for URLs)

	wg.Wait()

	// Phase 2: DNS Bruteforce with puredns (runs in passive mode - DNS is passive)
	if !e.cfg.SkipValidation && e.c.IsInstalled("puredns") {
		fmt.Println("    [*] DNS bruteforce...")
		res := e.bruteforce(domain)
		result.Sources["dns_bruteforce"] = len(res)
		fmt.Printf("        dns_bruteforce: %d\n", len(res))
		for _, s := range res {
			subs.Store(s, true)
		}
	}

	// Collect current subdomains for permutation
	var current []string
	subs.Range(func(k, _ interface{}) bool {
		s := k.(string)
		if strings.HasSuffix(s, "."+domain) || s == domain {
			current = append(current, s)
		}
		return true
	})

	// Phase 3: Permutations (alterx + mksub + dsieve)
	// Runs in passive mode too - permutations are passive (DNS validation)
	maxSubs := 2000

	if len(current) > 0 && len(current) < maxSubs {
		fmt.Println("    [*] Generating permutations...")

		permSet := make(map[string]bool)
		var alterxCount, mksubCount int

		// alterx generates permutations
		if e.c.IsInstalled("alterx") {
			res := e.alterx(current)
			alterxCount = len(res)
			for _, s := range res {
				permSet[s] = true
			}
			fmt.Printf("        alterx: %d\n", alterxCount)
		}

		// mksub
		if e.c.IsInstalled("mksub") {
			res := e.mksub(domain, current)
			mksubCount = len(res)
			for _, s := range res {
				permSet[s] = true
			}
			fmt.Printf("        mksub: %d\n", mksubCount)
		}

		// Convert to slice and filter with dsieve
		var permuted []string
		for s := range permSet {
			permuted = append(permuted, s)
		}

		if len(permuted) > 0 {
			fmt.Printf("        combined unique: %d\n", len(permuted))
			if e.c.IsInstalled("dsieve") {
				permuted = e.dsieve(domain, permuted)
				fmt.Printf("        dsieve filtered: %d\n", len(permuted))
			}
		}

		// Record counts
		result.Sources["alterx"] = alterxCount
		result.Sources["mksub"] = mksubCount
		result.Sources["permutations"] = len(permuted)

		for _, s := range permuted {
			subs.Store(s, true)
		}
	} else if len(current) >= maxSubs {
		fmt.Println("    [*] Permutations... SKIPPED (too many subdomains)")
	}

	// Collect all subdomains (before validation - for takeover detection)
	var all []string
	subs.Range(func(k, _ interface{}) bool {
		s := k.(string)
		if strings.HasSuffix(s, "."+domain) || s == domain {
			all = append(all, s)
		}
		return true
	})
	sort.Strings(all)

	// Store all subdomains before validation (for takeover check on dangling DNS)
	result.AllSubdomains = all
	result.TotalAll = len(all)

	// Phase 4: DNS Validation (puredns > dnsx fallback)
	validated := all
	if !e.cfg.SkipValidation && len(all) > 0 {
		fmt.Println("    [*] DNS validation...")
		validated = e.validate(all)
		fmt.Printf("        validated: %d alive\n", len(validated))
	}

	sort.Strings(validated)
	result.Subdomains = validated
	result.Total = len(validated)
	result.Duration = time.Since(start)
	return result, nil
}

func (e *Enumerator) subfinder(domain string) []string {
	if !e.c.IsInstalled("subfinder") {
		return nil
	}
	args := []string{"-d", domain, "-silent", "-all"}
	if e.cfg.Threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", e.cfg.Threads))
	}
	r := exec.Run("subfinder", args, &exec.Options{Timeout: 5 * time.Minute})
	if r.Error != nil {
		return nil
	}
	return exec.Lines(r.Stdout)
}

func (e *Enumerator) assetfinder(domain string) []string {
	if !e.c.IsInstalled("assetfinder") {
		return nil
	}
	r := exec.Run("assetfinder", []string{"--subs-only", domain}, &exec.Options{Timeout: 3 * time.Minute})
	if r.Error != nil {
		return nil
	}
	return exec.Lines(r.Stdout)
}

func (e *Enumerator) vita(domain string) []string {
	if !e.c.IsInstalled("vita") {
		return nil
	}
	r := exec.Run("vita", []string{"-d", domain}, &exec.Options{Timeout: 3 * time.Minute})
	if r.Error != nil {
		return nil
	}
	return exec.Lines(r.Stdout)
}

func (e *Enumerator) findomain(domain string) []string {
	if !e.c.IsInstalled("findomain") {
		return nil
	}
	r := exec.Run("findomain", []string{"-t", domain, "-q"}, &exec.Options{Timeout: 3 * time.Minute})
	if r.Error != nil {
		return nil
	}
	return exec.Lines(r.Stdout)
}

func (e *Enumerator) favirecon(domain string) []string {
	if !e.c.IsInstalled("favirecon") || e.cfg.FaviconHash == "" {
		return nil
	}
	// favirecon -fh <hash> finds domains using that favicon hash
	// It queries Shodan, so results may include subdomains of the target
	args := []string{"-fh", e.cfg.FaviconHash, "-silent"}
	r := exec.Run("favirecon", args, &exec.Options{Timeout: 2 * time.Minute})
	if r.Error != nil {
		return nil
	}
	// Filter results to only include subdomains of the target domain
	var results []string
	suffix := "." + domain
	for _, line := range exec.Lines(r.Stdout) {
		if strings.HasSuffix(line, suffix) || line == domain {
			results = append(results, line)
		}
	}
	return results
}

func (e *Enumerator) bruteforce(domain string) []string {
	if !e.c.IsInstalled("puredns") {
		return nil
	}
	wl := e.cfg.WordlistFile
	if wl == "" {
		// Use tools package to find wordlist (checks ~/.reconator/wordlists first)
		wl = tools.FindWordlist()
	}
	if wl == "" {
		fmt.Println("        (no wordlist found, run 'reconator install' first)")
		return nil
	}
	// puredns bruteforce <wordlist> <domain> -q (quiet mode outputs to stdout)
	args := []string{"bruteforce", wl, domain, "-q"}
	// Use resolvers from config or find installed resolvers
	resolvers := e.cfg.ResolversFile
	if resolvers == "" {
		resolvers = tools.FindResolvers()
	}
	if resolvers != "" {
		args = append(args, "-r", resolvers)
	}
	if e.cfg.DNSThreads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", e.cfg.DNSThreads))
	}
	// Increase rate limit for faster bruteforce
	args = append(args, "--rate-limit", "500")
	r := exec.Run("puredns", args, &exec.Options{Timeout: 15 * time.Minute})
	if r.Error != nil {
		// Check stderr for any output if stdout is empty
		if r.Stderr != "" && r.Stdout == "" {
			return exec.Lines(r.Stderr)
		}
		return nil
	}
	return exec.Lines(r.Stdout)
}

func (e *Enumerator) alterx(subs []string) []string {
	if !e.c.IsInstalled("alterx") {
		return nil
	}
	tmp, cleanup, err := exec.TempFile(strings.Join(subs, "\n"), ".txt")
	if err != nil {
		return nil
	}
	defer cleanup()
	r := exec.Run("alterx", []string{"-l", tmp, "-silent"}, &exec.Options{Timeout: 5 * time.Minute})
	if r.Error != nil {
		return nil
	}
	return exec.Lines(r.Stdout)
}

func (e *Enumerator) mksub(domain string, subs []string) []string {
	if !e.c.IsInstalled("mksub") {
		return nil
	}
	// Extract subdomain prefixes as wordlist for mksub
	// e.g., "api.test.example.com" -> "api", "test"
	words := make(map[string]bool)
	suffix := "." + domain
	for _, s := range subs {
		s = strings.TrimSuffix(s, suffix)
		for _, part := range strings.Split(s, ".") {
			if part != "" && len(part) > 1 {
				words[part] = true
			}
		}
	}
	var wordList []string
	for w := range words {
		wordList = append(wordList, w)
	}
	if len(wordList) == 0 {
		return nil
	}
	tmp, cleanup, err := exec.TempFile(strings.Join(wordList, "\n"), ".txt")
	if err != nil {
		return nil
	}
	defer cleanup()
	// mksub uses -w for wordlist, not -l (which is for subdomain level)
	r := exec.Run("mksub", []string{"-d", domain, "-w", tmp}, &exec.Options{Timeout: 5 * time.Minute})
	if r.Error != nil {
		return nil
	}
	return exec.Lines(r.Stdout)
}

func (e *Enumerator) dsieve(domain string, subs []string) []string {
	if !e.c.IsInstalled("dsieve") {
		return subs
	}
	tmp, cleanup, err := exec.TempFile(strings.Join(subs, "\n"), ".txt")
	if err != nil {
		return subs
	}
	defer cleanup()
	r := exec.Run("dsieve", []string{"-if", tmp, "-f", "3"}, &exec.Options{Timeout: 2 * time.Minute})
	if r.Error != nil {
		return subs
	}
	if res := exec.Lines(r.Stdout); len(res) > 0 {
		return res
	}
	return subs
}

func (e *Enumerator) validate(subs []string) []string {
	tmp, cleanup, err := exec.TempFile(strings.Join(subs, "\n"), ".txt")
	if err != nil {
		return subs
	}
	defer cleanup()

	// Prefer dnsx for validation - it reliably outputs to stdout
	if e.c.IsInstalled("dnsx") {
		args := []string{"-l", tmp, "-silent", "-resp"}
		if e.cfg.DNSThreads > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", e.cfg.DNSThreads))
		}
		if r := exec.Run("dnsx", args, &exec.Options{Timeout: 10 * time.Minute}); r.Error == nil {
			// dnsx with -resp outputs "domain [ip]", extract just the domain
			var results []string
			for _, line := range exec.Lines(r.Stdout) {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					results = append(results, parts[0])
				}
			}
			if len(results) > 0 {
				return results
			}
		}
	}

	// Fallback to puredns with explicit output file
	if e.c.IsInstalled("puredns") {
		outTmp, outCleanup, err := exec.TempFile("", "-resolved.txt")
		if err != nil {
			return subs
		}
		defer outCleanup()

		args := []string{"resolve", tmp, "-q", "-w", outTmp}
		// Use resolvers from config or find installed resolvers
		resolvers := e.cfg.ResolversFile
		if resolvers == "" {
			resolvers = tools.FindResolvers()
		}
		if resolvers != "" {
			args = append(args, "-r", resolvers)
		}
		if e.cfg.DNSThreads > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", e.cfg.DNSThreads))
		}
		if r := exec.Run("puredns", args, &exec.Options{Timeout: 10 * time.Minute}); r.Error == nil {
			// Read from output file
			if content, err := os.ReadFile(outTmp); err == nil {
				if results := exec.Lines(string(content)); len(results) > 0 {
					return results
				}
			}
		}
	}

	return subs
}

// NOTE: waybackSubdomains, gauSubdomains, extractSubdomainsFromURLs removed
// Subdomain extraction from historic URLs is now done in historic/collector.go
// This avoids duplicate wayback/gau execution
