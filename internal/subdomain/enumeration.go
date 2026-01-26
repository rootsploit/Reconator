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

	// Phase 1: Passive enumeration + DNS bruteforce (ALL PARALLEL)
	// puredns bruteforce uses a wordlist, not discovered subs, so it's independent
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

	// DNS Bruteforce with puredns - RUNS IN PARALLEL with passive enum
	// This is independent because it uses a wordlist, not discovered subdomains
	// Moving this to parallel saves 30-60 seconds per scan
	if !e.cfg.SkipValidation && e.c.IsInstalled("puredns") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println("    [*] DNS bruteforce (parallel)...")
			res := e.bruteforce(domain)
			mu.Lock()
			result.Sources["dns_bruteforce"] = len(res)
			mu.Unlock()
			for _, s := range res {
				subs.Store(s, true)
			}
			fmt.Printf("        dns_bruteforce: %d\n", len(res))
		}()
	}

	// NOTE: wayback/gau subdomain extraction moved to historic phase
	// Historic collector now extracts subdomains from URLs and feeds them back
	// This avoids running wayback/gau twice (once for subs, once for URLs)

	wg.Wait()

	// Collect current subdomains for permutation
	var current []string
	subs.Range(func(k, _ interface{}) bool {
		s := k.(string)
		if strings.HasSuffix(s, "."+domain) || s == domain {
			current = append(current, s)
		}
		return true
	})

	// Phase 3: Permutations (alterx + mksub + dsieve) - PARALLEL
	// alterx and mksub both take current subdomains as input (independent)
	// Running them in parallel saves 30-60 seconds per scan
	maxSubs := 2000

	if len(current) > 0 && len(current) < maxSubs {
		fmt.Println("    [*] Generating permutations (parallel)...")

		var permMu sync.Mutex
		permSet := make(map[string]bool)
		var alterxCount, mksubCount, aiPermCount int
		var permWg sync.WaitGroup

		// alterx generates permutations - PARALLEL
		if e.c.IsInstalled("alterx") {
			permWg.Add(1)
			go func() {
				defer permWg.Done()
				res := e.alterx(current)
				permMu.Lock()
				alterxCount = len(res)
				for _, s := range res {
					permSet[s] = true
				}
				permMu.Unlock()
				fmt.Printf("        alterx: %d\n", alterxCount)
			}()
		}

		// mksub - PARALLEL
		if e.c.IsInstalled("mksub") {
			permWg.Add(1)
			go func() {
				defer permWg.Done()
				res := e.mksub(domain, current)
				permMu.Lock()
				mksubCount = len(res)
				for _, s := range res {
					permSet[s] = true
				}
				permMu.Unlock()
				fmt.Printf("        mksub: %d\n", mksubCount)
			}()
		}

		// AI-powered permutations (uses LLM to analyze patterns) - PARALLEL
		hasAIKeys := e.cfg.OpenAIKey != "" || e.cfg.ClaudeKey != "" || e.cfg.GeminiKey != ""
		if hasAIKeys && len(current) >= 5 { // Need at least 5 subdomains for pattern analysis
			permWg.Add(1)
			go func() {
				defer permWg.Done()
				aiPerm := NewAIPermutator(e.cfg)
				aiPerms, err := aiPerm.GenerateSmartPermutations(domain, current)
				if err == nil && len(aiPerms) > 0 {
					permMu.Lock()
					aiPermCount = len(aiPerms)
					for _, s := range aiPerms {
						permSet[s] = true
					}
					permMu.Unlock()
					fmt.Printf("        ai_permutation: %d\n", aiPermCount)
				}
			}()
		}

		// Wait for all permutation generators to complete
		permWg.Wait()

		// Convert to slice (dsieve removed - dnsx is fast enough to validate all permutations)
		var permuted []string
		for s := range permSet {
			permuted = append(permuted, s)
		}

		if len(permuted) > 0 {
			fmt.Printf("        combined unique: %d\n", len(permuted))
			// NOTE: dsieve filtering removed - with resolvers, dnsx validates 7500 subs in ~10s
			// Old dsieve -f 2 was too aggressive (7524 → 1)
		}

		// Record counts
		result.Sources["alterx"] = alterxCount
		result.Sources["mksub"] = mksubCount
		result.Sources["ai_permutation"] = aiPermCount
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

	// Phase 5: SSL Certificate Recon (tlsx/CloudRecon + kaeferjaeger.gay IP ranges)
	// Scans cloud provider IP ranges for SSL certificates matching target domain
	// Discovers additional subdomains from certificate CN and SAN fields
	if (e.c.IsInstalled("tlsx") || e.c.IsInstalled("CloudRecon")) && !e.cfg.PassiveMode {
		sslRecon := NewSSLCertRecon(e.cfg, e.c)

		// Resolve validated subdomain IPs for targeted scanning
		var resolvedIPs []string
		if len(validated) > 0 {
			resolvedIPs = sslRecon.ResolveSubdomainIPs(validated)
		}

		sslResult, err := sslRecon.Discover(domain, resolvedIPs)
		if err == nil && len(sslResult.Subdomains) > 0 {
			// Record sources
			for source, count := range sslResult.Sources {
				result.Sources[source] = count
			}

			// Validate new subdomains before adding
			newSubs := sslResult.Subdomains
			if !e.cfg.SkipValidation {
				fmt.Println("    [*] Validating SSL cert discoveries...")
				newSubs = e.validate(newSubs)
				fmt.Printf("        ssl_cert_validated: %d alive\n", len(newSubs))
			}

			// Add to validated list
			for _, sub := range newSubs {
				validated = append(validated, sub)
			}

			// Also add to AllSubdomains for takeover checking
			result.AllSubdomains = append(result.AllSubdomains, sslResult.Subdomains...)
		}
	}

	// Dedupe and sort validated subdomains by level (lower levels first for priority scanning)
	// This ensures level 1 subdomains (api.example.com) are scanned before level 3 (a.b.api.example.com)
	validated = uniqueStrings(validated)
	sortSubdomainsByLevel(validated, domain)
	result.Subdomains = validated
	result.Total = len(validated)
	result.Duration = time.Since(start)
	return result, nil
}

// uniqueStrings removes duplicates from a slice of strings
func uniqueStrings(s []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}

// sortSubdomainsByLevel sorts subdomains by their level (depth) relative to the base domain
// Level 1: api.example.com (1 label before base)
// Level 2: dev.api.example.com (2 labels before base)
// This ensures important top-level subdomains are scanned first before deeper ones
// which helps when rate limiting or WAF blocking occurs
func sortSubdomainsByLevel(subs []string, baseDomain string) {
	baseLabels := strings.Count(baseDomain, ".") + 1 // example.com = 2 labels

	sort.Slice(subs, func(i, j int) bool {
		levelI := strings.Count(subs[i], ".") + 1 - baseLabels
		levelJ := strings.Count(subs[j], ".") + 1 - baseLabels

		// Sort by level first (ascending - lower levels first)
		if levelI != levelJ {
			return levelI < levelJ
		}
		// Then alphabetically within same level
		return subs[i] < subs[j]
	})
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

	// BB-5: Enhanced puredns flags for v2.x
	// --skip-wildcard-filter: Skip wildcard detection to prevent false positives
	// -l: Rate limit for public resolvers
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

	// BB-5: Skip wildcard filtering to prevent false positives
	// puredns v2.x uses --skip-wildcard-filter (not --skip-wildcard)
	args = append(args, "--skip-wildcard-filter")
	// Rate limit for public resolvers (puredns v2.x uses -l not --rate-limit)
	args = append(args, "-l", "500")

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

	// Limit alterx output to prevent permutation explosion
	// Default generates 50k+ permutations which overwhelms dnsx validation
	// Cap at 5000 to balance discovery vs validation time
	args := []string{"-l", tmp, "-silent", "-limit", "5000"}

	r := exec.Run("alterx", args, &exec.Options{Timeout: 5 * time.Minute})
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

	// Limit wordlist size to prevent combinatorial explosion
	// With 100 words at level 2, mksub generates 100*100 = 10k combinations
	maxWords := 50
	if len(wordList) > maxWords {
		wordList = wordList[:maxWords]
	}

	tmp, cleanup, err := exec.TempFile(strings.Join(wordList, "\n"), ".txt")
	if err != nil {
		return nil
	}
	defer cleanup()

	// mksub uses -w for wordlist, -l for subdomain level (depth)
	// Limit to level 2 to prevent permutation explosion (level 3+ = millions of combinations)
	r := exec.Run("mksub", []string{"-d", domain, "-w", tmp, "-l", "2"}, &exec.Options{Timeout: 5 * time.Minute})
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

	// dsieve -f filters by subdomain level
	// -f 2: Keep only subdomains with 2 or fewer levels (e.g., api.example.com, not api.dev.example.com)
	// This reduces permutation count significantly while keeping high-value targets
	r := exec.Run("dsieve", []string{"-if", tmp, "-f", "2"}, &exec.Options{Timeout: 2 * time.Minute})
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
		// Optimized dnsx flags for fast mass resolution:
		// - Use resolvers file (CRITICAL - system DNS is 10x slower)
		// - High thread count for parallel resolution
		// - Skip -cname and -wd for pure validation speed (takeover phase does its own CNAME check)
		args := []string{
			"-l", tmp,
			"-silent",
			"-resp", // Still need response to confirm resolution
		}

		// CRITICAL FIX: Use resolvers file - without this, dnsx uses system DNS which is 10x slower
		resolvers := e.cfg.ResolversFile
		if resolvers == "" {
			resolvers = tools.FindResolvers()
		}
		if resolvers != "" {
			args = append(args, "-r", resolvers)
			fmt.Printf("        using resolvers: %s\n", resolvers)
		}

		// Thread count for DNS resolution
		// NOTE: More threads != faster! Public resolvers throttle aggressive clients.
		// Sweet spot: 100-150 threads. Going higher causes:
		// - Resolver rate limiting → timeouts → retries → slower
		// - TCP connection overhead
		// - Network congestion
		threads := e.cfg.DNSThreads
		if threads <= 0 {
			threads = 100 // dnsx default - well tested
		}
		args = append(args, "-t", fmt.Sprintf("%d", threads))

		// NOTE: Rate limit removed - dnsx handles this internally
		// The -rl flag was causing ~2x slowdown in testing
		// If you experience resolver bans, add: args = append(args, "-rl", "10000")

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
