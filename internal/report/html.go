package report

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rootsploit/reconator/internal/aiguided"
	"github.com/rootsploit/reconator/internal/dirbrute"
	"github.com/rootsploit/reconator/internal/historic"
	"github.com/rootsploit/reconator/internal/iprange"
	"github.com/rootsploit/reconator/internal/portscan"
	"github.com/rootsploit/reconator/internal/screenshot"
	"github.com/rootsploit/reconator/internal/subdomain"
	"github.com/rootsploit/reconator/internal/takeover"
	"github.com/rootsploit/reconator/internal/techdetect"
	"github.com/rootsploit/reconator/internal/vulnscan"
	"github.com/rootsploit/reconator/internal/waf"
)

// Data holds all scan results for the report
type Data struct {
	// Metadata
	Target   string
	Version  string
	Date     string
	Duration string
	Command  string

	// Phase Results
	Subdomain  *subdomain.Result
	WAF        *waf.Result
	Ports      *portscan.Result
	Takeover   *takeover.Result
	Historic   *historic.Result
	Tech       *techdetect.Result
	DirBrute   *dirbrute.Result
	VulnScan   *vulnscan.Result
	AIGuided   *aiguided.Result
	IPRange    *iprange.Result
	Screenshot *screenshot.Result
	OSINT      interface{}

	// Computed per-subdomain details
	SubdomainDetails []SubdomainDetail

	// Screenshots embedded as base64 for self-contained HTML
	ScreenshotImages []ScreenshotImage
}

// ScreenshotImage holds a screenshot with embedded base64 data
type ScreenshotImage struct {
	URL      string
	Host     string
	DataURI  string // base64 encoded image
	FilePath string
}

// SubdomainDetail holds aggregated information for a single subdomain
type SubdomainDetail struct {
	Name         string
	IsAlive      bool
	Ports        []int
	Services     []ServiceInfo
	Technologies []string
	Vulns        []VulnInfo
	TakeoverRisk bool
	TakeoverSvc  string
	WAFProtected bool
	WAFName      string
	DirFindings  int
}

// ServiceInfo holds service information for display
type ServiceInfo struct {
	Port       int
	Title      string
	StatusCode int
}

// VulnInfo holds vulnerability information for display
type VulnInfo struct {
	Name     string
	Severity string
	Type     string
}

// aggregateSubdomainDetails builds per-subdomain view from all scan results
func aggregateSubdomainDetails(data *Data) []SubdomainDetail {
	if data.Subdomain == nil || len(data.Subdomain.Subdomains) == 0 {
		return nil
	}

	// Build lookup maps for efficient aggregation
	aliveSet := make(map[string]bool)
	if data.Ports != nil {
		for _, url := range data.Ports.AliveHosts {
			host := extractHost(url)
			aliveSet[host] = true
		}
	}

	portsByHost := make(map[string][]int)
	servicesByHost := make(map[string][]ServiceInfo)
	if data.Ports != nil {
		for host, ports := range data.Ports.OpenPorts {
			portsByHost[host] = ports
		}
		for host, svcs := range data.Ports.Services {
			for _, svc := range svcs {
				servicesByHost[host] = append(servicesByHost[host], ServiceInfo{
					Port:       svc.Port,
					Title:      svc.Title,
					StatusCode: svc.StatusCode,
				})
			}
		}
	}

	techByHost := make(map[string][]string)
	if data.Tech != nil {
		techByHost = data.Tech.TechByHost
	}

	vulnsByHost := make(map[string][]VulnInfo)
	if data.VulnScan != nil {
		for _, v := range data.VulnScan.Vulnerabilities {
			host := extractHost(v.Host)
			vulnsByHost[host] = append(vulnsByHost[host], VulnInfo{
				Name:     v.Name,
				Severity: v.Severity,
				Type:     v.Type,
			})
		}
	}

	takeoverByHost := make(map[string]string)
	if data.Takeover != nil {
		for _, t := range data.Takeover.Vulnerable {
			takeoverByHost[t.Subdomain] = t.Service
		}
	}

	wafByHost := make(map[string]string)
	wafProtected := make(map[string]bool)
	if data.WAF != nil {
		// CDNDetails maps host -> CDN/WAF name
		for host, cdnName := range data.WAF.CDNDetails {
			wafByHost[host] = cdnName
			wafProtected[host] = true
		}
	}

	dirByHost := make(map[string]int)
	if data.DirBrute != nil {
		// ByHost is already map[string]int (count per host)
		dirByHost = data.DirBrute.ByHost
	}

	// Build per-subdomain details
	var details []SubdomainDetail
	for _, sub := range data.Subdomain.Subdomains {
		detail := SubdomainDetail{
			Name:         sub,
			IsAlive:      aliveSet[sub],
			Ports:        portsByHost[sub],
			Services:     servicesByHost[sub],
			Technologies: techByHost[sub],
			Vulns:        vulnsByHost[sub],
			WAFProtected: wafProtected[sub],
			WAFName:      wafByHost[sub],
			DirFindings:  dirByHost[sub],
		}

		if svc, ok := takeoverByHost[sub]; ok {
			detail.TakeoverRisk = true
			detail.TakeoverSvc = svc
		}

		details = append(details, detail)
	}

	// Sort by interest: vulns first, then alive, then alphabetically
	sort.Slice(details, func(i, j int) bool {
		// Takeover risks first
		if details[i].TakeoverRisk != details[j].TakeoverRisk {
			return details[i].TakeoverRisk
		}
		// Then by vulnerability count
		if len(details[i].Vulns) != len(details[j].Vulns) {
			return len(details[i].Vulns) > len(details[j].Vulns)
		}
		// Then by alive status
		if details[i].IsAlive != details[j].IsAlive {
			return details[i].IsAlive
		}
		// Then alphabetically
		return details[i].Name < details[j].Name
	})

	return details
}

// extractHost extracts hostname from URL (strips scheme and port)
func extractHost(urlStr string) string {
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "https://")
	if idx := strings.Index(urlStr, ":"); idx > 0 {
		urlStr = urlStr[:idx]
	}
	if idx := strings.Index(urlStr, "/"); idx > 0 {
		urlStr = urlStr[:idx]
	}
	return urlStr
}

// loadScreenshotImages loads screenshots and embeds them as base64 data URIs
func loadScreenshotImages(data *Data, outputDir string) {
	if data.Screenshot == nil || len(data.Screenshot.Screenshots) == 0 {
		return
	}

	// Limit to first 50 screenshots to avoid huge HTML files
	maxScreenshots := 50
	count := 0

	// Screenshot directory for resolving relative paths
	screenshotDir := filepath.Join(outputDir, "screenshots")

	for _, ss := range data.Screenshot.Screenshots {
		if count >= maxScreenshots {
			break
		}

		// Try the file path as-is first, then try relative to screenshot dir
		filePath := ss.FilePath
		imgData, err := os.ReadFile(filePath)
		if err != nil {
			// Try relative to screenshot directory
			filePath = filepath.Join(screenshotDir, filepath.Base(ss.FilePath))
			imgData, err = os.ReadFile(filePath)
			if err != nil {
				// Try relative to output directory
				filePath = filepath.Join(outputDir, ss.FilePath)
				imgData, err = os.ReadFile(filePath)
				if err != nil {
					continue
				}
			}
		}

		// Determine MIME type from extension
		ext := strings.ToLower(filepath.Ext(ss.FilePath))
		mimeType := "image/png"
		if ext == ".jpg" || ext == ".jpeg" {
			mimeType = "image/jpeg"
		}

		// Create base64 data URI
		b64 := base64.StdEncoding.EncodeToString(imgData)
		dataURI := fmt.Sprintf("data:%s;base64,%s", mimeType, b64)

		data.ScreenshotImages = append(data.ScreenshotImages, ScreenshotImage{
			URL:      ss.URL,
			Host:     ss.Host,
			DataURI:  dataURI,
			FilePath: ss.FilePath,
		})
		count++
	}
}

// Generate generates the HTML report
func Generate(data *Data, outputDir string) error {
	// Aggregate per-subdomain details
	data.SubdomainDetails = aggregateSubdomainDetails(data)

	// Load screenshots as base64 for embedding
	loadScreenshotImages(data, outputDir)

	const tpl = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reconator Report - {{.Target}}</title>
    <style>
        :root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --accent: #3b82f6; --danger: #ef4444; --warning: #f59e0b; --success: #22c55e; }
        body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; line-height: 1.5; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1, h2, h3 { color: white; }
        .header { background: var(--card); padding: 20px; border-radius: 8px; margin-bottom: 20px; border-left: 5px solid var(--accent); }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .card { background: var(--card); padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
        .stat { font-size: 2em; font-weight: bold; color: var(--accent); }
        .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; margin-right: 5px; background: #334155; }
        .tag.critical { background: var(--danger); }
        .tag.high { background: var(--danger); opacity: 0.8; }
        .tag.medium { background: var(--warning); }
        .tag.low { background: var(--accent); }
        .tag.info { background: #6366f1; }
        .tag.alive { background: var(--success); }
        .tag.dead { background: #475569; }
        .tag.waf { background: #8b5cf6; }
        .tag.takeover { background: var(--danger); animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #334155; }
        th { color: #94a3b8; }
        a { color: var(--accent); text-decoration: none; }
        a:hover { text-decoration: underline; }
        .vuln-card { border-left: 4px solid var(--accent); margin-bottom: 10px; padding: 10px; background: #252f45; }
        .vuln-card.critical { border-color: var(--danger); }
        .vuln-card.high { border-color: #fca5a5; }

        /* Per-subdomain styles */
        .subdomain-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 15px; }
        .subdomain-card { background: var(--card); border-radius: 8px; padding: 15px; border-left: 4px solid #334155; transition: all 0.2s; }
        .subdomain-card:hover { transform: translateY(-2px); box-shadow: 0 8px 16px rgba(0,0,0,0.2); }
        .subdomain-card.has-vulns { border-color: var(--danger); }
        .subdomain-card.has-takeover { border-color: var(--danger); background: linear-gradient(135deg, var(--card) 0%, #3f1515 100%); }
        .subdomain-card.alive { border-color: var(--success); }
        .subdomain-card.dead { border-color: #475569; opacity: 0.7; }
        .subdomain-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .subdomain-name { font-weight: bold; font-size: 1.1em; word-break: break-all; }
        .subdomain-badges { display: flex; flex-wrap: wrap; gap: 5px; }
        .subdomain-details { font-size: 0.9em; color: #94a3b8; }
        .subdomain-details p { margin: 5px 0; }
        .subdomain-section { margin-top: 10px; padding-top: 10px; border-top: 1px solid #334155; }
        .subdomain-section h4 { margin: 0 0 8px 0; font-size: 0.85em; color: #64748b; text-transform: uppercase; }
        .port-list { display: flex; flex-wrap: wrap; gap: 5px; }
        .port-badge { background: #334155; padding: 2px 8px; border-radius: 4px; font-size: 0.85em; }
        .tech-list { display: flex; flex-wrap: wrap; gap: 5px; }
        .tech-badge { background: #1e3a5f; padding: 2px 8px; border-radius: 4px; font-size: 0.85em; color: #60a5fa; }
        .vuln-mini { display: flex; align-items: center; gap: 5px; margin: 3px 0; font-size: 0.9em; }

        /* Search and filter */
        .controls { margin-bottom: 20px; display: flex; gap: 15px; flex-wrap: wrap; align-items: center; }
        .search-box { background: var(--card); border: 1px solid #334155; border-radius: 6px; padding: 10px 15px; color: var(--text); font-size: 1em; width: 300px; }
        .search-box:focus { outline: none; border-color: var(--accent); }
        .filter-btn { background: #334155; border: none; border-radius: 6px; padding: 8px 16px; color: var(--text); cursor: pointer; transition: all 0.2s; }
        .filter-btn:hover, .filter-btn.active { background: var(--accent); }
        .count-badge { background: var(--card); padding: 5px 12px; border-radius: 20px; font-size: 0.9em; }

        /* Screenshots gallery */
        .screenshot-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 20px; }
        .screenshot-card { background: var(--card); border-radius: 8px; overflow: hidden; transition: transform 0.2s; }
        .screenshot-card:hover { transform: scale(1.02); }
        .screenshot-img { width: 100%; height: 200px; object-fit: cover; object-position: top; cursor: pointer; }
        .screenshot-info { padding: 12px; }
        .screenshot-url { font-size: 0.85em; color: #94a3b8; word-break: break-all; }
        .screenshot-host { font-weight: bold; margin-bottom: 5px; }

        /* Lightbox for full-size screenshots */
        .lightbox { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.9); z-index: 1000; justify-content: center; align-items: center; }
        .lightbox.active { display: flex; }
        .lightbox img { max-width: 95%; max-height: 95%; object-fit: contain; }
        .lightbox-close { position: absolute; top: 20px; right: 30px; font-size: 40px; color: white; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Reconator Report: {{.Target}}</h1>
            <p>Generated: {{.Date}} | Duration: {{.Duration}} | Version: {{.Version}}</p>
        </div>

        <div class="grid">
            <div class="card">
                <h3>Subdomains</h3>
                <div class="stat">{{if .Subdomain}}{{.Subdomain.TotalAll}}{{else}}0{{end}}</div>
                <p>Found ({{if .Subdomain}}{{.Subdomain.Total}} Validated{{end}})</p>
            </div>
            <div class="card">
                <h3>Live Hosts</h3>
                <div class="stat">{{if .Ports}}{{len .Ports.AliveHosts}}{{else}}0{{end}}</div>
                <p>Ports Open: {{if .Ports}}{{.Ports.TotalPorts}}{{else}}0{{end}}</p>
            </div>
            <div class="card">
                <h3>Vulnerabilities</h3>
                <div class="stat" style="color: var(--danger)">{{if .VulnScan}}{{len .VulnScan.Vulnerabilities}}{{else}}0{{end}}</div>
                <p>High/Critical: {{if .VulnScan}}{{add (index .VulnScan.BySeverity "critical") (index .VulnScan.BySeverity "high")}}{{else}}0{{end}}</p>
            </div>
            <div class="card">
                <h3>Technologies</h3>
                <div class="stat">{{if .Tech}}{{.Tech.Total}}{{else}}0{{end}}</div>
                <p>Unique: {{if .Tech}}{{len .Tech.TechCount}}{{else}}0{{end}}</p>
            </div>
            {{if .WAF}}
            <div class="card">
                <h3>WAF/CDN</h3>
                <div class="stat" style="color: #8b5cf6">{{len .WAF.CDNHosts}}</div>
                <p>Direct: {{len .WAF.DirectHosts}}</p>
            </div>
            {{end}}
        </div>

        {{if .VulnScan}}{{if .VulnScan.Vulnerabilities}}
        <h2 style="color: var(--danger)">Critical & High Vulnerabilities</h2>
        {{range .VulnScan.Vulnerabilities}}
            {{if or (eq .Severity "critical") (eq .Severity "high")}}
            <div class="vuln-card {{.Severity}}">
                <div style="float:right"><span class="tag {{.Severity}}">{{.Severity}}</span></div>
                <h3>{{.Name}}</h3>
                <p><strong>Host:</strong> {{.Host}} | <strong>Type:</strong> {{.Type}}</p>
                {{if .MatcherName}}<p>Matcher: {{.MatcherName}}</p>{{end}}
            </div>
            {{end}}
        {{end}}
        {{end}}{{end}}

        {{if .AIGuided}}{{if .AIGuided.ChainAnalysis}}{{if .AIGuided.ChainAnalysis.Chains}}
        <h2 style="color: var(--warning)">Attack Chains</h2>
        <p style="color: #94a3b8; margin-bottom: 20px;">AI-identified vulnerability chains that could be exploited together</p>
        {{range .AIGuided.ChainAnalysis.Chains}}
        <div class="card" style="border-left: 4px solid {{if eq .Severity "critical"}}var(--danger){{else if eq .Severity "high"}}#fca5a5{{else}}var(--warning){{end}}; margin-bottom: 15px;">
            <h3>{{.Name}} <span class="tag {{.Severity}}">{{.Severity}}</span></h3>
            <p>{{.Description}}</p>
            <p><strong>Impact:</strong> {{.Impact}}</p>
            <p><strong>Likelihood:</strong> {{.Likelihood}}</p>
            <h4>Vulnerabilities in Chain:</h4>
            <ul style="margin: 10px 0;">
            {{range .Vulns}}
                <li><span class="tag {{.Severity}}">{{.Severity}}</span> {{.Name}} ({{.Host}}) - <em>{{.Role}}</em></li>
            {{end}}
            </ul>
            <h4>Exploitation Steps:</h4>
            <ol style="margin: 10px 0; padding-left: 20px;">
            {{range .Steps}}
                <li>{{.}}</li>
            {{end}}
            </ol>
            <h4>Mitigations:</h4>
            <ul style="margin: 10px 0; color: var(--success);">
            {{range .Mitigations}}
                <li>{{.}}</li>
            {{end}}
            </ul>
        </div>
        {{end}}
        {{end}}{{end}}{{end}}

        {{if .AIGuided}}{{if .AIGuided.ChainAnalysis}}{{if .AIGuided.ChainAnalysis.PrioritizedVulns}}
        <h2>Prioritized Vulnerabilities</h2>
        <p style="color: #94a3b8; margin-bottom: 20px;">Vulnerabilities ranked by exploitability and attack chain participation</p>
        <div class="card">
            <table>
                <tr><th>Priority</th><th>Name</th><th>Severity</th><th>Host</th><th>Reasoning</th></tr>
                {{range .AIGuided.ChainAnalysis.PrioritizedVulns}}
                {{if ge .Priority 6}}
                <tr>
                    <td><strong>{{.Priority}}/10</strong></td>
                    <td>{{.Name}}</td>
                    <td><span class="tag {{.Severity}}">{{.Severity}}</span></td>
                    <td>{{.Host}}</td>
                    <td style="font-size: 0.9em; color: #94a3b8;">{{.Reasoning}}</td>
                </tr>
                {{end}}
                {{end}}
            </table>
        </div>
        {{end}}{{end}}{{end}}

        {{if .Takeover}}{{if .Takeover.Vulnerable}}
        <h2 style="color: var(--danger)">Subdomain Takeovers</h2>
        <div class="card">
            <table>
                <tr><th>Subdomain</th><th>Service</th><th>Severity</th></tr>
                {{range .Takeover.Vulnerable}}
                <tr>
                    <td>{{.Subdomain}}</td>
                    <td>{{.Service}}</td>
                    <td><span class="tag high">High</span></td>
                </tr>
                {{end}}
            </table>
        </div>
        {{end}}{{end}}

        {{if .SubdomainDetails}}
        <h2>Per-Subdomain Breakdown</h2>
        <p style="color: #94a3b8; margin-bottom: 15px;">Detailed view of each subdomain with ports, technologies, and vulnerabilities</p>

        <div class="controls">
            <input type="text" class="search-box" placeholder="Search subdomains..." id="subSearch" onkeyup="filterSubdomains()">
            <button class="filter-btn active" onclick="setFilter('all')">All</button>
            <button class="filter-btn" onclick="setFilter('alive')">Alive</button>
            <button class="filter-btn" onclick="setFilter('vulns')">Has Vulns</button>
            <button class="filter-btn" onclick="setFilter('takeover')">Takeover Risk</button>
            <span class="count-badge" id="countBadge">{{len .SubdomainDetails}} subdomains</span>
        </div>

        <div class="subdomain-grid" id="subdomainGrid">
            {{range .SubdomainDetails}}
            <div class="subdomain-card {{if .TakeoverRisk}}has-takeover{{else if .Vulns}}has-vulns{{else if .IsAlive}}alive{{else}}dead{{end}}"
                 data-name="{{.Name}}"
                 data-alive="{{.IsAlive}}"
                 data-vulns="{{len .Vulns}}"
                 data-takeover="{{.TakeoverRisk}}">
                <div class="subdomain-header">
                    <span class="subdomain-name"><a href="https://{{.Name}}" target="_blank">{{.Name}}</a></span>
                    <div class="subdomain-badges">
                        {{if .TakeoverRisk}}<span class="tag takeover">TAKEOVER</span>{{end}}
                        {{if .IsAlive}}<span class="tag alive">ALIVE</span>{{else}}<span class="tag dead">DOWN</span>{{end}}
                        {{if .WAFProtected}}<span class="tag waf">{{.WAFName}}</span>{{end}}
                    </div>
                </div>

                <div class="subdomain-details">
                    {{if .TakeoverRisk}}
                    <div class="subdomain-section" style="background: rgba(239,68,68,0.1); margin: -5px -10px 10px -10px; padding: 10px; border-radius: 4px;">
                        <h4 style="color: var(--danger);">Takeover Vulnerability</h4>
                        <p style="color: var(--danger);">Service: <strong>{{.TakeoverSvc}}</strong></p>
                    </div>
                    {{end}}

                    {{if .Ports}}
                    <div class="subdomain-section">
                        <h4>Open Ports ({{len .Ports}})</h4>
                        <div class="port-list">
                            {{range .Ports}}<span class="port-badge">{{.}}</span>{{end}}
                        </div>
                    </div>
                    {{end}}

                    {{if .Services}}
                    <div class="subdomain-section">
                        <h4>Services</h4>
                        {{range .Services}}
                        <p>:{{.Port}} - {{if .Title}}{{.Title}}{{else}}Unknown{{end}} {{if .StatusCode}}({{.StatusCode}}){{end}}</p>
                        {{end}}
                    </div>
                    {{end}}

                    {{if .Technologies}}
                    <div class="subdomain-section">
                        <h4>Technologies ({{len .Technologies}})</h4>
                        <div class="tech-list">
                            {{range .Technologies}}<span class="tech-badge">{{.}}</span>{{end}}
                        </div>
                    </div>
                    {{end}}

                    {{if .Vulns}}
                    <div class="subdomain-section">
                        <h4 style="color: var(--danger);">Vulnerabilities ({{len .Vulns}})</h4>
                        {{range .Vulns}}
                        <div class="vuln-mini">
                            <span class="tag {{.Severity}}">{{.Severity}}</span>
                            <span>{{.Name}}</span>
                        </div>
                        {{end}}
                    </div>
                    {{end}}

                    {{if .DirFindings}}
                    <div class="subdomain-section">
                        <h4>Directory Findings</h4>
                        <p>{{.DirFindings}} interesting paths discovered</p>
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
        </div>
        {{end}}

        {{if .ScreenshotImages}}
        <h2>Screenshots Gallery</h2>
        <p style="color: #94a3b8; margin-bottom: 15px;">Visual overview of discovered web applications ({{len .ScreenshotImages}} captured)</p>

        <div class="screenshot-grid">
            {{range .ScreenshotImages}}
            <div class="screenshot-card">
                <img class="screenshot-img" src="{{.DataURI}}" alt="{{.Host}}" onclick="openLightbox(this.src)">
                <div class="screenshot-info">
                    <div class="screenshot-host">{{.Host}}</div>
                    <div class="screenshot-url"><a href="{{.URL}}" target="_blank">{{.URL}}</a></div>
                </div>
            </div>
            {{end}}
        </div>
        {{end}}

        <!-- Lightbox for full-size screenshots -->
        <div class="lightbox" id="lightbox" onclick="closeLightbox()">
            <span class="lightbox-close">&times;</span>
            <img id="lightbox-img" src="" alt="Full screenshot">
        </div>

        <footer style="margin-top: 50px; text-align: center; color: #64748b;">
            <p>Generated by Reconator v{{.Version}}</p>
        </footer>
    </div>

    <script>
        let currentFilter = 'all';

        function openLightbox(src) {
            document.getElementById('lightbox-img').src = src;
            document.getElementById('lightbox').classList.add('active');
        }

        function closeLightbox() {
            document.getElementById('lightbox').classList.remove('active');
        }

        function setFilter(filter) {
            currentFilter = filter;
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            filterSubdomains();
        }

        function filterSubdomains() {
            const search = document.getElementById('subSearch').value.toLowerCase();
            const cards = document.querySelectorAll('.subdomain-card');
            let visible = 0;

            cards.forEach(card => {
                const name = card.dataset.name.toLowerCase();
                const alive = card.dataset.alive === 'true';
                const hasVulns = parseInt(card.dataset.vulns) > 0;
                const hasTakeover = card.dataset.takeover === 'true';

                let show = name.includes(search);

                if (show && currentFilter !== 'all') {
                    switch(currentFilter) {
                        case 'alive': show = alive; break;
                        case 'vulns': show = hasVulns; break;
                        case 'takeover': show = hasTakeover; break;
                    }
                }

                card.style.display = show ? 'block' : 'none';
                if (show) visible++;
            });

            document.getElementById('countBadge').textContent = visible + ' subdomains';
        }
    </script>
</body>
</html>
`

	// Helper functions for template
	funcMap := template.FuncMap{
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"ge":  func(a, b int) bool { return a >= b },
	}

	t, err := template.New("report").Funcs(funcMap).Parse(tpl)
	if err != nil {
		return err
	}

	f, err := os.Create(filepath.Join(outputDir, fmt.Sprintf("report_%s.html", data.Target)))
	if err != nil {
		return err
	}
	defer f.Close()

	return t.Execute(f, data)
}
