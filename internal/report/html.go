package report

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"github.com/rootsploit/reconator/internal/aiguided"
	"github.com/rootsploit/reconator/internal/dirbrute"
	"github.com/rootsploit/reconator/internal/historic"
	"github.com/rootsploit/reconator/internal/iprange"
	"github.com/rootsploit/reconator/internal/portscan"
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
	Subdomain *subdomain.Result
	WAF       *waf.Result
	Ports     *portscan.Result
	Takeover  *takeover.Result
	Historic  *historic.Result
	Tech      *techdetect.Result
	DirBrute  *dirbrute.Result
	VulnScan  *vulnscan.Result
	AIGuided  *aiguided.Result
	IPRange   *iprange.Result
	OSINT     interface{} // Generic because osint package import might cause cycles if not careful, but osint is leaf so it should be fine.
	// Actually report is leaf, runner calls it. So we can import osint.
}

// Generate generates the HTML report
func Generate(data *Data, outputDir string) error {
	// Simple CSS/HTML Template
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
        .container { max-width: 1200px; margin: 0 auto; }
        h1, h2, h3 { color: white; }
        .header { background: var(--card); padding: 20px; border-radius: 8px; margin-bottom: 20px; border-left: 5px solid var(--accent); }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .card { background: var(--card); padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
        .stat { font-size: 2em; font-weight: bold; color: var(--accent); }
        .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; margin-right: 5px; background: #334155; }
        .tag.critical { background: var(--danger); }
        .tag.high { background: var(--danger); opacity: 0.8; }
        .tag.medium { background: var(--warning); }
        .tag.low { background: var(--accent); }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #334155; }
        th { color: #94a3b8; }
        a { color: var(--accent); text-decoration: none; }
        a:hover { text-decoration: underline; }
        .vuln-card { border-left: 4px solid var(--accent); margin-bottom: 10px; padding: 10px; background: #252f45; }
        .vuln-card.critical { border-color: var(--danger); }
        .vuln-card.high { border-color: #fca5a5; }
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
                <div class="stat">{{if .Ports}}{{.Ports.TotalAlive}}{{else}}0{{end}}</div>
                <p>Ports Open: {{if .Ports}}{{.Ports.TotalPorts}}{{else}}0{{end}}</p>
            </div>
            <div class="card">
                <h3>Vulnerabilities</h3>
                <div class="stat" style="color: var(--danger)">{{if .VulnScan}}{{.VulnScan.Total}}{{else}}0{{end}}</div>
                <p>High/Critical: {{if .VulnScan}}{{add .VulnScan.BySeverity.critical .VulnScan.BySeverity.high}}{{else}}0{{end}}</p>
            </div>
             <div class="card">
                <h3>Technologies</h3>
                <div class="stat">{{if .Tech}}{{.Tech.Total}}{{else}}0{{end}}</div>
                <p>Frameworks detected</p>
            </div>
        </div>

        {{if .VulnScan}}
        <h2 style="color: var(--danger)">⚠️ Critical & High Vulnerabilities</h2>
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
        {{end}}

        {{if .Takeover}}
        {{if .Takeover.Vulnerable}}
        <h2 style="color: var(--warning)">🚩 Subdomain Takeovers</h2>
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
        {{end}}
        {{end}}

        {{if .Subdomain}}
        <h2>🌐 Subdomains</h2>
        <div class="card" style="max-height: 400px; overflow-y: auto;">
            <table>
                <tr><th>Domain</th><th>Sources</th></tr>
                {{range $i, $sub := .Subdomain.Subdomains}}
                {{if lt $i 100}}
                <tr><td><a href="https://{{$sub}}" target="_blank">{{$sub}}</a></td><td>-</td></tr>
                {{end}}
                {{end}}
                {{if gt (len .Subdomain.Subdomains) 100}}
                <tr><td colspan="2">...and {{sub (len .Subdomain.Subdomains) 100}} more</td></tr>
                {{end}}
            </table>
        </div>
        {{end}}
        
        <footer style="margin-top: 50px; text-align: center; color: #64748b;">
            <p>Generated by Reconator v{{.Version}}</p>
        </footer>
    </div>
</body>
</html>
`

	// Helper functions for template
	funcMap := template.FuncMap{
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
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
