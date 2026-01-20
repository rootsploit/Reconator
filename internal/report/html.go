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

	// Screenshot clusters for gallery view
	ScreenshotClusters []ScreenshotCluster

	// Technology summary for visualization
	TechSummary []TechCount
}

// ScreenshotImage holds a screenshot with embedded base64 data
type ScreenshotImage struct {
	URL       string
	Host      string
	DataURI   template.URL // base64 encoded image (template.URL to prevent escaping)
	FilePath  string
	ClusterID string
}

// ScreenshotCluster groups screenshots by visual similarity
type ScreenshotCluster struct {
	ID          string
	Name        string
	Count       int
	Screenshots []ScreenshotImage
}

// TechCount for technology visualization
type TechCount struct {
	Name  string
	Count int
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
	IPAddress    string
	StatusCode   int
	// Enhanced fields for richer display
	ASN          string // ASN info (e.g., "AS13335, Cloudflare")
	WebServer    string // Web server header (e.g., "nginx", "cloudflare")
	SSLIssuer    string // SSL certificate issuer
	SSLDaysLeft  int    // Days until SSL cert expiry
	SSLExpired   bool   // True if SSL cert is expired
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
	ipByHost := make(map[string]string)
	asnByHost := make(map[string]string)
	webServerByHost := make(map[string]string)
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
				// Capture IP, ASN, WebServer from first service with data
				if svc.IP != "" && ipByHost[host] == "" {
					ipByHost[host] = svc.IP
				}
				if svc.ASN != "" && asnByHost[host] == "" {
					asnByHost[host] = svc.ASN
				}
				if svc.WebServer != "" && webServerByHost[host] == "" {
					webServerByHost[host] = svc.WebServer
				}
			}
		}
	}

	// Extract SSL/TLS info
	sslIssuerByHost := make(map[string]string)
	sslDaysByHost := make(map[string]int)
	sslExpiredByHost := make(map[string]bool)
	if data.Ports != nil && data.Ports.TLSInfo != nil {
		for host, tls := range data.Ports.TLSInfo {
			sslIssuerByHost[host] = tls.Issuer
			sslDaysByHost[host] = tls.DaysLeft
			sslExpiredByHost[host] = tls.DaysLeft < 0
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
			// Enhanced fields
			IPAddress:   ipByHost[sub],
			ASN:         asnByHost[sub],
			WebServer:   webServerByHost[sub],
			SSLIssuer:   sslIssuerByHost[sub],
			SSLDaysLeft: sslDaysByHost[sub],
			SSLExpired:  sslExpiredByHost[sub],
		}

		// Get status code from first service
		if len(detail.Services) > 0 {
			detail.StatusCode = detail.Services[0].StatusCode
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

	// Build cluster lookup
	clusterLookup := make(map[string]string) // filepath -> cluster_id
	clusterNames := make(map[string]string)  // cluster_id -> cluster_name
	if data.Screenshot != nil {
		for _, cluster := range data.Screenshot.Clusters {
			clusterNames[cluster.ID] = cluster.Name
			for _, fp := range cluster.Screenshots {
				clusterLookup[fp] = cluster.ID
			}
		}
	}

	// Limit to first 100 screenshots to avoid huge HTML files
	maxScreenshots := 100
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

		clusterID := clusterLookup[ss.FilePath]

		data.ScreenshotImages = append(data.ScreenshotImages, ScreenshotImage{
			URL:       ss.URL,
			Host:      ss.Host,
			DataURI:   template.URL(dataURI),
			FilePath:  ss.FilePath,
			ClusterID: clusterID,
		})
		count++
	}

	// Build screenshot clusters for gallery view
	clusterMap := make(map[string]*ScreenshotCluster)
	for _, img := range data.ScreenshotImages {
		clusterID := img.ClusterID
		if clusterID == "" {
			clusterID = "unclustered"
		}
		if _, ok := clusterMap[clusterID]; !ok {
			name := clusterNames[clusterID]
			if name == "" {
				name = "Other Screenshots"
			}
			clusterMap[clusterID] = &ScreenshotCluster{
				ID:          clusterID,
				Name:        name,
				Screenshots: []ScreenshotImage{},
			}
		}
		clusterMap[clusterID].Screenshots = append(clusterMap[clusterID].Screenshots, img)
		clusterMap[clusterID].Count++
	}

	// Convert to slice and sort by count
	for _, cluster := range clusterMap {
		data.ScreenshotClusters = append(data.ScreenshotClusters, *cluster)
	}
	sort.Slice(data.ScreenshotClusters, func(i, j int) bool {
		return data.ScreenshotClusters[i].Count > data.ScreenshotClusters[j].Count
	})
}

// buildTechSummary creates technology count summary for visualization
func buildTechSummary(data *Data) []TechCount {
	if data.Tech == nil || data.Tech.TechCount == nil {
		return nil
	}

	var summary []TechCount
	for name, count := range data.Tech.TechCount {
		summary = append(summary, TechCount{Name: name, Count: count})
	}

	// Sort by count descending
	sort.Slice(summary, func(i, j int) bool {
		return summary[i].Count > summary[j].Count
	})

	// Limit to top 20
	if len(summary) > 20 {
		summary = summary[:20]
	}

	return summary
}

// Generate generates the HTML report
func Generate(data *Data, outputDir string) error {
	// Aggregate per-subdomain details
	data.SubdomainDetails = aggregateSubdomainDetails(data)

	// Load screenshots as base64 for embedding
	loadScreenshotImages(data, outputDir)

	// Build tech summary
	data.TechSummary = buildTechSummary(data)

	const tpl = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reconator - {{.Target}}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: #1a1a24;
            --bg-hover: #22222e;
            --border: #2a2a3a;
            --text-primary: #f4f4f5;
            --text-secondary: #a1a1aa;
            --text-muted: #71717a;
            --accent: #6366f1;
            --accent-hover: #818cf8;
            --critical: #dc2626;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #8b5cf6;
            --success: #22c55e;
            --warning: #f59e0b;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }

        /* Layout */
        .app {
            display: flex;
            min-height: 100vh;
        }

        /* Sidebar */
        .sidebar {
            width: 260px;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border);
            padding: 20px 0;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
            z-index: 100;
        }

        .sidebar-header {
            padding: 0 20px 20px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 20px;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--text-primary);
        }

        .logo-icon {
            width: 36px;
            height: 36px;
            background: linear-gradient(135deg, var(--accent) 0%, #a855f7 100%);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
        }

        .target-badge {
            margin-top: 12px;
            padding: 8px 12px;
            background: var(--bg-card);
            border-radius: 6px;
            font-size: 0.875rem;
            color: var(--text-secondary);
            word-break: break-all;
        }

        .nav-section {
            margin-bottom: 8px;
        }

        .nav-section-title {
            padding: 8px 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 0.05em;
        }

        .nav-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 20px;
            color: var(--text-secondary);
            text-decoration: none;
            transition: all 0.15s;
            cursor: pointer;
            border-left: 3px solid transparent;
        }

        .nav-item:hover, .nav-item.active {
            background: var(--bg-hover);
            color: var(--text-primary);
            border-left-color: var(--accent);
        }

        .nav-item .icon { font-size: 1.1rem; width: 24px; text-align: center; }
        .nav-item .badge {
            margin-left: auto;
            padding: 2px 8px;
            background: var(--bg-card);
            border-radius: 10px;
            font-size: 0.75rem;
            font-weight: 500;
        }
        .nav-item .badge.critical { background: var(--critical); color: white; }
        .nav-item .badge.warning { background: var(--warning); color: black; }

        /* Main Content */
        .main {
            flex: 1;
            margin-left: 260px;
            padding: 24px 32px;
            max-width: calc(100% - 260px);
        }

        /* Sections */
        .section {
            display: none;
            animation: fadeIn 0.3s ease;
        }

        .section.active { display: block; }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .section-header {
            margin-bottom: 24px;
        }

        .section-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 4px;
        }

        .section-subtitle {
            color: var(--text-secondary);
            font-size: 0.875rem;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            transition: all 0.2s;
        }

        .stat-card:hover {
            border-color: var(--accent);
            transform: translateY(-2px);
        }

        .stat-card .label {
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .stat-card .value {
            font-size: 2rem;
            font-weight: 700;
            line-height: 1;
        }

        .stat-card .subtext {
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-top: 8px;
        }

        .stat-card.critical .value { color: var(--critical); }
        .stat-card.warning .value { color: var(--warning); }
        .stat-card.success .value { color: var(--success); }
        .stat-card.accent .value { color: var(--accent); }

        /* Cards */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-bottom: 24px;
            overflow: hidden;
        }

        .card-header {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-weight: 600;
        }

        .card-title {
            font-size: 1rem;
            font-weight: 600;
        }

        .card-body { padding: 20px; }

        /* Tags/Badges */
        .tag {
            display: inline-flex;
            align-items: center;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 500;
            gap: 4px;
        }

        .tag.critical, .badge.critical { background: rgba(220, 38, 38, 0.2); color: #fca5a5; border: 1px solid rgba(220, 38, 38, 0.3); }
        .tag.high, .badge.high { background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.3); }
        .tag.medium, .badge.medium { background: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid rgba(234, 179, 8, 0.3); }
        .tag.low, .badge.low { background: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.3); }
        .tag.info, .badge.info { background: rgba(139, 92, 246, 0.2); color: #c4b5fd; border: 1px solid rgba(139, 92, 246, 0.3); }
        .tag.success, .badge.success { background: rgba(34, 197, 94, 0.2); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.3); }
        .tag.waf, .badge.waf { background: rgba(168, 85, 247, 0.2); color: #d8b4fe; border: 1px solid rgba(168, 85, 247, 0.3); }
        .tag.tech, .badge.tech { background: rgba(99, 102, 241, 0.15); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.2); }
        .tag.takeover, .badge.takeover { background: rgba(220, 38, 38, 0.3); color: #fca5a5; border: 1px solid rgba(220, 38, 38, 0.5); }

        .badge {
            display: inline-flex;
            align-items: center;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        /* Severity Breakdown */
        .severity-breakdown {
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
        }

        .severity-item {
            flex: 1;
            min-width: 120px;
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 16px;
            transition: all 0.2s;
            border: 1px solid var(--border);
        }

        .severity-item:hover {
            transform: translateY(-2px);
            border-color: var(--accent);
        }

        .severity-item.critical .severity-count { color: var(--critical); }
        .severity-item.high .severity-count { color: var(--high); }
        .severity-item.medium .severity-count { color: var(--medium); }
        .severity-item.low .severity-count { color: var(--low); }
        .severity-item.info .severity-count { color: var(--info); }

        .severity-count {
            font-size: 2rem;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 4px;
        }

        .severity-label {
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }

        .severity-bar {
            height: 4px;
            background: var(--bg-card);
            border-radius: 2px;
            overflow: hidden;
        }

        .severity-bar-fill {
            height: 100%;
            border-radius: 2px;
            transition: width 0.5s ease;
        }

        .severity-bar-fill.critical { background: var(--critical); }
        .severity-bar-fill.high { background: var(--high); }
        .severity-bar-fill.medium { background: var(--medium); }
        .severity-bar-fill.low { background: var(--low); }
        .severity-bar-fill.info { background: var(--info); }

        /* Nessus-inspired Scan Phases UI */
        .scan-phases {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .scan-phase {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            background: var(--bg-secondary);
            border-radius: 8px;
            border-left: 3px solid transparent;
            transition: all 0.2s;
        }

        .scan-phase:hover {
            background: var(--bg-hover);
        }

        .scan-phase.completed {
            border-left-color: var(--success);
        }

        .scan-phase.skipped {
            border-left-color: var(--text-muted);
            opacity: 0.7;
        }

        .scan-phase.warning {
            border-left-color: var(--warning);
        }

        .scan-phase.critical {
            border-left-color: var(--critical);
        }

        .phase-icon {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            flex-shrink: 0;
        }

        .phase-icon.completed {
            background: rgba(34, 197, 94, 0.2);
            color: var(--success);
        }

        .phase-icon.skipped {
            background: rgba(113, 113, 122, 0.2);
            color: var(--text-muted);
        }

        .phase-icon.warning {
            background: rgba(245, 158, 11, 0.2);
            color: var(--warning);
        }

        .phase-icon.critical {
            background: rgba(220, 38, 38, 0.2);
            color: var(--critical);
        }

        .phase-info {
            flex: 1;
            min-width: 0;
        }

        .phase-name {
            font-weight: 500;
            font-size: 0.875rem;
            color: var(--text-primary);
            margin-bottom: 2px;
        }

        .phase-details {
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        .phase-stats {
            display: flex;
            gap: 12px;
            flex-shrink: 0;
        }

        .phase-stat {
            text-align: right;
        }

        .phase-stat-value {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text-primary);
            line-height: 1;
        }

        .phase-stat-label {
            font-size: 0.65rem;
            color: var(--text-muted);
            text-transform: uppercase;
        }

        .phase-stat-value.critical { color: var(--critical); }
        .phase-stat-value.warning { color: var(--warning); }
        .phase-stat-value.success { color: var(--success); }

        /* Tables */
        .data-table {
            width: 100%;
            border-collapse: collapse;
        }

        .data-table th {
            text-align: left;
            padding: 12px 16px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            color: var(--text-muted);
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
        }

        .data-table td {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            font-size: 0.875rem;
        }

        .data-table tr:hover td {
            background: var(--bg-hover);
        }

        .data-table a {
            color: var(--accent);
            text-decoration: none;
        }

        .data-table a:hover { text-decoration: underline; }

        /* Search & Filters */
        .controls {
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            align-items: center;
        }

        .search-input {
            flex: 1;
            min-width: 200px;
            max-width: 300px;
            padding: 10px 16px;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 0.875rem;
        }

        .search-input:focus {
            outline: none;
            border-color: var(--accent);
        }

        .filter-group {
            display: flex;
            gap: 4px;
            background: var(--bg-secondary);
            padding: 4px;
            border-radius: 8px;
            flex-wrap: wrap;
        }

        .filter-btn {
            padding: 6px 12px;
            background: transparent;
            border: none;
            border-radius: 6px;
            color: var(--text-secondary);
            font-size: 0.75rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.15s;
            white-space: nowrap;
        }

        .filter-btn:hover { color: var(--text-primary); }
        .filter-btn.active {
            background: var(--accent);
            color: white;
        }

        .count-display {
            padding: 8px 16px;
            background: var(--bg-secondary);
            border-radius: 8px;
            font-size: 0.875rem;
            color: var(--text-secondary);
        }

        /* Dropdown Filter */
        .filter-dropdown {
            position: relative;
        }

        .filter-dropdown select {
            padding: 8px 32px 8px 12px;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text-primary);
            font-size: 0.8rem;
            cursor: pointer;
            appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23a1a1aa' d='M3 4.5L6 7.5L9 4.5'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 10px center;
        }

        .filter-dropdown select:focus {
            outline: none;
            border-color: var(--accent);
        }

        /* Asset List View */
        .asset-list {
            display: flex;
            flex-direction: column;
            gap: 1px;
            background: var(--border);
            border-radius: 12px;
            overflow: hidden;
        }

        .asset-row {
            display: flex;
            align-items: stretch;
            background: var(--bg-card);
            transition: background 0.15s;
            min-height: 100px;
        }

        .asset-row:hover {
            background: var(--bg-hover);
        }

        .asset-row.has-vuln { border-left: 3px solid var(--critical); }
        .asset-row.has-takeover { border-left: 3px solid var(--critical); background: linear-gradient(90deg, rgba(220, 38, 38, 0.15) 0%, var(--bg-card) 30%); }
        .asset-row.alive { /* no border for alive rows */ }
        .asset-row.dead { opacity: 0.5; }

        .asset-content {
            flex: 1;
            padding: 16px 20px;
            min-width: 0;
        }

        .asset-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 8px;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--text-muted);
            flex-shrink: 0;
        }
        .status-dot.alive { background: var(--success); }
        .status-dot.dead { background: var(--text-muted); }
        .status-dot.vuln { background: var(--critical); }
        .status-dot.takeover { background: var(--critical); animation: pulse 2s infinite; }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .asset-name {
            font-weight: 600;
            font-size: 0.95rem;
            color: var(--text-primary);
            text-decoration: none;
        }

        .asset-name:hover { color: var(--accent); }

        .asset-badges {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-left: auto;
        }

        .asset-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            font-size: 0.8rem;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }

        .meta-item {
            display: flex;
            align-items: center;
            gap: 4px;
        }

        .meta-label {
            color: var(--text-muted);
        }

        .tech-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-top: 8px;
        }

        .tech-tag {
            padding: 3px 8px;
            background: rgba(99, 102, 241, 0.15);
            border: 1px solid rgba(99, 102, 241, 0.2);
            border-radius: 4px;
            font-size: 0.7rem;
            color: #a5b4fc;
        }

        .port-badge {
            padding: 2px 6px;
            background: var(--bg-secondary);
            border-radius: 4px;
            font-size: 0.7rem;
            font-family: monospace;
            color: var(--text-secondary);
        }

        /* Screenshot Thumbnail on Right */
        .asset-screenshot {
            width: 180px;
            flex-shrink: 0;
            background: var(--bg-secondary);
            display: flex;
            align-items: center;
            justify-content: center;
            border-left: 1px solid var(--border);
            overflow: hidden;
        }

        .asset-screenshot a {
            display: block;
            width: 100%;
            height: 100%;
        }

        .asset-screenshot img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            object-position: top left;
            cursor: pointer;
            transition: opacity 0.2s;
        }

        .asset-screenshot img:hover { opacity: 0.8; }

        .asset-screenshot .no-screenshot {
            font-size: 0.7rem;
            color: var(--text-muted);
            text-align: center;
            padding: 10px;
        }

        /* Screenshot Gallery */
        .gallery-controls {
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }

        .view-toggle {
            display: flex;
            gap: 4px;
            background: var(--bg-secondary);
            padding: 4px;
            border-radius: 8px;
        }

        .view-btn {
            padding: 8px 14px;
            background: transparent;
            border: none;
            border-radius: 6px;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.15s;
        }

        .view-btn:hover { color: var(--text-primary); }
        .view-btn.active {
            background: var(--accent);
            color: white;
        }

        .screenshot-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 16px;
        }

        .screenshot-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            transition: all 0.2s;
        }

        .screenshot-card:hover {
            border-color: var(--accent);
            transform: translateY(-2px);
        }

        .screenshot-img {
            width: 100%;
            height: 180px;
            object-fit: cover;
            object-position: top;
            cursor: pointer;
            background: var(--bg-secondary);
        }

        .screenshot-info {
            padding: 12px 16px;
        }

        .screenshot-host {
            font-weight: 600;
            font-size: 0.9rem;
            margin-bottom: 4px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .screenshot-url {
            font-size: 0.75rem;
            color: var(--text-muted);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .screenshot-url a {
            color: var(--text-muted);
            text-decoration: none;
        }

        .screenshot-url a:hover { color: var(--accent); }

        /* Cluster View */
        .cluster-section {
            margin-bottom: 32px;
        }

        .cluster-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
        }

        .cluster-name {
            font-size: 1.1rem;
            font-weight: 600;
        }

        .cluster-count {
            padding: 4px 10px;
            background: var(--bg-secondary);
            border-radius: 12px;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }

        /* Vulnerability Cards */
        .vuln-item {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px 18px;
            margin-bottom: 10px;
            border-left: 4px solid var(--border);
        }

        .vuln-item.critical { border-left-color: var(--critical); }
        .vuln-item.high { border-left-color: var(--high); }
        .vuln-item.medium { border-left-color: var(--medium); }
        .vuln-item.low { border-left-color: var(--low); }

        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }

        .vuln-name {
            font-weight: 600;
            font-size: 0.95rem;
        }

        .vuln-meta {
            display: flex;
            gap: 16px;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }

        .vuln-meta a { color: var(--accent); text-decoration: none; }
        .vuln-meta a:hover { text-decoration: underline; }

        /* Tech Chart */
        .tech-chart {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .tech-item { margin-bottom: 4px; }

        .tech-row {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 6px 8px;
            border-radius: 6px;
            transition: background 0.15s;
        }

        .tech-row:hover { background: var(--bg-hover); }
        .tech-row.expanded { background: var(--bg-hover); }

        .expand-icon {
            font-size: 0.7rem;
            color: var(--text-muted);
            transition: transform 0.2s;
            width: 12px;
        }

        .tech-row.expanded .expand-icon { transform: rotate(90deg); }

        .tech-assets {
            margin: 8px 0 16px 24px;
            padding: 12px;
            background: var(--bg-secondary);
            border-radius: 8px;
            border-left: 2px solid var(--accent);
        }

        .tech-asset-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 8px 12px;
            background: var(--bg-card);
            border-radius: 6px;
            margin-bottom: 6px;
            font-size: 0.85rem;
        }

        .tech-asset-item:last-child { margin-bottom: 0; }
        .tech-asset-item a { color: var(--text-primary); text-decoration: none; }
        .tech-asset-item a:hover { color: var(--accent); }
        .tech-asset-item .status-dot { width: 6px; height: 6px; }

        .tech-name {
            width: 140px;
            font-size: 0.85rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            color: var(--text-secondary);
        }

        .tech-bar-bg {
            flex: 1;
            height: 8px;
            background: var(--bg-secondary);
            border-radius: 4px;
            overflow: hidden;
        }

        .tech-bar-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--accent) 0%, #a855f7 100%);
            border-radius: 4px;
            transition: width 0.3s ease;
        }

        .tech-count {
            width: 40px;
            text-align: right;
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        /* Attack Chain Cards */
        .chain-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
        }

        .chain-card.critical { border-left: 4px solid var(--critical); }
        .chain-card.high { border-left: 4px solid var(--high); }

        .chain-title { font-size: 1.1rem; font-weight: 600; }

        .chain-desc {
            color: var(--text-secondary);
            margin-bottom: 16px;
            font-size: 0.9rem;
        }

        .chain-section { margin-bottom: 16px; }

        .chain-section-title {
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-bottom: 8px;
        }

        .chain-vulns {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .chain-vuln-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 8px 12px;
            background: var(--bg-secondary);
            border-radius: 6px;
            font-size: 0.85rem;
        }

        .chain-steps {
            list-style: none;
            counter-reset: steps;
        }

        .chain-steps li {
            counter-increment: steps;
            padding: 8px 0 8px 36px;
            position: relative;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }

        .chain-steps li::before {
            content: counter(steps);
            position: absolute;
            left: 0;
            width: 24px;
            height: 24px;
            background: var(--accent);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: 600;
            color: white;
        }

        .mitigation-list {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .mitigation-item {
            display: flex;
            align-items: flex-start;
            gap: 8px;
            font-size: 0.85rem;
            color: var(--success);
        }

        .mitigation-item::before {
            content: "✓";
            font-weight: bold;
        }

        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-secondary);
        }

        .empty-state .icon {
            font-size: 48px;
            margin-bottom: 16px;
            opacity: 0.5;
        }

        /* Footer */
        .footer {
            margin-top: 60px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            text-align: center;
            color: var(--text-muted);
            font-size: 0.8rem;
        }

        /* Responsive */
        @media (max-width: 1024px) {
            .sidebar { width: 60px; padding: 10px 0; }
            .sidebar-header { padding: 0 10px 10px; }
            .logo span, .target-badge, .nav-section-title, .nav-item span:not(.icon), .nav-item .badge { display: none; }
            .nav-item { justify-content: center; padding: 12px 0; }
            .nav-item .icon { width: auto; font-size: 1.3rem; }
            .main { margin-left: 60px; max-width: calc(100% - 60px); padding: 16px; }
            .asset-screenshot { width: 120px; }
            .screenshot-grid { grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); }
        }

        @media (max-width: 768px) {
            .asset-screenshot { display: none; }
            .controls { flex-direction: column; align-items: stretch; }
            .filter-group { justify-content: center; }
        }
    </style>
</head>
<body>
    <div class="app">
        <!-- Sidebar -->
        <aside class="sidebar">
            <div class="sidebar-header">
                <div class="logo">
                    <span>Reconator</span>
                </div>
                <div class="target-badge">{{.Target}}</div>
            </div>

            <nav>
                <div class="nav-section">
                    <div class="nav-section-title">Overview</div>
                    <a class="nav-item active" onclick="showSection('dashboard')">
                        <span class="icon">📊</span>
                        <span>Dashboard</span>
                    </a>
                </div>

                <div class="nav-section">
                    <div class="nav-section-title">Assets</div>
                    <a class="nav-item" onclick="showSection('assets')">
                        <span class="icon">🌐</span>
                        <span>Subdomains</span>
                        <span class="badge">{{if .SubdomainDetails}}{{len .SubdomainDetails}}{{else}}0{{end}}</span>
                    </a>
                    {{if .ScreenshotImages}}
                    <a class="nav-item" onclick="showSection('screenshots')">
                        <span class="icon">📸</span>
                        <span>Screenshots</span>
                        <span class="badge">{{len .ScreenshotImages}}</span>
                    </a>
                    {{end}}
                </div>

                <div class="nav-section">
                    <div class="nav-section-title">Security</div>
                    {{if .VulnScan}}{{if .VulnScan.Vulnerabilities}}
                    <a class="nav-item" onclick="showSection('vulnerabilities')">
                        <span class="icon">🔓</span>
                        <span>Vulnerabilities</span>
                        <span class="badge critical">{{len .VulnScan.Vulnerabilities}}</span>
                    </a>
                    {{end}}{{end}}
                    {{if .Takeover}}{{if .Takeover.Vulnerable}}
                    <a class="nav-item" onclick="showSection('takeovers')">
                        <span class="icon">⚠️</span>
                        <span>Takeovers</span>
                        <span class="badge critical">{{len .Takeover.Vulnerable}}</span>
                    </a>
                    {{end}}{{end}}
                    {{if .AIGuided}}{{if .AIGuided.ChainAnalysis}}{{if .AIGuided.ChainAnalysis.Chains}}
                    <a class="nav-item" onclick="showSection('chains')">
                        <span class="icon">🔗</span>
                        <span>Attack Chains</span>
                        <span class="badge">{{len .AIGuided.ChainAnalysis.Chains}}</span>
                    </a>
                    {{end}}{{end}}{{end}}
                </div>

                {{if .Tech}}
                <div class="nav-section">
                    <div class="nav-section-title">Intelligence</div>
                    <a class="nav-item" onclick="showSection('technologies')">
                        <span class="icon">🔧</span>
                        <span>Technologies</span>
                        <span class="badge">{{len .Tech.TechCount}}</span>
                    </a>
                </div>
                {{end}}
            </nav>
        </aside>

        <!-- Main Content -->
        <main class="main">
            <!-- Dashboard -->
            <section class="section active" id="dashboard">
                <div class="section-header">
                    <h1 class="section-title">Attack Surface Overview</h1>
                    <p class="section-subtitle">Scan completed on {{.Date}} · Duration: {{.Duration}}</p>
                </div>

                <div class="stats-grid">
                    <div class="stat-card accent" onclick="navigateToSection('assets')" style="cursor: pointer;">
                        <div class="label">🌐 Subdomains</div>
                        <div class="value">{{if .Subdomain}}{{.Subdomain.TotalAll}}{{else}}0{{end}}</div>
                        <div class="subtext">{{if .Subdomain}}{{.Subdomain.Total}} validated{{end}}</div>
                    </div>
                    <div class="stat-card success" onclick="navigateToSectionWithFilter('assets', 'alive')" style="cursor: pointer;">
                        <div class="label">✓ Live Hosts</div>
                        <div class="value">{{if .Ports}}{{len .Ports.AliveHosts}}{{else}}0{{end}}</div>
                        <div class="subtext">{{if .Ports}}{{.Ports.TotalPorts}} open ports{{end}}</div>
                    </div>
                    <div class="stat-card critical" onclick="navigateToSection('vulnerabilities')" style="cursor: pointer;">
                        <div class="label">🔓 Vulnerabilities</div>
                        <div class="value">{{if .VulnScan}}{{len .VulnScan.Vulnerabilities}}{{else}}0{{end}}</div>
                        <div class="subtext">{{if .VulnScan}}{{add (index .VulnScan.BySeverity "critical") (index .VulnScan.BySeverity "high")}} critical/high{{end}}</div>
                    </div>
                    <div class="stat-card warning" onclick="navigateToSectionWithFilter('assets', 'takeover')" style="cursor: pointer;">
                        <div class="label">⚠️ Takeovers</div>
                        <div class="value">{{if .Takeover}}{{len .Takeover.Vulnerable}}{{else}}0{{end}}</div>
                        <div class="subtext">subdomain takeover risks</div>
                    </div>
                    <div class="stat-card" onclick="navigateToSection('technologies')" style="cursor: pointer;">
                        <div class="label">🔧 Technologies</div>
                        <div class="value">{{if .Tech}}{{len .Tech.TechCount}}{{else}}0{{end}}</div>
                        <div class="subtext">{{if .Tech}}{{.Tech.Total}} detections{{end}}</div>
                    </div>
                    {{if .WAF}}
                    <div class="stat-card" onclick="navigateToSectionWithFilter('assets', 'waf')" style="cursor: pointer;">
                        <div class="label">🛡️ WAF/CDN</div>
                        <div class="value">{{len .WAF.CDNHosts}}</div>
                        <div class="subtext">{{len .WAF.DirectHosts}} direct access</div>
                    </div>
                    {{end}}
                </div>

                {{if .VulnScan}}{{if .VulnScan.Vulnerabilities}}
                <div class="card" style="margin-bottom: 20px;">
                    <div class="card-header">
                        <span class="card-title">Vulnerability Severity Breakdown</span>
                        <span class="badge" style="background: var(--bg-secondary);">{{len .VulnScan.Vulnerabilities}} Total</span>
                    </div>
                    <div class="card-body">
                        <div class="severity-breakdown">
                            <div class="severity-item critical" onclick="navigateToSectionWithVulnFilter('critical')" style="cursor: pointer;">
                                <div class="severity-count">{{index .VulnScan.BySeverity "critical"}}</div>
                                <div class="severity-label">Critical</div>
                                <div class="severity-bar">
                                    <div class="severity-bar-fill critical" style="width: {{if gt (len .VulnScan.Vulnerabilities) 0}}{{percent (index .VulnScan.BySeverity "critical") (len .VulnScan.Vulnerabilities)}}{{else}}0{{end}}%"></div>
                                </div>
                            </div>
                            <div class="severity-item high" onclick="navigateToSectionWithVulnFilter('high')" style="cursor: pointer;">
                                <div class="severity-count">{{index .VulnScan.BySeverity "high"}}</div>
                                <div class="severity-label">High</div>
                                <div class="severity-bar">
                                    <div class="severity-bar-fill high" style="width: {{if gt (len .VulnScan.Vulnerabilities) 0}}{{percent (index .VulnScan.BySeverity "high") (len .VulnScan.Vulnerabilities)}}{{else}}0{{end}}%"></div>
                                </div>
                            </div>
                            <div class="severity-item medium" onclick="navigateToSectionWithVulnFilter('medium')" style="cursor: pointer;">
                                <div class="severity-count">{{index .VulnScan.BySeverity "medium"}}</div>
                                <div class="severity-label">Medium</div>
                                <div class="severity-bar">
                                    <div class="severity-bar-fill medium" style="width: {{if gt (len .VulnScan.Vulnerabilities) 0}}{{percent (index .VulnScan.BySeverity "medium") (len .VulnScan.Vulnerabilities)}}{{else}}0{{end}}%"></div>
                                </div>
                            </div>
                            <div class="severity-item low" onclick="navigateToSectionWithVulnFilter('low')" style="cursor: pointer;">
                                <div class="severity-count">{{index .VulnScan.BySeverity "low"}}</div>
                                <div class="severity-label">Low</div>
                                <div class="severity-bar">
                                    <div class="severity-bar-fill low" style="width: {{if gt (len .VulnScan.Vulnerabilities) 0}}{{percent (index .VulnScan.BySeverity "low") (len .VulnScan.Vulnerabilities)}}{{else}}0{{end}}%"></div>
                                </div>
                            </div>
                            <div class="severity-item info" onclick="navigateToSectionWithVulnFilter('info')" style="cursor: pointer;">
                                <div class="severity-count">{{index .VulnScan.BySeverity "info"}}</div>
                                <div class="severity-label">Info</div>
                                <div class="severity-bar">
                                    <div class="severity-bar-fill info" style="width: {{if gt (len .VulnScan.Vulnerabilities) 0}}{{percent (index .VulnScan.BySeverity "info") (len .VulnScan.Vulnerabilities)}}{{else}}0{{end}}%"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                {{end}}{{end}}

                <!-- Nessus-inspired Scan Phases Summary -->
                <div class="card" style="margin-bottom: 20px;">
                    <div class="card-header">
                        <span class="card-title">Scan Phases Summary</span>
                        <span class="badge" style="background: var(--bg-secondary);">{{.Duration}}</span>
                    </div>
                    <div class="card-body">
                        <div class="scan-phases">
                            <!-- Phase 1: Subdomain Enumeration -->
                            {{if .Subdomain}}
                            <div class="scan-phase completed" onclick="navigateToSection('assets')" style="cursor: pointer;">
                                <div class="phase-icon completed">✓</div>
                                <div class="phase-info">
                                    <div class="phase-name">Subdomain Enumeration</div>
                                    <div class="phase-details">DNS records, certificate transparency, web archives</div>
                                </div>
                                <div class="phase-stats">
                                    <div class="phase-stat">
                                        <div class="phase-stat-value">{{.Subdomain.TotalAll}}</div>
                                        <div class="phase-stat-label">Found</div>
                                    </div>
                                    <div class="phase-stat">
                                        <div class="phase-stat-value success">{{.Subdomain.Total}}</div>
                                        <div class="phase-stat-label">Valid</div>
                                    </div>
                                </div>
                            </div>
                            {{else}}
                            <div class="scan-phase skipped">
                                <div class="phase-icon skipped">—</div>
                                <div class="phase-info">
                                    <div class="phase-name">Subdomain Enumeration</div>
                                    <div class="phase-details">Skipped</div>
                                </div>
                            </div>
                            {{end}}

                            <!-- Phase 2: WAF Detection -->
                            {{if .WAF}}
                            <div class="scan-phase completed">
                                <div class="phase-icon completed">✓</div>
                                <div class="phase-info">
                                    <div class="phase-name">WAF/CDN Detection</div>
                                    <div class="phase-details">Identified CDN-protected and direct-access hosts</div>
                                </div>
                                <div class="phase-stats">
                                    <div class="phase-stat">
                                        <div class="phase-stat-value">{{len .WAF.CDNHosts}}</div>
                                        <div class="phase-stat-label">CDN</div>
                                    </div>
                                    <div class="phase-stat">
                                        <div class="phase-stat-value success">{{len .WAF.DirectHosts}}</div>
                                        <div class="phase-stat-label">Direct</div>
                                    </div>
                                </div>
                            </div>
                            {{end}}

                            <!-- Phase 3: Port Scanning -->
                            {{if .Ports}}
                            <div class="scan-phase completed" onclick="navigateToSection('assets')" style="cursor: pointer;">
                                <div class="phase-icon completed">✓</div>
                                <div class="phase-info">
                                    <div class="phase-name">Port Scanning & TLS Analysis</div>
                                    <div class="phase-details">Open ports, service detection, SSL/TLS inspection</div>
                                </div>
                                <div class="phase-stats">
                                    <div class="phase-stat">
                                        <div class="phase-stat-value">{{.Ports.TotalPorts}}</div>
                                        <div class="phase-stat-label">Ports</div>
                                    </div>
                                    <div class="phase-stat">
                                        <div class="phase-stat-value success">{{len .Ports.AliveHosts}}</div>
                                        <div class="phase-stat-label">Live</div>
                                    </div>
                                </div>
                            </div>
                            {{end}}

                            <!-- Phase 4: Takeover Check -->
                            {{if .Takeover}}
                            <div class="scan-phase {{if .Takeover.Vulnerable}}critical{{else}}completed{{end}}">
                                <div class="phase-icon {{if .Takeover.Vulnerable}}critical{{else}}completed{{end}}">{{if .Takeover.Vulnerable}}!{{else}}✓{{end}}</div>
                                <div class="phase-info">
                                    <div class="phase-name">Subdomain Takeover Analysis</div>
                                    <div class="phase-details">Dangling DNS records, orphaned cloud resources</div>
                                </div>
                                <div class="phase-stats">
                                    {{if .Takeover.Vulnerable}}
                                    <div class="phase-stat">
                                        <div class="phase-stat-value critical">{{len .Takeover.Vulnerable}}</div>
                                        <div class="phase-stat-label">Vulnerable</div>
                                    </div>
                                    {{else}}
                                    <div class="phase-stat">
                                        <div class="phase-stat-value success">0</div>
                                        <div class="phase-stat-label">Issues</div>
                                    </div>
                                    {{end}}
                                </div>
                            </div>
                            {{end}}

                            <!-- Phase 5: Technology Detection -->
                            {{if .Tech}}
                            <div class="scan-phase completed" onclick="navigateToSection('technologies')" style="cursor: pointer;">
                                <div class="phase-icon completed">✓</div>
                                <div class="phase-info">
                                    <div class="phase-name">Technology Detection</div>
                                    <div class="phase-details">Frameworks, CMS, servers, libraries</div>
                                </div>
                                <div class="phase-stats">
                                    <div class="phase-stat">
                                        <div class="phase-stat-value">{{len .Tech.TechCount}}</div>
                                        <div class="phase-stat-label">Technologies</div>
                                    </div>
                                    <div class="phase-stat">
                                        <div class="phase-stat-value">{{.Tech.Total}}</div>
                                        <div class="phase-stat-label">Detections</div>
                                    </div>
                                </div>
                            </div>
                            {{end}}

                            <!-- Phase 6: Vulnerability Scanning -->
                            {{if .VulnScan}}
                            <div class="scan-phase {{if gt (add (index .VulnScan.BySeverity "critical") (index .VulnScan.BySeverity "high")) 0}}critical{{else if gt (len .VulnScan.Vulnerabilities) 0}}warning{{else}}completed{{end}}" onclick="navigateToSection('vulnerabilities')" style="cursor: pointer;">
                                <div class="phase-icon {{if gt (add (index .VulnScan.BySeverity "critical") (index .VulnScan.BySeverity "high")) 0}}critical{{else if gt (len .VulnScan.Vulnerabilities) 0}}warning{{else}}completed{{end}}">{{if gt (len .VulnScan.Vulnerabilities) 0}}!{{else}}✓{{end}}</div>
                                <div class="phase-info">
                                    <div class="phase-name">Vulnerability Scanning</div>
                                    <div class="phase-details">Nuclei templates, CVE checks, misconfigurations</div>
                                </div>
                                <div class="phase-stats">
                                    <div class="phase-stat">
                                        <div class="phase-stat-value {{if gt (index .VulnScan.BySeverity "critical") 0}}critical{{end}}">{{index .VulnScan.BySeverity "critical"}}</div>
                                        <div class="phase-stat-label">Critical</div>
                                    </div>
                                    <div class="phase-stat">
                                        <div class="phase-stat-value {{if gt (index .VulnScan.BySeverity "high") 0}}warning{{end}}">{{index .VulnScan.BySeverity "high"}}</div>
                                        <div class="phase-stat-label">High</div>
                                    </div>
                                    <div class="phase-stat">
                                        <div class="phase-stat-value">{{len .VulnScan.Vulnerabilities}}</div>
                                        <div class="phase-stat-label">Total</div>
                                    </div>
                                </div>
                            </div>
                            {{end}}

                            <!-- Phase 7: Screenshots -->
                            {{if .Screenshot}}{{if not .Screenshot.Skipped}}
                            <div class="scan-phase completed" onclick="navigateToSection('screenshots')" style="cursor: pointer;">
                                <div class="phase-icon completed">✓</div>
                                <div class="phase-info">
                                    <div class="phase-name">Visual Reconnaissance</div>
                                    <div class="phase-details">Screenshot capture and clustering</div>
                                </div>
                                <div class="phase-stats">
                                    <div class="phase-stat">
                                        <div class="phase-stat-value">{{.Screenshot.TotalCaptures}}</div>
                                        <div class="phase-stat-label">Captures</div>
                                    </div>
                                    {{if .Screenshot.Clusters}}
                                    <div class="phase-stat">
                                        <div class="phase-stat-value">{{len .Screenshot.Clusters}}</div>
                                        <div class="phase-stat-label">Clusters</div>
                                    </div>
                                    {{end}}
                                </div>
                            </div>
                            {{end}}{{end}}

                            <!-- Phase 8: AI-Guided Scanning -->
                            {{if .AIGuided}}
                            <div class="scan-phase {{if gt (len .AIGuided.Vulnerabilities) 0}}warning{{else}}completed{{end}}">
                                <div class="phase-icon {{if gt (len .AIGuided.Vulnerabilities) 0}}warning{{else}}completed{{end}}">{{if gt (len .AIGuided.Vulnerabilities) 0}}!{{else}}✓{{end}}</div>
                                <div class="phase-info">
                                    <div class="phase-name">AI-Guided Analysis</div>
                                    <div class="phase-details">{{.AIGuided.AIProvider}} · Smart vulnerability correlation</div>
                                </div>
                                <div class="phase-stats">
                                    <div class="phase-stat">
                                        <div class="phase-stat-value">{{len .AIGuided.Vulnerabilities}}</div>
                                        <div class="phase-stat-label">Findings</div>
                                    </div>
                                    {{if .AIGuided.ChainAnalysis}}{{if .AIGuided.ChainAnalysis.Chains}}
                                    <div class="phase-stat">
                                        <div class="phase-stat-value warning">{{len .AIGuided.ChainAnalysis.Chains}}</div>
                                        <div class="phase-stat-label">Chains</div>
                                    </div>
                                    {{end}}{{end}}
                                </div>
                            </div>
                            {{end}}
                        </div>
                    </div>
                </div>

                {{if .AIGuided}}{{if .AIGuided.ExecutiveSummary}}
                <div class="card" style="margin-bottom: 20px;">
                    <div class="card-header">
                        <span class="card-title">AI Security Analysis</span>
                        {{if .AIGuided.AIProvider}}<span class="badge info">{{.AIGuided.AIProvider}}</span>{{end}}
                    </div>
                    <div class="card-body">
                        <div style="margin-bottom: 16px;">
                            <p style="font-size: 1rem; color: var(--text-primary); line-height: 1.6; margin: 0;">{{.AIGuided.ExecutiveSummary.OneLiner}}</p>
                        </div>
                        {{if .AIGuided.ExecutiveSummary.KeyFindings}}
                        <div style="margin-bottom: 16px;">
                            <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-secondary); margin-bottom: 8px;">Key Findings</div>
                            <ul style="margin: 0; padding-left: 20px; color: var(--text-secondary); font-size: 0.875rem; line-height: 1.7;">
                                {{range .AIGuided.ExecutiveSummary.KeyFindings}}<li>{{.}}</li>{{end}}
                            </ul>
                        </div>
                        {{end}}
                        {{if .AIGuided.ExecutiveSummary.ImmediateActions}}
                        <div style="margin-bottom: 16px;">
                            <div style="font-size: 0.85rem; font-weight: 600; color: var(--critical); margin-bottom: 8px;">Immediate Actions Required</div>
                            <ul style="margin: 0; padding-left: 20px; color: var(--text-secondary); font-size: 0.875rem; line-height: 1.7;">
                                {{range .AIGuided.ExecutiveSummary.ImmediateActions}}<li style="color: var(--critical);">{{.}}</li>{{end}}
                            </ul>
                        </div>
                        {{end}}
                        {{if .AIGuided.ExecutiveSummary.RiskAssessment}}
                        <div style="padding: 12px 16px; background: var(--bg-secondary); border-radius: 8px; border-left: 3px solid var(--accent);">
                            <div style="font-size: 0.75rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">Risk Assessment</div>
                            <p style="margin: 0; color: var(--text-primary); font-size: 0.875rem;">{{.AIGuided.ExecutiveSummary.RiskAssessment}}</p>
                        </div>
                        {{end}}
                    </div>
                </div>
                {{end}}{{end}}

                {{if .TechSummary}}
                <div class="card">
                    <div class="card-header">Technology Distribution</div>
                    <div class="card-body">
                        <div class="tech-chart">
                            {{$maxCount := 1}}
                            {{range .TechSummary}}{{if gt .Count $maxCount}}{{$maxCount = .Count}}{{end}}{{end}}
                            {{range .TechSummary}}
                            <div class="tech-row" onclick="filterByTech('{{.Name}}')" style="cursor: pointer;">
                                <span class="tech-name" title="{{.Name}}">{{.Name}}</span>
                                <div class="tech-bar-bg">
                                    <div class="tech-bar-fill" style="width: {{percent .Count $maxCount}}%"></div>
                                </div>
                                <span class="tech-count">{{.Count}}</span>
                            </div>
                            {{end}}
                        </div>
                    </div>
                </div>
                {{end}}

                {{if .AIGuided}}{{if .AIGuided.ChainAnalysis}}{{if .AIGuided.ChainAnalysis.Chains}}
                <div class="card">
                    <div class="card-header">Critical Attack Chains</div>
                    <div class="card-body">
                        {{range $i, $chain := .AIGuided.ChainAnalysis.Chains}}
                        {{if lt $i 3}}
                        <div class="chain-card {{$chain.Severity}}" style="margin-bottom: 16px;">
                            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                                <span class="chain-title">{{$chain.Name}}</span>
                                <span class="badge {{$chain.Severity}}">{{$chain.Severity}}</span>
                            </div>
                            <p class="chain-desc">{{$chain.Description}}</p>
                            <div class="chain-section" style="margin-bottom: 0;">
                                <div class="chain-section-title">Impact</div>
                                <p style="font-size: 13px; color: var(--text-secondary);">{{$chain.Impact}}</p>
                            </div>
                        </div>
                        {{end}}
                        {{end}}
                    </div>
                </div>
                {{end}}{{end}}{{end}}
            </section>

            <!-- Assets Section - List View -->
            <section class="section" id="assets">
                <div class="section-header">
                    <h1 class="section-title">Subdomains</h1>
                    <p class="section-subtitle">{{if .SubdomainDetails}}{{len .SubdomainDetails}}{{else}}0{{end}} discovered assets</p>
                </div>

                {{if .SubdomainDetails}}
                <div class="controls">
                    <input type="text" class="search-input" placeholder="Search subdomains..." id="assetSearch" onkeyup="filterAssets()">
                    <div class="filter-group">
                        <button class="filter-btn active" onclick="setAssetFilter('all', this)">All</button>
                        <button class="filter-btn" onclick="setAssetFilter('alive', this)">Live</button>
                        <button class="filter-btn" onclick="setAssetFilter('vulns', this)">Vulnerable</button>
                        <button class="filter-btn" onclick="setAssetFilter('takeover', this)">Takeover</button>
                        <button class="filter-btn" onclick="setAssetFilter('waf', this)">WAF</button>
                    </div>
                    <div class="filter-dropdown">
                        <select id="techFilter" onchange="filterAssets()">
                            <option value="">All Technologies</option>
                            {{range .TechSummary}}<option value="{{.Name}}">{{.Name}} ({{.Count}})</option>{{end}}
                        </select>
                    </div>
                    <div class="filter-dropdown">
                        <select id="portFilter" onchange="filterAssets()">
                            <option value="">All Ports</option>
                            <option value="80">Port 80</option>
                            <option value="443">Port 443</option>
                            <option value="8080">Port 8080</option>
                            <option value="8443">Port 8443</option>
                            <option value="3000">Port 3000</option>
                            <option value="5000">Port 5000</option>
                        </select>
                    </div>
                    <span class="count-display" id="assetCount">{{len .SubdomainDetails}} results</span>
                </div>

                <div class="asset-list" id="assetList">
                    {{range .SubdomainDetails}}
                    <div class="asset-row {{if .TakeoverRisk}}has-takeover{{else if .Vulns}}has-vuln{{else if .IsAlive}}alive{{else}}dead{{end}}"
                         data-name="{{.Name}}"
                         data-alive="{{.IsAlive}}"
                         data-vulns="{{len .Vulns}}"
                         data-takeover="{{.TakeoverRisk}}"
                         data-waf="{{.WAFProtected}}"
                         data-ports="{{range $i, $p := .Ports}}{{if $i}},{{end}}{{$p}}{{end}}"
                         data-techs="{{range $i, $t := .Technologies}}{{if $i}},{{end}}{{$t}}{{end}}"
                         data-ip="{{.IPAddress}}"
                         data-asn="{{.ASN}}">
                        <div class="asset-content">
                            <div class="asset-header">
                                <span class="status-dot {{if .TakeoverRisk}}takeover{{else if .Vulns}}vuln{{else if .IsAlive}}alive{{else}}dead{{end}}"></span>
                                <a class="asset-name" href="https://{{.Name}}" target="_blank">{{.Name}}{{if .Ports}}:{{index .Ports 0}}{{end}}</a>
                                <div class="asset-badges">
                                    {{if .TakeoverRisk}}<span class="badge takeover">Takeover</span>{{end}}
                                    {{if .Vulns}}<span class="badge critical">{{len .Vulns}} Vulns</span>{{end}}
                                    {{if .WAFProtected}}<span class="badge waf">{{.WAFName}}</span>{{end}}
                                </div>
                            </div>
                            <div class="asset-meta">
                                {{if .StatusCode}}<span class="meta-item"><span class="badge {{if eq .StatusCode 200}}success{{else if lt .StatusCode 400}}info{{else if lt .StatusCode 500}}medium{{else}}critical{{end}}">{{.StatusCode}}</span></span>{{end}}
                                {{if .ASN}}<span class="meta-item"><span class="badge info">{{.ASN}}</span></span>{{end}}
                                {{if .IPAddress}}<span class="meta-item"><span class="badge tech">{{.IPAddress}}</span></span>{{end}}
                                {{if .Ports}}{{if gt (len .Ports) 1}}<span class="meta-item"><span class="badge info">+{{sub (len .Ports) 1}}</span></span>{{end}}{{end}}
                            </div>
                            <div class="asset-meta" style="margin-top: 6px;">
                                {{if .SSLIssuer}}<span class="meta-item">{{if .SSLExpired}}<span class="badge critical">SSL Expired</span>{{else if and .SSLDaysLeft (lt .SSLDaysLeft 30)}}<span class="badge medium">SSL {{.SSLDaysLeft}}d</span>{{else if .SSLDaysLeft}}<span class="badge success">SSL {{.SSLDaysLeft}}d</span>{{end}} <span class="badge tech">{{.SSLIssuer}}</span></span>{{end}}
                                {{if .WebServer}}<span class="meta-item"><span class="badge tech">{{.WebServer}}</span></span>{{end}}
                                {{if .TakeoverRisk}}<span class="meta-item"><span class="badge takeover">{{.TakeoverSvc}}</span></span>{{end}}
                            </div>
                            {{if .Technologies}}
                            <div class="tech-tags">
                                {{range .Technologies}}<span class="tech-tag">{{.}}</span>{{end}}
                            </div>
                            {{end}}
                            {{if .Vulns}}
                            <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border);">
                                {{range .Vulns}}
                                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px; font-size: 0.75rem;">
                                    <span class="badge {{.Severity}}">{{.Severity}}</span>
                                    <span style="color: var(--text-secondary);">{{.Name}}</span>
                                </div>
                                {{end}}
                            </div>
                            {{end}}
                        </div>
                        <div class="asset-screenshot" data-host="{{.Name}}">
                            <span class="no-screenshot">No screenshot</span>
                        </div>
                    </div>
                    {{end}}
                </div>
                {{else}}
                <div class="empty-state">
                    <div class="icon">🔍</div>
                    <p>No subdomains discovered</p>
                </div>
                {{end}}
            </section>

            <!-- Screenshots Section -->
            {{if .ScreenshotImages}}
            <section class="section" id="screenshots">
                <div class="section-header">
                    <h1 class="section-title">Screenshots</h1>
                    <p class="section-subtitle">{{len .ScreenshotImages}} captured web applications</p>
                </div>

                <div class="controls">
                    <div class="filter-group">
                        <button class="filter-btn active" onclick="setGalleryView('grid', this)">Grid</button>
                        <button class="filter-btn" onclick="setGalleryView('cluster', this)">Clusters</button>
                    </div>
                    <input type="text" class="search-input" placeholder="Search hosts..." id="screenshotSearch" onkeyup="filterScreenshots()">
                </div>

                <div id="gridView">
                    <div class="screenshot-grid" id="screenshotGrid">
                        {{range .ScreenshotImages}}
                        <div class="screenshot-card" data-host="{{.Host}}" data-url="{{.URL}}">
                            <a href="{{.DataURI}}" target="_blank">
                                <img class="screenshot-img" src="{{.DataURI}}" alt="{{.Host}}" loading="lazy">
                            </a>
                            <div class="screenshot-info">
                                <div class="screenshot-host">{{.Host}}</div>
                                <div class="screenshot-url"><a href="{{.URL}}" target="_blank">{{.URL}}</a></div>
                            </div>
                        </div>
                        {{end}}
                    </div>
                </div>

                <div id="clusterView" style="display: none;">
                    {{range .ScreenshotClusters}}
                    <div class="cluster-section">
                        <div class="cluster-header">
                            <span class="cluster-name">{{.Name}}</span>
                            <span class="cluster-count">{{.Count}} screenshots</span>
                        </div>
                        <div class="screenshot-grid">
                            {{range .Screenshots}}
                            <div class="screenshot-card" data-host="{{.Host}}" data-url="{{.URL}}">
                                <a href="{{.DataURI}}" target="_blank">
                                    <img class="screenshot-img" src="{{.DataURI}}" alt="{{.Host}}" loading="lazy">
                                </a>
                                <div class="screenshot-info">
                                    <div class="screenshot-host">{{.Host}}</div>
                                    <div class="screenshot-url"><a href="{{.URL}}" target="_blank">{{.URL}}</a></div>
                                </div>
                            </div>
                            {{end}}
                        </div>
                    </div>
                    {{end}}
                </div>
            </section>
            {{end}}

            <!-- Vulnerabilities Section -->
            {{if .VulnScan}}{{if .VulnScan.Vulnerabilities}}
            <section class="section" id="vulnerabilities">
                <div class="section-header">
                    <h1 class="section-title">Vulnerabilities</h1>
                    <p class="section-subtitle">{{len .VulnScan.Vulnerabilities}} security issues identified</p>
                </div>

                <div class="controls">
                    <input type="text" class="search-input" placeholder="Search vulnerabilities..." id="vulnSearch" onkeyup="filterVulns()">
                    <div class="filter-group">
                        <button class="filter-btn active" onclick="setVulnFilter('all', this)">All</button>
                        <button class="filter-btn" onclick="setVulnFilter('critical', this)">Critical</button>
                        <button class="filter-btn" onclick="setVulnFilter('high', this)">High</button>
                        <button class="filter-btn" onclick="setVulnFilter('medium', this)">Medium</button>
                        <button class="filter-btn" onclick="setVulnFilter('low', this)">Low</button>
                    </div>
                </div>

                <div class="vuln-list" id="vulnList">
                    {{range .VulnScan.Vulnerabilities}}
                    <div class="vuln-item {{.Severity}}" data-severity="{{.Severity}}" data-name="{{.Name}}" data-host="{{.Host}}">
                        <div class="vuln-header">
                            <span class="vuln-name">{{.Name}}</span>
                            <span class="badge {{.Severity}}">{{.Severity}}</span>
                        </div>
                        <div class="vuln-meta">
                            <span>Host: <a href="{{.Host}}" target="_blank">{{.Host}}</a></span>
                            <span>Type: {{.Type}}</span>
                            {{if .MatcherName}}<span>Matcher: {{.MatcherName}}</span>{{end}}
                        </div>
                    </div>
                    {{end}}
                </div>
            </section>
            {{end}}{{end}}

            <!-- Takeovers Section -->
            {{if .Takeover}}{{if .Takeover.Vulnerable}}
            <section class="section" id="takeovers">
                <div class="section-header">
                    <h1 class="section-title">Subdomain Takeovers</h1>
                    <p class="section-subtitle">{{len .Takeover.Vulnerable}} vulnerable subdomains</p>
                </div>

                <div class="card">
                    <div class="card-body" style="padding: 0;">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Subdomain</th>
                                    <th>Service</th>
                                    <th>Severity</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{range .Takeover.Vulnerable}}
                                <tr>
                                    <td><a href="https://{{.Subdomain}}" target="_blank">{{.Subdomain}}</a></td>
                                    <td>{{.Service}}</td>
                                    <td><span class="badge critical">Critical</span></td>
                                    <td><span class="badge takeover">Vulnerable</span></td>
                                </tr>
                                {{end}}
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>
            {{end}}{{end}}

            <!-- Attack Chains Section -->
            {{if .AIGuided}}{{if .AIGuided.ChainAnalysis}}{{if .AIGuided.ChainAnalysis.Chains}}
            <section class="section" id="chains">
                <div class="section-header">
                    <h1 class="section-title">Attack Chains</h1>
                    <p class="section-subtitle">AI-identified vulnerability chains</p>
                </div>

                {{range .AIGuided.ChainAnalysis.Chains}}
                <div class="chain-card {{.Severity}}">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
                        <span class="chain-title">{{.Name}}</span>
                        <span class="badge {{.Severity}}">{{.Severity}}</span>
                    </div>
                    <p class="chain-desc">{{.Description}}</p>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 20px;">
                        <div class="chain-section" style="margin-bottom: 0;">
                            <div class="chain-section-title">Impact</div>
                            <p style="font-size: 13px; color: var(--text-secondary);">{{.Impact}}</p>
                        </div>
                        <div class="chain-section" style="margin-bottom: 0;">
                            <div class="chain-section-title">Likelihood</div>
                            <p style="font-size: 13px; color: var(--text-secondary);">{{.Likelihood}}</p>
                        </div>
                    </div>

                    <div class="chain-section">
                        <div class="chain-section-title">Vulnerabilities in Chain</div>
                        <div class="chain-vulns">
                            {{range .Vulns}}
                            <div class="chain-vuln-item">
                                <span class="badge {{.Severity}}">{{.Severity}}</span>
                                <span>{{.Name}}</span>
                                <span style="color: var(--text-muted); margin-left: auto; font-size: 0.8rem;">{{.Host}}</span>
                            </div>
                            {{end}}
                        </div>
                    </div>

                    <div class="chain-section">
                        <div class="chain-section-title">Exploitation Steps</div>
                        <ol class="chain-steps">
                            {{range .Steps}}
                            <li>{{.}}</li>
                            {{end}}
                        </ol>
                    </div>

                    <div class="chain-section" style="margin-bottom: 0;">
                        <div class="chain-section-title">Mitigations</div>
                        <div class="mitigation-list">
                            {{range .Mitigations}}
                            <div class="mitigation-item">{{.}}</div>
                            {{end}}
                        </div>
                    </div>
                </div>
                {{end}}
            </section>
            {{end}}{{end}}{{end}}

            <!-- Technologies Section -->
            {{if .Tech}}
            <section class="section" id="technologies">
                <div class="section-header">
                    <h1 class="section-title">Technologies</h1>
                    <p class="section-subtitle">{{.Tech.Total}} detections across {{len .Tech.TechCount}} technologies</p>
                </div>

                <div class="card">
                    <div class="card-header">Technology Stack</div>
                    <div class="card-body">
                        <div class="tech-chart">
                            {{$maxCount := 1}}
                            {{range .TechSummary}}{{if gt .Count $maxCount}}{{$maxCount = .Count}}{{end}}{{end}}
                            {{range .TechSummary}}
                            <div class="tech-item">
                                <div class="tech-row" onclick="toggleTechAssets('{{.Name}}', this)" style="cursor: pointer;">
                                    <span class="expand-icon">▶</span>
                                    <span class="tech-name" title="{{.Name}}">{{.Name}}</span>
                                    <div class="tech-bar-bg">
                                        <div class="tech-bar-fill" style="width: {{percent .Count $maxCount}}%"></div>
                                    </div>
                                    <span class="tech-count">{{.Count}}</span>
                                </div>
                                <div class="tech-assets" style="display: none;"></div>
                            </div>
                            {{end}}
                        </div>
                    </div>
                </div>
            </section>
            {{end}}

            <footer class="footer">
                Generated by Reconator v{{.Version}} · {{.Date}}
            </footer>
        </main>
    </div>

    <script>
        // Screenshot lookup for asset list
        const screenshotMap = new Map();
        {{range .ScreenshotImages}}
        screenshotMap.set('{{.Host}}', '{{.DataURI}}');
        {{end}}

        // Populate screenshots in asset list (open in new tab on click)
        document.querySelectorAll('.asset-screenshot').forEach(el => {
            const host = el.dataset.host;
            const img = screenshotMap.get(host);
            if (img) {
                el.innerHTML = '<a href="' + img + '" target="_blank"><img src="' + img + '" loading="lazy"></a>';
            }
        });

        // Navigation
        function showSection(id) {
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            document.getElementById(id).classList.add('active');
            event.currentTarget.classList.add('active');
        }

        // Navigate to section from dashboard stat-card
        function navigateToSection(id) {
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            document.getElementById(id).classList.add('active');
            const navItem = document.querySelector('.nav-item[onclick*="' + id + '"]');
            if (navItem) navItem.classList.add('active');
        }

        // Navigate to section and apply filter
        function navigateToSectionWithFilter(section, filter) {
            navigateToSection(section);

            if (section === 'assets') {
                assetFilter = filter;
                document.querySelectorAll('#assets .filter-group .filter-btn').forEach(b => b.classList.remove('active'));
                const filterBtn = document.querySelector('#assets .filter-btn[onclick*="' + filter + '"]');
                if (filterBtn) filterBtn.classList.add('active');
                filterAssets();
            }
        }

        // Navigate to vulnerabilities section with severity filter
        function navigateToSectionWithVulnFilter(severity) {
            navigateToSection('vulnerabilities');
            vulnFilter = severity;
            document.querySelectorAll('#vulnerabilities .filter-group .filter-btn').forEach(b => b.classList.remove('active'));
            const filterBtn = document.querySelector('#vulnerabilities .filter-btn[onclick*="' + severity + '"]');
            if (filterBtn) filterBtn.classList.add('active');
            filterVulns();
        }

        // Asset Filtering
        let assetFilter = 'all';

        function setAssetFilter(filter, btn) {
            assetFilter = filter;
            document.querySelectorAll('#assets .filter-group .filter-btn').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            filterAssets();
        }

        function filterAssets() {
            const search = document.getElementById('assetSearch').value.toLowerCase();
            const techFilter = document.getElementById('techFilter')?.value || '';
            const portFilter = document.getElementById('portFilter')?.value || '';
            const rows = document.querySelectorAll('.asset-row');
            let count = 0;

            rows.forEach(row => {
                const name = row.dataset.name.toLowerCase();
                const alive = row.dataset.alive === 'true';
                const hasVulns = parseInt(row.dataset.vulns) > 0;
                const hasTakeover = row.dataset.takeover === 'true';
                const hasWaf = row.dataset.waf === 'true';
                const ports = row.dataset.ports || '';
                const techs = row.dataset.techs || '';

                let show = name.includes(search);

                // Status filter
                if (show && assetFilter !== 'all') {
                    switch(assetFilter) {
                        case 'alive': show = alive; break;
                        case 'vulns': show = hasVulns; break;
                        case 'takeover': show = hasTakeover; break;
                        case 'waf': show = hasWaf; break;
                    }
                }

                // Technology filter
                if (show && techFilter) {
                    show = techs.toLowerCase().includes(techFilter.toLowerCase());
                }

                // Port filter
                if (show && portFilter) {
                    show = ports.split(',').includes(portFilter);
                }

                row.style.display = show ? 'flex' : 'none';
                if (show) count++;
            });

            document.getElementById('assetCount').textContent = count + ' results';
        }

        // Filter by technology (from dashboard click) - navigates to Technologies tab and expands
        function filterByTech(techName) {
            // Navigate to technologies section
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            document.getElementById('technologies').classList.add('active');
            const navItem = document.querySelector('.nav-item[onclick*="technologies"]');
            if (navItem) navItem.classList.add('active');

            // Find and expand the matching tech row
            setTimeout(() => {
                const techRows = document.querySelectorAll('#technologies .tech-row');
                techRows.forEach(row => {
                    const name = row.querySelector('.tech-name');
                    if (name && name.textContent.toLowerCase().includes(techName.toLowerCase())) {
                        // Collapse any already expanded
                        if (!row.classList.contains('expanded')) {
                            toggleTechAssets(techName, row);
                        }
                        // Scroll into view
                        row.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    }
                });
            }, 100);
        }

        // Toggle tech assets in-place (for Technologies section) - with fingerprint data
        function toggleTechAssets(techName, barElement) {
            const techItem = barElement.closest('.tech-item');
            const assetsPanel = techItem.querySelector('.tech-assets');
            const isExpanded = barElement.classList.contains('expanded');

            if (isExpanded) {
                // Collapse
                barElement.classList.remove('expanded');
                assetsPanel.style.display = 'none';
                assetsPanel.innerHTML = '';
            } else {
                // Expand - find matching assets and display them with fingerprint data
                barElement.classList.add('expanded');

                // Get all assets with this technology
                const rows = document.querySelectorAll('.asset-row');
                let html = '';

                rows.forEach(row => {
                    const techs = (row.dataset.techs || '').toLowerCase();
                    if (techs.includes(techName.toLowerCase())) {
                        const name = row.dataset.name;
                        const alive = row.dataset.alive === 'true';
                        const ip = row.dataset.ip || '';
                        const asn = row.dataset.asn || '';

                        html += '<div class="tech-asset-item" style="flex-wrap: wrap;">' +
                            '<span class="status-dot ' + (alive ? 'alive' : 'dead') + '"></span>' +
                            '<a href="https://' + name + '" target="_blank" style="flex: 1; min-width: 150px;">' + name + '</a>' +
                            '<div style="display: flex; gap: 6px; flex-wrap: wrap;">';

                        if (ip) {
                            html += '<span class="badge tech" style="font-size: 0.65rem;">' + ip + '</span>';
                        }
                        if (asn) {
                            html += '<span class="badge info" style="font-size: 0.65rem;">' + asn + '</span>';
                        }

                        html += '</div></div>';
                    }
                });

                if (html) {
                    assetsPanel.innerHTML = html;
                } else {
                    assetsPanel.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem;">No assets found</div>';
                }
                assetsPanel.style.display = 'block';
            }
        }

        // Vulnerability Filtering
        let vulnFilter = 'all';

        function setVulnFilter(filter, btn) {
            vulnFilter = filter;
            document.querySelectorAll('#vulnerabilities .filter-group .filter-btn').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            filterVulns();
        }

        function filterVulns() {
            const search = document.getElementById('vulnSearch')?.value.toLowerCase() || '';
            document.querySelectorAll('.vuln-item').forEach(item => {
                const name = item.dataset.name.toLowerCase();
                const host = item.dataset.host.toLowerCase();
                const severity = item.dataset.severity;

                let show = name.includes(search) || host.includes(search);
                if (show && vulnFilter !== 'all') show = severity === vulnFilter;

                item.style.display = show ? 'block' : 'none';
            });
        }

        // Screenshot Gallery
        function setGalleryView(view, btn) {
            document.querySelectorAll('#screenshots .filter-group .filter-btn').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById('gridView').style.display = view === 'grid' ? 'block' : 'none';
            document.getElementById('clusterView').style.display = view === 'cluster' ? 'block' : 'none';
        }

        function filterScreenshots() {
            const search = document.getElementById('screenshotSearch').value.toLowerCase();
            document.querySelectorAll('.screenshot-card').forEach(card => {
                const host = card.dataset.host.toLowerCase();
                const url = card.dataset.url.toLowerCase();
                card.style.display = (host.includes(search) || url.includes(search)) ? 'block' : 'none';
            });
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
		"percent": func(value, max int) int {
			if max == 0 {
				return 0
			}
			return (value * 100) / max
		},
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
