package output

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

var (
	dimWhite    = color.New(color.FgWhite, color.Faint)
	boldWhite   = color.New(color.FgWhite, color.Bold)
	tagCyan     = color.New(color.FgCyan)
	sevCritical = color.New(color.FgRed, color.Bold) // Dark red for critical
	sevHigh     = color.New(color.FgRed)             // Red for high
	sevMedium   = color.New(color.FgYellow)          // Orange/Yellow for medium
	sevLow      = color.New(color.FgGreen)           // Green for low
	sevInfo     = color.New(color.FgBlue)            // Blue for info
	urlGreen    = color.New(color.FgGreen)
)

// severityColor returns the color for a given severity level
func severityColor(severity string) *color.Color {
	switch strings.ToLower(severity) {
	case "critical":
		return sevCritical
	case "high":
		return sevHigh
	case "medium":
		return sevMedium
	case "low":
		return sevLow
	default:
		return sevInfo
	}
}

// statusColor returns color for HTTP status codes
func statusColor(code int) *color.Color {
	switch {
	case code >= 200 && code < 300:
		return color.New(color.FgGreen)
	case code >= 300 && code < 400:
		return color.New(color.FgYellow)
	case code >= 400 && code < 500:
		return color.New(color.FgRed)
	case code >= 500:
		return color.New(color.FgRed, color.Bold)
	default:
		return dimWhite
	}
}

// PrintFinding prints a single finding in nuclei-style format:
// [template-id] [severity] target [extra]
func PrintFinding(tag, severity, target, extra string) {
	dimWhite.Print("[")
	tagCyan.Print(tag)
	dimWhite.Print("] [")
	severityColor(severity).Print(severity)
	dimWhite.Print("] ")
	urlGreen.Print(target)
	if extra != "" {
		dimWhite.Print(" [")
		boldWhite.Print(extra)
		dimWhite.Print("]")
	}
	fmt.Println()
}

// PrintSubdomain prints a discovered subdomain:
// sub.example.com [source]
func PrintSubdomain(subdomain, source string) {
	urlGreen.Print(subdomain)
	if source != "" {
		dimWhite.Print(" [")
		tagCyan.Print(source)
		dimWhite.Print("]")
	}
	fmt.Println()
}

// PrintHost prints an httpx-style host result:
// https://target.com [200] [nginx] [Page Title]
func PrintHost(url string, statusCode int, server, title string) {
	urlGreen.Print(url)
	if statusCode > 0 {
		dimWhite.Print(" [")
		statusColor(statusCode).Printf("%d", statusCode)
		dimWhite.Print("]")
	}
	if server != "" {
		dimWhite.Print(" [")
		tagCyan.Print(server)
		dimWhite.Print("]")
	}
	if title != "" {
		dimWhite.Print(" [")
		boldWhite.Print(title)
		dimWhite.Print("]")
	}
	fmt.Println()
}

// PrintOSINT prints an OSINT finding:
// [whois] [info] domain [details]
func PrintOSINT(tag, severity, target, details string) {
	PrintFinding(tag, severity, target, details)
}

// PrintTech prints technology detection:
// [tech] [info] host [tech1, tech2, tech3]
func PrintTech(host string, techs []string) {
	if len(techs) == 0 {
		return
	}
	detail := strings.Join(techs, ", ")
	if len(detail) > 100 {
		detail = detail[:97] + "..."
	}
	PrintFinding("tech", "info", host, detail)
}
