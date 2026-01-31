package vulnscan

import "strings"

// SkipCVELookup contains products that should NOT have CVE lookups
// These are typically cloud services, CDNs, or generic terms that cause false positives
// This list is shared between cve_lookup.go and aiguided/scanner.go to ensure consistency
var SkipCVELookup = map[string]bool{
	// AWS services (not software you run - cloud infrastructure)
	"amazon s3":           true,
	"amazon s 3":          true,
	"aws s3":              true,
	"s3":                  true,
	"amazon cloudfront":   true,
	"cloudfront":          true,
	"amazon web services": true,
	"aws":                 true,
	"amazon elb":          true,
	"amazon ec2":          true,
	"amazon rds":          true,
	"amazon lambda":       true,
	"amazon api gateway":  true,

	// Google Cloud services
	"google cloud":         true,
	"google cloud storage": true,
	"gcp":                  true,
	"google cloud cdn":     true,

	// Azure services
	"azure storage": true,
	"azure blob":    true,
	"azure cdn":     true,
	"microsoft azure": true,

	// CDN providers (not software you run)
	"cloudflare":             true,
	"cloudflare bot management": true,
	"akamai":                 true,
	"fastly":                 true,
	"jsdelivr":               true,
	"cdnjs":                  true,
	"unpkg":                  true,
	"vercel":                 true,
	"netlify":                true,
	"datadome":               true,

	// Generic terms that cause FPs
	"cdn":              true,
	"hosted":           true,
	"api":              true,
	"analytics":        true,
	"tracking":         true,
	"fonts":            true,
	"google fonts":     true,
	"adobe fonts":      true,
	"typekit":          true,
	"google analytics": true,
	"google tag manager": true,
	"hubspot":          true,
	"hubspot cms hub":  true,
	"youtube":          true,
	"merge":            true,

	// Protocol/standard names (not products)
	"http/3":  true,
	"http/2":  true,
	"http":    true,
	"https":   true,
	"hsts":    true,
	"tls":     true,
	"ssl":     true,
}

// ShouldSkipCVELookup checks if a product should be skipped for CVE lookups
// It normalizes the product name (lowercase, trim spaces) before checking
func ShouldSkipCVELookup(product string) bool {
	normalized := strings.ToLower(strings.TrimSpace(product))
	return SkipCVELookup[normalized]
}
