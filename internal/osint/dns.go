package osint

import (
	"fmt"
	"net"
	"strings"
)

// runDNSRecords collects DNS records for a target domain using Go's net package.
// This includes TXT (SPF, DMARC, DKIM), MX, NS records.
func runDNSRecords(target string) *DNSRecordSet {
	result := &DNSRecordSet{}

	// TXT records for target domain
	txts, _ := net.LookupTXT(target)
	result.TXT = txts

	// Extract SPF from TXT
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=spf1") {
			result.SPF = txt
			break
		}
	}

	// DMARC: lookup _dmarc.target
	dmarcTxts, _ := net.LookupTXT("_dmarc." + target)
	for _, txt := range dmarcTxts {
		if strings.HasPrefix(txt, "v=DMARC1") {
			result.DMARC = txt
			break
		}
	}

	// DKIM: try common selectors
	selectors := []string{"google", "default", "selector1", "selector2", "k1", "k2", "s1", "s2", "dkim", "mail"}
	for _, sel := range selectors {
		dkimTxts, _ := net.LookupTXT(sel + "._domainkey." + target)
		for _, txt := range dkimTxts {
			if strings.Contains(txt, "DKIM1") || strings.Contains(txt, "p=") {
				result.DKIM = append(result.DKIM, sel+": "+txt)
			}
		}
	}

	// MX records
	mxs, _ := net.LookupMX(target)
	for _, mx := range mxs {
		result.MX = append(result.MX, fmt.Sprintf("%s (priority: %d)", strings.TrimSuffix(mx.Host, "."), mx.Pref))
	}

	// NS records
	nss, _ := net.LookupNS(target)
	for _, ns := range nss {
		result.NS = append(result.NS, strings.TrimSuffix(ns.Host, "."))
	}

	return result
}
