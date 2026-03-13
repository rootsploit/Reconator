package osint

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// hibpBreach represents a HIBP breach response
type hibpBreach struct {
	Name        string   `json:"Name"`
	Title       string   `json:"Title"`
	Domain      string   `json:"Domain"`
	BreachDate  string   `json:"BreachDate"`
	PwnCount    int      `json:"PwnCount"`
	Description string   `json:"Description"`
	DataClasses []string `json:"DataClasses"`
	IsVerified  bool     `json:"IsVerified"`
}

// runBreachCheck checks for known breaches associated with the domain
func (s *Scanner) runBreachCheck(target string) ([]BreachEntry, error) {
	client := &http.Client{Timeout: 15 * time.Second}

	// Try HIBP API (free for domain search, rate-limited)
	req, err := http.NewRequest("GET", fmt.Sprintf("https://haveibeenpwned.com/api/v3/breaches?domain=%s", target), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Reconator-OSINT")

	resp, err := client.Do(req)
	if err != nil {
		// HIBP may be unavailable or rate limited - non-fatal
		return nil, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		// API key required for this endpoint - return empty
		return nil, nil
	}

	if resp.StatusCode != 200 {
		return nil, nil
	}

	var breaches []hibpBreach
	if err := json.NewDecoder(resp.Body).Decode(&breaches); err != nil {
		return nil, nil
	}

	var results []BreachEntry
	for _, b := range breaches {
		results = append(results, BreachEntry{
			Name:        b.Title,
			Domain:      b.Domain,
			BreachDate:  b.BreachDate,
			DataClasses: b.DataClasses,
			RecordCount: b.PwnCount,
			Description: b.Description,
		})
	}

	return results, nil
}
