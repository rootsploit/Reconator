package iprotate

// IPRotateConfig holds configuration for IP rotation via AWS API Gateway
type IPRotateConfig struct {
	Enabled    bool     `yaml:"enabled" json:"enabled"`
	Regions    []string `yaml:"regions" json:"regions"`       // AWS regions for API Gateways
	TargetURL  string   `yaml:"target_url" json:"target_url"` // Base URL to proxy through
	ProxyPort  int      `yaml:"proxy_port" json:"proxy_port"` // Local proxy listen port
	MaxRetries int      `yaml:"max_retries" json:"max_retries"`
}

// GatewayInfo holds info about a deployed API Gateway
type GatewayInfo struct {
	APIID    string `json:"api_id"`
	Region   string `json:"region"`
	Endpoint string `json:"endpoint"` // https://{api-id}.execute-api.{region}.amazonaws.com/proxy
}

// DefaultIPRotateConfig returns sane defaults for IP rotation
func DefaultIPRotateConfig() *IPRotateConfig {
	return &IPRotateConfig{
		Enabled:    false,
		ProxyPort:  8888,
		MaxRetries: 3,
		Regions: []string{
			"us-east-1",
			"us-east-2",
			"us-west-1",
			"us-west-2",
			"eu-west-1",
			"eu-west-2",
			"eu-central-1",
			"ap-southeast-1",
			"ap-northeast-1",
			"ap-south-1",
		},
	}
}
