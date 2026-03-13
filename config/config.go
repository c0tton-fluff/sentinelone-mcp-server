package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	APIKey  string
	APIBase string
}

var cached *Config

func Load() (*Config, error) {
	key := os.Getenv("SENTINELONE_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("SENTINELONE_API_KEY environment variable is required")
	}

	base := os.Getenv("SENTINELONE_API_BASE")
	if base == "" {
		return nil, fmt.Errorf("SENTINELONE_API_BASE environment variable is required")
	}

	u, err := url.ParseRequestURI(base)
	if err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf(
			"SENTINELONE_API_BASE must be an HTTPS URL (e.g., https://usea1.sentinelone.net)",
		)
	}

	cached = &Config{
		APIKey:  key,
		APIBase: strings.TrimRight(base, "/"),
	}
	return cached, nil
}

func Get() *Config {
	if cached == nil {
		panic("config.Load() must be called before config.Get()")
	}
	return cached
}
