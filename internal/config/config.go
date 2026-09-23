// Package config layers detour settings: flag > env > file > default.
package config

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	// DefaultCanary is an RFC 6761 .invalid name, non-resolving by construction.
	// It remains the fallback for the deprecated --canary flag.
	DefaultCanary = "canary.invalid"

	// DefaultRedirectTo is where payloads try to send the target.
	//
	// A redirect that arrives here is the finding, so this host is never
	// contacted: the scope guard refuses it, and detour reads the Location
	// rather than following it. google.com is the default because it is what a
	// triager expects to see in a proof of concept.
	DefaultRedirectTo = "https://google.com"

	// EnvPrefix namespaces environment variables as DETOUR_*.
	EnvPrefix = "DETOUR"

	defaultLogLevel    = "info"
	defaultRate        = 5.0
	defaultConcurrency = 10
	defaultTimeout     = 10 * time.Second
)

// Config is the resolved runtime configuration.
type Config struct {
	ConfigFile  string        `mapstructure:"config"`
	LogLevel    string        `mapstructure:"log-level"`
	ScopeFile   string        `mapstructure:"scope-file"`
	Canary      string        `mapstructure:"canary"`
	RedirectTo  string        `mapstructure:"redirect-to"`
	Proxy       string        `mapstructure:"proxy"`
	Headers     []string      `mapstructure:"header"`
	Cookie      string        `mapstructure:"cookie"`
	CookiesFile string        `mapstructure:"cookies-file"`
	Rate        float64       `mapstructure:"rate"`
	Concurrency int           `mapstructure:"concurrency"`
	Delay       time.Duration `mapstructure:"delay"`
	Timeout     time.Duration `mapstructure:"timeout"`
}

// NewViper returns an isolated viper with defaults, env prefix, and key replacer.
func NewViper() *viper.Viper {
	v := viper.New()
	SetDefaults(v)
	v.SetEnvPrefix(EnvPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.AutomaticEnv()

	return v
}

// SetDefaults writes the safe-by-default values onto v.
func SetDefaults(v *viper.Viper) {
	v.SetDefault("log-level", defaultLogLevel)
	v.SetDefault("canary", DefaultCanary)
	v.SetDefault("redirect-to", DefaultRedirectTo)
	v.SetDefault("rate", defaultRate)
	v.SetDefault("concurrency", defaultConcurrency)
	v.SetDefault("timeout", defaultTimeout)
	v.SetDefault("delay", time.Duration(0))
}

// LoadFile reads an optional YAML config. A missing file is not an error.
func LoadFile(v *viper.Viper, cfgFile string) error {
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("finding home directory: %w", err)
		}

		v.AddConfigPath(home)
		v.AddConfigPath(".")
		v.SetConfigName(".detour")
		v.SetConfigType("yaml")
	}

	if err := v.ReadInConfig(); err != nil {
		// A missing config file is the normal case: every setting has a
		// default and flags and env override anyway.
		if _, missing := errors.AsType[viper.ConfigFileNotFoundError](err); !missing {
			return fmt.Errorf("reading config: %w", err)
		}
	}

	return nil
}

// Unmarshal maps the resolved viper tree into Config.
func Unmarshal(v *viper.Viper) (Config, error) {
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("unmarshaling config: %w", err)
	}

	if cfg.Canary == "" {
		cfg.Canary = DefaultCanary
	}

	if cfg.RedirectTo == "" {
		cfg.RedirectTo = DefaultRedirectTo
	}

	if _, err := cfg.destination(); err != nil {
		return Config{}, err
	}

	if cfg.Concurrency <= 0 {
		cfg.Concurrency = defaultConcurrency
	}

	if cfg.Rate <= 0 {
		cfg.Rate = defaultRate
	}

	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}

	if cfg.Headers == nil {
		cfg.Headers = []string{}
	}

	return cfg, nil
}

// ParseHeaders turns "Key: Value" flag entries into a header map.
func ParseHeaders(raw []string) (http.Header, error) {
	headers := make(http.Header, len(raw))

	for _, item := range raw {
		name, value, ok := strings.Cut(item, ":")
		if !ok || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("invalid header %q: expected Name: Value", item)
		}

		headers.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}

	return headers, nil
}

// Destination is the host payloads try to reach, and therefore the host a
// finding is proved against and the host the scope guard refuses.
//
// --redirect-to accepts either a URL or a bare host, because both are natural
// to type and a proof of concept is usually written as a URL. --canary is the
// older name for the same thing and is honoured when it was set explicitly.
func (c Config) Destination() string {
	host, err := c.destination()
	if err != nil {
		return DefaultCanary
	}

	return host
}

// destination resolves the configured value, reporting why it is unusable.
//
// A bad value cannot be allowed to fall back quietly. An empty destination
// switches the scope guard off for every host at once and makes detection a
// no-op, and a value like "google.com/path" leaves the real destination
// unprotected, so both are refused at startup instead.
func (c Config) destination() (string, error) {
	raw := c.RedirectTo
	if c.canarySet() {
		raw = c.Canary
	}

	return hostOnly(raw)
}

// canarySet reports whether the deprecated flag carries an explicit value.
func (c Config) canarySet() bool {
	return c.Canary != "" && c.Canary != DefaultCanary
}

// hostOnly reduces a URL or a bare host to a hostname, and refuses anything
// that is not one.
func hostOnly(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errors.New("redirect destination is empty")
	}

	// A bare host or a host with a path has no scheme for url.Parse to find,
	// and without one it reads "google.com/path" as a path and "host:8443" as
	// a scheme. The scope guard already does this; the two must agree.
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parsing redirect destination %q: %w", raw, err)
	}

	host := strings.ToLower(strings.Trim(parsed.Hostname(), "."))
	if host == "" {
		return "", fmt.Errorf("redirect destination %q has no host", raw)
	}

	if !strings.Contains(host, ".") && host != "localhost" {
		return "", fmt.Errorf("redirect destination %q is not a hostname", raw)
	}

	return host, nil
}
