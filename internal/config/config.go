// Package config layers detour settings: flag > env > file > default.
package config

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	// DefaultCanary is an RFC 6761 .invalid name, non-resolving by construction.
	DefaultCanary = "canary.invalid"

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
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
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
