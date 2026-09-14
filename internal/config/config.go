// Package config resolves connection settings: flags > env > ~/.config/adgctl/config.yaml.
package config

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	URL      string `yaml:"url"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// PasswordCmd is run and its stdout used as the password, e.g.
	// "security find-generic-password -s adguard -w" on macOS.
	PasswordCmd string `yaml:"password_cmd"`
}

func Path() string {
	if p := os.Getenv("ADGCTL_CONFIG"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(dir, "adgctl", "config.yaml")
}

func Load() (*Config, error) {
	c := &Config{}
	if b, err := os.ReadFile(Path()); err == nil {
		if err := yaml.Unmarshal(b, c); err != nil {
			return nil, err
		}
	}
	if v := os.Getenv("ADG_URL"); v != "" {
		c.URL = v
	}
	if v := os.Getenv("ADG_USER"); v != "" {
		c.Username = v
	}
	if v := os.Getenv("ADG_PASS"); v != "" {
		c.Password = v
	}
	if v := os.Getenv("ADG_PASS_CMD"); v != "" {
		c.PasswordCmd = v
	}
	return c, nil
}

// Resolve fills Password from PasswordCmd when needed and validates.
func (c *Config) Resolve() error {
	if c.Password == "" && c.PasswordCmd != "" {
		out, err := exec.Command("sh", "-c", c.PasswordCmd).Output()
		if err != nil {
			return errors.New("password_cmd failed: " + err.Error())
		}
		c.Password = strings.TrimSpace(string(out))
	}
	switch {
	case c.URL == "":
		return errors.New("no AdGuard URL: set ADG_URL or url in " + Path())
	case c.Username == "":
		return errors.New("no username: set ADG_USER or username in " + Path())
	case c.Password == "":
		return errors.New("no password: set ADG_PASS, ADG_PASS_CMD, or password/password_cmd in " + Path())
	}
	c.URL = strings.TrimRight(c.URL, "/")
	return nil
}

func Save(c *Config) error {
	p := Path()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}
