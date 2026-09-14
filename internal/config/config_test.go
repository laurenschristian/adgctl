package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveLoadResolve(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	t.Setenv("ADGCTL_CONFIG", p)
	for _, k := range []string{"ADG_URL", "ADG_USER", "ADG_PASS", "ADG_PASS_CMD"} {
		t.Setenv(k, "")
	}
	if err := Save(&Config{URL: "http://a:3000/", Username: "u", PasswordCmd: "echo secret"}); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Resolve(); err != nil || c.Password != "secret" || c.URL != "http://a:3000" {
		t.Fatalf("%v %+v", err, c)
	}
	t.Setenv("ADG_URL", "http://b")
	t.Setenv("ADG_USER", "v")
	t.Setenv("ADG_PASS", "pw")
	t.Setenv("ADG_PASS_CMD", "false")
	c, _ = Load()
	if err := c.Resolve(); err != nil || c.URL != "http://b" || c.Username != "v" || c.Password != "pw" {
		t.Fatalf("env: %v %+v", err, c)
	}
}

func TestResolveErrors(t *testing.T) {
	t.Setenv("ADGCTL_CONFIG", filepath.Join(t.TempDir(), "none.yaml"))
	cases := []struct {
		c    Config
		want string
	}{
		{Config{}, "no AdGuard URL"},
		{Config{URL: "http://x"}, "no username"},
		{Config{URL: "http://x", Username: "u"}, "no password"},
		{Config{URL: "http://x", Username: "u", PasswordCmd: "exit 2"}, "password_cmd failed"},
	}
	for _, tc := range cases {
		err := tc.c.Resolve()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: got %v want %s", tc.c, err, tc.want)
		}
	}
}

func TestBadYAMLAndPath(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	t.Setenv("ADGCTL_CONFIG", p)
	_ = os.WriteFile(p, []byte("url: [x"), 0o600)
	if _, err := Load(); err == nil {
		t.Fatal("want yaml error")
	}
	t.Setenv("ADGCTL_CONFIG", "")
	if !strings.HasSuffix(Path(), filepath.Join("adgctl", "config.yaml")) {
		t.Fatal(Path())
	}
}
