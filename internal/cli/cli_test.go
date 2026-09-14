package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/laurenschristian/adgctl/internal/adguard"
	"github.com/laurenschristian/adgctl/internal/adguard/adguardtest"
)

func setup(t *testing.T) *adguardtest.Server {
	t.Helper()
	srv := adguardtest.New()
	t.Cleanup(srv.Close)
	t.Setenv("ADG_URL", srv.URL)
	t.Setenv("ADG_USER", "u")
	t.Setenv("ADG_PASS", "p")
	t.Setenv("ADG_PASS_CMD", "")
	t.Setenv("ADGCTL_CONFIG", filepath.Join(t.TempDir(), "c.yaml"))
	return srv
}

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	flagJSON, flagURL, flagUser = false, "", ""
	root := Root()
	root.SetArgs(args)
	err := root.Execute()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String(), err
}

func must(t *testing.T, out string, err error, want ...string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	norm := func(x string) string { return strings.Join(strings.Fields(x), " ") }
	for _, w := range want {
		if !strings.Contains(norm(out), norm(w)) {
			t.Fatalf("missing %q in\n%s", w, out)
		}
	}
}

func TestInitAndConfigErrors(t *testing.T) {
	setup(t)
	out, err := run(t, "init", "--url", "http://x:3000", "--user", "a", "--password-cmd", "echo p")
	must(t, out, err, "wrote")
	if _, err := run(t, "init", "--user", "a", "--password", "x", "--password-cmd", "y"); err == nil {
		t.Fatal("both password flags must fail")
	}
	t.Setenv("ADG_PASS", "")
	t.Setenv("ADGCTL_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	if _, err := run(t, "--url", "http://x", "--user", "a", "status"); err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("got %v", err)
	}
	if _, err := run(t, "help"); err != nil {
		t.Fatal(err)
	}
}

func TestReadCommands(t *testing.T) {
	setup(t)
	out, err := run(t, "status")
	must(t, out, err, "v0.107.50", "protection  on", "10.0.0.2:53")
	out, err = run(t, "status", "--json")
	must(t, out, err, `"protection_enabled": true`)
	out, err = run(t, "stats")
	must(t, out, err, "queries 1000  blocked 100 (10.0%)", "10.0.0.5", "ads.example")
	out, err = run(t, "stats", "--json")
	must(t, out, err, `"num_dns_queries": 1000`)
	out, err = run(t, "log", "-n", "5")
	must(t, out, err, "example.com", "ads.example")
	out, err = run(t, "blocked")
	must(t, out, err, "||ads.example^")
	if strings.Contains(out, "example.com") {
		t.Fatal("blocked must filter")
	}
	out, err = run(t, "log", "-s", "ads", "--json")
	must(t, out, err, `"reason": "FilteredBlackList"`)
	out, err = run(t, "check", "ads.example")
	must(t, out, err, "FilteredBlackList", "||ads.example^  (list 0)")
	out, err = run(t, "check", "ads.example", "--json")
	must(t, out, err, `"reason"`)
	out, err = run(t, "rules")
	must(t, out, err, "||ads.example^")
	out, err = run(t, "rules", "--json")
	must(t, out, err, "[")
	out, err = run(t, "filters")
	must(t, out, err, "on   100  AdGuard DNS filter", "off  200  OISD big")
	out, err = run(t, "filters", "--json")
	must(t, out, err, `"rules_count": 200`)
	out, err = run(t, "clients")
	must(t, out, err, "nas", "10.0.0.7", "rDNS")
	out, err = run(t, "clients", "--json")
	must(t, out, err, `"auto_clients"`)
	out, err = run(t, "rewrites")
	must(t, out, err, "nas.lan  10.0.0.5")
	out, err = run(t, "rewrites", "--json")
	must(t, out, err, `"domain": "nas.lan"`)
	out, err = run(t, "services")
	must(t, out, err, "tiktok")
	out, err = run(t, "services", "--all")
	must(t, out, err, "roblox", "Roblox")
	out, err = run(t, "services", "--all", "--json")
	must(t, out, err, `"id": "roblox"`)
	out, err = run(t, "services", "--json")
	must(t, out, err, `"ids"`)
	out, err = run(t, "upstreams")
	must(t, out, err, "dns.cloudflare.com", "fallback   9.9.9.9", "dnssec     true")
	out, err = run(t, "upstreams", "--json")
	must(t, out, err, `"upstream_mode": "parallel"`)
	out, err = run(t, "upstreams", "--test")
	must(t, out, err, "OK")
	out, err = run(t, "upstreams", "--test", "--json")
	must(t, out, err, `"OK"`)
	out, err = run(t, "version")
	must(t, out, err, "current: v0.107.50", "available: v0.108.0")
	out, err = run(t, "version", "--json")
	must(t, out, err, `"can_autoupdate": true`)
	out, err = run(t, "access")
	must(t, out, err, "disallowed clients  10.0.0.99", "blocked hosts       version.bind")
	out, err = run(t, "access", "--json")
	must(t, out, err, `"blocked_hosts"`)
	out, err = run(t, "safesearch")
	must(t, out, err, "safesearch: off")
	out, err = run(t, "safesearch", "--json")
	must(t, out, err, `"google": true`)
	out, err = run(t, "safebrowsing")
	must(t, out, err, "safebrowsing: on")
	out, err = run(t, "parental", "--json")
	must(t, out, err, `"enabled": false`)
	out, err = run(t, "tls")
	must(t, out, err, "dns.example", "853 / 853", "warning: self-signed")
	out, err = run(t, "tls", "--json")
	must(t, out, err, `"port_dns_over_tls": 853`)
	out, err = run(t, "dhcp")
	must(t, out, err, "dhcp: off  interface: eth0  leases: 1  static: 1", "10.0.0.5  cc:dd  nas")
	out, err = run(t, "dhcp", "--json")
	must(t, out, err, `"static_leases"`)
	out, err = run(t, "logconfig")
	must(t, out, err, "retention=30d anonymize_client_ip=false")
	out, err = run(t, "logconfig", "--json")
	must(t, out, err, `"interval"`)
	out, err = run(t, "statsconfig")
	must(t, out, err, "window=30d")
	out, err = run(t, "statsconfig", "--json")
	must(t, out, err, `"enabled": true`)
	out, err = run(t, "raw", "status")
	must(t, out, err, "v0.107.50")
	out, err = run(t, "raw", "-X", "POST", "-d", `{"enabled":false}`, "protection")
	must(t, out, err)
	if _, err := run(t, "raw", "nope"); err == nil {
		t.Fatal("raw 404 must error")
	}
}

func TestWriteCommands(t *testing.T) {
	srv := setup(t)
	out, err := run(t, "off", "--for", "5")
	must(t, out, err, "protection off for 5 min")
	if srv.Protection {
		t.Fatal("still on")
	}
	out, err = run(t, "off", "--for", "0")
	must(t, out, err, "until re-enabled")
	out, err = run(t, "on")
	must(t, out, err, "protection on")
	if !srv.Protection {
		t.Fatal("still off")
	}
	out, err = run(t, "allow", "ok.example")
	must(t, out, err, "allowed ok.example")
	out, err = run(t, "allow", "ok.example")
	must(t, out, err, "already present: ok.example")
	out, err = run(t, "block", "bad.example")
	must(t, out, err, "blocked bad.example")
	if len(srv.UserRules) != 3 {
		t.Fatalf("rules %v", srv.UserRules)
	}
	out, err = run(t, "unrule", "ok.example", "bad.example", "none.example")
	must(t, out, err, "ok.example: removed 1", "bad.example: removed 1", "none.example: removed 0")
	out, err = run(t, "filters", "--enable", "oisd")
	must(t, out, err, "OISD big -> enabled=true")
	out, err = run(t, "filters", "--disable", "adguard")
	must(t, out, err, "AdGuard DNS filter -> enabled=false")
	if srv.Filters[0]["enabled"] != false || srv.Filters[1]["enabled"] != true {
		t.Fatalf("filters %v", srv.Filters)
	}
	out, err = run(t, "refresh")
	must(t, out, err, "updated 2 list(s)")
	out, err = run(t, "rewrites", "add", "x.lan", "10.0.0.9")
	must(t, out, err, "added x.lan -> 10.0.0.9")
	out, err = run(t, "rewrites", "rm", "x.lan", "10.0.0.9")
	must(t, out, err, "removed 1")
	out, err = run(t, "rewrites", "rm", "nas.lan")
	must(t, out, err, "removed 1")
	if len(srv.Rewrites) != 0 {
		t.Fatalf("rewrites %v", srv.Rewrites)
	}
	out, err = run(t, "services", "block", "roblox")
	must(t, out, err, "2 service(s) blocked")
	out, err = run(t, "services", "unblock", "tiktok", "roblox")
	must(t, out, err, "0 service(s) blocked")
	out, err = run(t, "upstreams", "--set", "tls://1.1.1.1,tls://9.9.9.9")
	must(t, out, err, "upstreams set", "tls://9.9.9.9")
	out, err = run(t, "version", "--update")
	must(t, out, err, "update started")
	if srv.Updated != 1 {
		t.Fatal("update not called")
	}
	srv.CanUpdate = false
	if _, err := run(t, "version", "--update"); err == nil {
		t.Fatal("cannot self-update must error")
	}
	srv.NewVersion = "v0.107.50"
	out, err = run(t, "version")
	must(t, out, err, "up to date")
	out, err = run(t, "access", "--allow", "10.0.0.0/24", "--hosts", "")
	must(t, out, err, "access lists updated", "allowed clients     10.0.0.0/24")
	out, err = run(t, "access", "--deny", "10.0.0.1")
	must(t, out, err, "disallowed clients  10.0.0.1")
	out, err = run(t, "safesearch", "on")
	must(t, out, err, "safesearch: on")
	out, err = run(t, "parental", "on")
	must(t, out, err, "parental: on")
	out, err = run(t, "safebrowsing", "off")
	must(t, out, err, "safebrowsing: off")
	out, err = run(t, "client", "add", "tv", "--ids", "10.0.0.8,aa:bb:cc:dd:ee:ff", "--tags", "device_tv", "--block-services", "tiktok")
	must(t, out, err, "added client tv")
	out, err = run(t, "client", "add", "guest", "--ids", "10.0.0.50", "--no-filter")
	must(t, out, err, "added client guest")
	if len(srv.Clients) != 3 || srv.Clients[1]["use_global_blocked_services"] != false || srv.Clients[2]["filtering_enabled"] != false {
		t.Fatalf("clients %v", srv.Clients)
	}
	out, err = run(t, "client", "rm", "tv")
	must(t, out, err, "deleted client tv")
	out, err = run(t, "logconfig", "--days", "7", "--anonymize", "on", "--clear")
	must(t, out, err, "query log cleared", "retention=7d anonymize_client_ip=true")
	out, err = run(t, "statsconfig", "--days", "1", "--reset")
	must(t, out, err, "stats reset", "window=1d")
	if srv.Cleared != 1 || srv.Reset != 1 {
		t.Fatal("clear/reset")
	}
}

func TestClientImport(t *testing.T) {
	srv := setup(t)
	in := `[{"name":"tv","ids":["10.0.0.8"],"tags":["device_tv"]},{"name":"nas","ids":["10.0.0.5"]},{"name":"dup","ids":["10.0.0.5"]},{"name":"","ids":["1.1.1.1"]}]`
	f := filepath.Join(t.TempDir(), "in.json")
	_ = os.WriteFile(f, []byte(in), 0o600)
	out, err := run(t, "client", "import", "--file", f, "--dry-run")
	must(t, out, err, "add tv 10.0.0.8", "already belongs to \"nas\"", "added 1, updated 0, skipped 3 (dry run)")
	if len(srv.Clients) != 1 {
		t.Fatal("dry run wrote")
	}
	out, err = run(t, "client", "import", "--file", f, "--update")
	must(t, out, err, "add tv", "update nas", `rename "nas" -> "dup"`, "added 1, updated 2, skipped 1")
	if len(srv.Clients) != 2 || srv.Clients[0]["name"] != "dup" || srv.Clients[1]["tags"].([]any)[0] != "device_tv" {
		t.Fatalf("clients %v", srv.Clients)
	}
	// A device renamed upstream keeps its id; --update should rename the owning client, not skip.
	ren := filepath.Join(t.TempDir(), "ren.json")
	_ = os.WriteFile(ren, []byte(`[{"name":"NAS | Office","ids":["10.0.0.5"]}]`), 0o600)
	// 10.0.0.5 now belongs to "dup" after the collision rename above.
	out, err = run(t, "client", "import", "--file", ren, "--update")
	must(t, out, err, `rename "dup" -> "NAS | Office"`, "updated 1")
	names := map[string]bool{}
	for _, c := range srv.Clients {
		names[c["name"].(string)] = true
	}
	if !names["NAS | Office"] || names["dup"] || len(srv.Clients) != 2 {
		t.Fatalf("rename by id failed: %v", srv.Clients)
	}
	// Without --update, a new name on an already-owned id is skipped as a collision.
	coll := filepath.Join(t.TempDir(), "coll.json")
	_ = os.WriteFile(coll, []byte(`[{"name":"Someone Else","ids":["10.0.0.5"]}]`), 0o600)
	out, err = run(t, "client", "import", "--file", coll)
	must(t, out, err, `already belongs to "NAS | Office"`, "skipped 1")
	r, w, _ := os.Pipe()
	_, _ = w.WriteString(`[{"name":"tv","ids":["10.0.0.8"]}]`)
	_ = w.Close()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	out, err = run(t, "client", "import")
	must(t, out, err, "added 0, updated 0, skipped 1")
	if _, err := run(t, "client", "import", "--file", "/nonexistent"); err == nil {
		t.Fatal("missing file")
	}
	_ = os.WriteFile(f, []byte("{bad"), 0o600)
	if _, err := run(t, "client", "import", "--file", f); err == nil {
		t.Fatal("bad json")
	}
}

func TestErrorsPropagate(t *testing.T) {
	srv := setup(t)
	srv.FailPath = "stats"
	if _, err := run(t, "stats"); err == nil {
		t.Fatal("stats should fail")
	}
	srv.FailPath = "filtering/status"
	if _, err := run(t, "allow", "x.y"); err == nil {
		t.Fatal("allow should fail")
	}
	if firstNonLoopback(nil) != "?" || firstNonLoopback([]string{"127.0.0.1"}) != "127.0.0.1" {
		t.Fatal("firstNonLoopback")
	}
}

func TestMCPTools(t *testing.T) {
	srv := setup(t)
	c := adguard.New(srv.URL, "u", "p")
	s := mcpServer(c)
	ct, st := mcp.NewInMemoryTransports()
	go func() { _ = s.Run(context.Background(), st) }()
	sess, err := mcp.NewClient(&mcp.Implementation{Name: "t"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	tools, err := sess.ListTools(context.Background(), nil)
	if err != nil || len(tools.Tools) != 33 {
		t.Fatalf("%v tools=%d", err, len(tools.Tools))
	}
	call := func(name string, args map[string]any) string {
		t.Helper()
		res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		txt := res.Content[0].(*mcp.TextContent).Text
		if res.IsError {
			return "ERR:" + txt
		}
		return txt
	}
	for _, name := range []string{"adguard_status", "adguard_stats", "adguard_user_rules", "adguard_filters", "adguard_clients", "adguard_rewrites",
		"adguard_blocked_services", "adguard_dns_info", "adguard_version", "adguard_refresh_filters", "adguard_access", "adguard_safety_features",
		"adguard_tls", "adguard_dhcp", "adguard_log_config", "adguard_protection_on", "adguard_test_upstreams"} {
		if out := call(name, nil); strings.HasPrefix(out, "ERR:") {
			t.Fatalf("%s: %s", name, out)
		}
	}
	if out := call("adguard_query_log", map[string]any{"status": "blocked"}); !strings.Contains(out, "ads.example") || strings.Contains(out, "example.com") {
		t.Fatalf("query_log %s", out)
	}
	if out := call("adguard_check_host", map[string]any{"host": "ads.example"}); !strings.Contains(out, "FilteredBlackList") {
		t.Fatalf("check %s", out)
	}
	if out := call("adguard_allow", map[string]any{"hosts": []string{"a.b", "c.d"}}); !strings.Contains(out, "allowed 2 of 2") {
		t.Fatalf("allow %s", out)
	}
	if out := call("adguard_block", map[string]any{"hosts": []string{"e.f"}}); !strings.Contains(out, "blocked 1 of 1") {
		t.Fatalf("block %s", out)
	}
	if out := call("adguard_unrule", map[string]any{"hosts": []string{"a.b", "e.f"}}); !strings.Contains(out, "removed 2") {
		t.Fatalf("unrule %s", out)
	}
	if out := call("adguard_set_filter", map[string]any{"name_contains": "oisd", "enabled": true}); !strings.Contains(out, "updated 1") {
		t.Fatalf("set_filter %s", out)
	}
	call("adguard_protection_off", map[string]any{"minutes": 5})
	if srv.Protection {
		t.Fatal("protection_off")
	}
	call("adguard_add_rewrite", map[string]any{"domain": "x.lan", "answer": "10.0.0.9"})
	call("adguard_delete_rewrite", map[string]any{"domain": "x.lan", "answer": "10.0.0.9"})
	if len(srv.Rewrites) != 1 {
		t.Fatal("rewrites")
	}
	call("adguard_set_blocked_services", map[string]any{"ids": []string{"roblox"}})
	if srv.Blocked[0] != "roblox" {
		t.Fatal("blocked services")
	}
	call("adguard_test_upstreams", map[string]any{"upstreams": []string{"tls://1.1.1.1"}})
	call("adguard_set_upstreams", map[string]any{"upstreams": []string{"tls://1.1.1.1"}})
	if srv.Upstreams[0] != "tls://1.1.1.1" {
		t.Fatal("upstreams")
	}
	call("adguard_set_access", map[string]any{"allowed_clients": []string{"10.0.0.0/24"}, "disallowed_clients": []string{}, "blocked_hosts": []string{"x"}})
	if srv.Access["allowed_clients"][0] != "10.0.0.0/24" || len(srv.Access["disallowed_clients"]) != 0 {
		t.Fatalf("access %v", srv.Access)
	}
	call("adguard_set_safety_feature", map[string]any{"feature": "safesearch", "enabled": true})
	call("adguard_set_safety_feature", map[string]any{"feature": "parental", "enabled": true})
	if !srv.SafeSearch["enabled"] || !srv.Toggles["parental"] {
		t.Fatal("safety features")
	}
	if out := call("adguard_set_safety_feature", map[string]any{"feature": "nope", "enabled": true}); !strings.HasPrefix(out, "ERR:") {
		t.Fatal("unknown feature must error")
	}
	if out := call("adguard_add_client", map[string]any{"name": "tv", "ids": []string{"10.0.0.8"}}); strings.HasPrefix(out, "ERR:") {
		t.Fatal(out)
	}
	if len(srv.Clients) != 2 || srv.Clients[1]["use_global_settings"] != true {
		t.Fatalf("add_client %v", srv.Clients)
	}
	call("adguard_delete_client", map[string]any{"name": "tv"})
	if len(srv.Clients) != 1 {
		t.Fatal("delete_client")
	}
	call("adguard_set_log_config", map[string]any{"querylog_days": 7, "stats_days": 1, "anonymize_client_ip": true})
	if srv.LogConfig["interval"] != float64(7*86_400_000) || srv.StatsConf["interval"] != float64(86_400_000) || srv.LogConfig["anonymize_client_ip"] != true {
		t.Fatalf("log config %v %v", srv.LogConfig, srv.StatsConf)
	}
	srv.FailPath = "stats"
	if out := call("adguard_stats", nil); !strings.HasPrefix(out, "ERR:") {
		t.Fatal("stats error must surface")
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(call("adguard_version", nil)), &v); err != nil || v["current"] != "v0.107.50" {
		t.Fatalf("version %v", v)
	}
}
