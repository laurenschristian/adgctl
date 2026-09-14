package adguard

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/laurenschristian/adgctl/internal/adguard/adguardtest"
)

func setup(t *testing.T) (*adguardtest.Server, *Client) {
	t.Helper()
	srv := adguardtest.New()
	t.Cleanup(srv.Close)
	return srv, New(srv.URL+"/", "u", "p")
}

func TestStatusAuthAndTrim(t *testing.T) {
	_, c := setup(t)
	s, err := c.Status(context.Background())
	if err != nil || s.Version != "v0.107.50" || !s.ProtectionEnabled {
		t.Fatalf("status: %+v %v", s, err)
	}
	c.Password = "wrong"
	if _, err := c.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 error, got %v", err)
	}
}

func TestUserRules(t *testing.T) {
	srv, c := setup(t)
	ctx := context.Background()
	added, err := c.AddUserRule(ctx, AllowRule("ok.example"))
	if err != nil || !added || len(srv.UserRules) != 2 {
		t.Fatalf("add: added=%v rules=%v err=%v", added, srv.UserRules, err)
	}
	if added, _ = c.AddUserRule(ctx, AllowRule("ok.example")); added {
		t.Fatal("duplicate must not be added")
	}
	n, err := c.RemoveUserRule(ctx, "ok.example")
	if err != nil || n != 1 || len(srv.UserRules) != 1 {
		t.Fatalf("remove: n=%d rules=%v err=%v", n, srv.UserRules, err)
	}
	if n, _ = c.RemoveUserRule(ctx, "missing.example"); n != 0 {
		t.Fatal("nothing to remove")
	}
	if BlockRule("x.y") != "||x.y^" || AllowRule("x.y") != "@@||x.y^$important" {
		t.Fatal("rule helpers")
	}
	r, err := c.CheckHost(ctx, "ads.example")
	if err != nil || r.Reason != "FilteredBlackList" || len(r.Rules) != 1 {
		t.Fatalf("check_host %+v %v", r, err)
	}
	wctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if !c.WaitRule(wctx, "ads.example", "FilteredBlackList") {
		t.Fatal("WaitRule should see the rule")
	}
	wctx2, cancel2 := context.WithTimeout(ctx, 400*time.Millisecond)
	defer cancel2()
	if c.WaitRule(wctx2, "ads.example", "NotFilteredWhiteList") {
		t.Fatal("WaitRule should time out")
	}
}

func TestReadEndpoints(t *testing.T) {
	_, c := setup(t)
	ctx := context.Background()
	st, err := c.Stats(ctx)
	if err != nil || st.NumDNSQueries != 1000 {
		t.Fatalf("stats %+v %v", st, err)
	}
	l, err := c.QueryLog(ctx, 10, "", "blocked")
	if err != nil || len(l.Data) != 1 || l.Data[0].Question.Name != "ads.example" {
		t.Fatalf("querylog %+v %v", l, err)
	}
	l, _ = c.QueryLog(ctx, 10, "example.com", "")
	if len(l.Data) != 1 {
		t.Fatalf("search %+v", l)
	}
	fs, err := c.FilteringStatus(ctx)
	if err != nil || len(fs.Filters) != 2 || len(fs.UserRules) != 1 {
		t.Fatalf("filtering %+v %v", fs, err)
	}
	cl, err := c.Clients(ctx)
	if err != nil || len(cl.Clients) != 1 || cl.AutoClients[0].IP != "10.0.0.7" {
		t.Fatalf("clients %+v %v", cl, err)
	}
	rw, err := c.Rewrites(ctx)
	if err != nil || rw[0].Domain != "nas.lan" {
		t.Fatalf("rewrites %+v %v", rw, err)
	}
	all, err := c.AllServices(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("services %+v %v", all, err)
	}
	bs, err := c.BlockedServices(ctx)
	if err != nil || bs.IDs[0] != "tiktok" {
		t.Fatalf("blocked %+v %v", bs, err)
	}
	d, err := c.DNSInfo(ctx)
	if err != nil || !d.EnableDNSSEC || d.UpstreamMode != "parallel" {
		t.Fatalf("dns_info %+v %v", d, err)
	}
	res, err := c.TestUpstreams(ctx, d.UpstreamDNS)
	if err != nil || res[d.UpstreamDNS[0]] != "OK" {
		t.Fatalf("test %+v %v", res, err)
	}
	v, err := c.CheckVersion(ctx)
	if err != nil || v.NewVersion != "v0.108.0" {
		t.Fatalf("version %+v %v", v, err)
	}
	a, err := c.Access(ctx)
	if err != nil || a.DisallowedClients[0] != "10.0.0.99" {
		t.Fatalf("access %+v %v", a, err)
	}
	ss, err := c.SafeSearch(ctx)
	if err != nil || ss.Enabled || !ss.Google {
		t.Fatalf("safesearch %+v %v", ss, err)
	}
	on, err := c.ToggleStatus(ctx, "safebrowsing")
	if err != nil || !on {
		t.Fatalf("toggle status %v %v", on, err)
	}
	tl, err := c.TLS(ctx)
	if err != nil || tl.PortDoT != 853 || tl.WarningMessage == "" {
		t.Fatalf("tls %+v %v", tl, err)
	}
	dh, err := c.DHCP(ctx)
	if err != nil || len(dh.Leases) != 1 || dh.StaticLeases[0].Hostname != "nas" {
		t.Fatalf("dhcp %+v %v", dh, err)
	}
	lc, err := c.QueryLogConfig(ctx)
	if err != nil || lc.IntervalMs != 30*86_400_000 {
		t.Fatalf("logconfig %+v %v", lc, err)
	}
	sc, err := c.StatsConfig(ctx)
	if err != nil || !sc.Enabled {
		t.Fatalf("statsconfig %+v %v", sc, err)
	}
	raw, err := c.Raw(ctx, "GET", "/status", nil)
	if err != nil || !strings.Contains(string(raw), "v0.107.50") {
		t.Fatalf("raw %s %v", raw, err)
	}
	if _, err := c.Raw(ctx, "GET", "nope", nil); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("raw 404: %v", err)
	}
}

func TestWriteEndpoints(t *testing.T) {
	srv, c := setup(t)
	ctx := context.Background()
	if err := c.SetProtection(ctx, false, 60_000); err != nil || srv.Protection {
		t.Fatal("protection off", err)
	}
	if err := c.SetProtection(ctx, true, 0); err != nil || !srv.Protection {
		t.Fatal("protection on", err)
	}
	fs, _ := c.FilteringStatus(ctx)
	if err := c.SetFilterEnabled(ctx, fs.Filters[1], true); err != nil || srv.Filters[1]["enabled"] != true {
		t.Fatal("set_url", err)
	}
	if n, err := c.RefreshFilters(ctx); err != nil || n != 2 {
		t.Fatal("refresh", n, err)
	}
	if err := c.AddRewrite(ctx, Rewrite{Domain: "x.lan", Answer: "10.0.0.9"}); err != nil || len(srv.Rewrites) != 2 {
		t.Fatal("add rewrite", err)
	}
	if err := c.DeleteRewrite(ctx, Rewrite{Domain: "x.lan", Answer: "10.0.0.9"}); err != nil || len(srv.Rewrites) != 1 {
		t.Fatal("delete rewrite", err)
	}
	if err := c.SetBlockedServices(ctx, &BlockedServices{}); err != nil || len(srv.Blocked) != 0 {
		t.Fatal("blocked services empty", err)
	}
	if err := c.SetBlockedServices(ctx, &BlockedServices{IDs: []string{"roblox"}}); err != nil || srv.Blocked[0] != "roblox" {
		t.Fatal("blocked services", err)
	}
	if err := c.SetUpstreams(ctx, []string{"tls://1.1.1.1"}); err != nil || srv.Upstreams[0] != "tls://1.1.1.1" {
		t.Fatal("upstreams", err)
	}
	if err := c.Update(ctx); err != nil || srv.Updated != 1 {
		t.Fatal("update", err)
	}
	if err := c.SetAccess(ctx, &AccessList{AllowedClients: []string{"10.0.0.0/24"}}); err != nil || srv.Access["allowed_clients"][0] != "10.0.0.0/24" || len(srv.Access["blocked_hosts"]) != 0 {
		t.Fatalf("access %v %v", srv.Access, err)
	}
	if err := c.SetSafeSearch(ctx, &SafeSearch{Enabled: true}); err != nil || !srv.SafeSearch["enabled"] {
		t.Fatal("safesearch", err)
	}
	if err := c.Toggle(ctx, "parental", true); err != nil || !srv.Toggles["parental"] {
		t.Fatal("toggle on", err)
	}
	if err := c.Toggle(ctx, "safebrowsing", false); err != nil || srv.Toggles["safebrowsing"] {
		t.Fatal("toggle off", err)
	}
	if err := c.AddClient(ctx, &PersistentClient{Name: "tv", IDs: []string{"10.0.0.8"}}); err != nil || len(srv.Clients) != 2 {
		t.Fatal("add client", err)
	}
	if err := c.UpdateClient(ctx, "tv", &PersistentClient{Name: "tv", IDs: []string{"10.0.0.18"}}); err != nil || srv.Clients[1]["ids"].([]any)[0] != "10.0.0.18" {
		t.Fatalf("update client %v %v", srv.Clients, err)
	}
	if err := c.DeleteClient(ctx, "tv"); err != nil || len(srv.Clients) != 1 {
		t.Fatal("delete client", err)
	}
	if err := c.SetQueryLogConfig(ctx, &LogConfig{Enabled: true, IntervalMs: 86_400_000, AnonymizeClientIP: true}); err != nil || srv.LogConfig["anonymize_client_ip"] != true {
		t.Fatal("logconfig", err)
	}
	if err := c.SetStatsConfig(ctx, &LogConfig{Enabled: true, IntervalMs: 7 * 86_400_000}); err != nil || srv.StatsConf["interval"] != float64(7*86_400_000) {
		t.Fatalf("statsconfig %v %v", srv.StatsConf, err)
	}
	if err := c.ClearQueryLog(ctx); err != nil || srv.Cleared != 1 {
		t.Fatal("clear", err)
	}
	if err := c.ResetStats(ctx); err != nil || srv.Reset != 1 {
		t.Fatal("reset", err)
	}
}

func TestServerErrorSurfaces(t *testing.T) {
	srv, c := setup(t)
	srv.FailPath = "stats"
	if _, err := c.Stats(context.Background()); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("got %v", err)
	}
}
