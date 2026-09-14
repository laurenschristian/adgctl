// Package adguard is a small client for the AdGuard Home REST API (/control/*).
package adguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL  string
	Username string
	Password string
	HTTP     *http.Client
}

func New(baseURL, user, pass string) *Client {
	return &Client{
		BaseURL:  strings.TrimRight(baseURL, "/"),
		Username: user,
		Password: pass,
		HTTP:     &http.Client{Timeout: 15 * time.Second},
	}
}

type Status struct {
	Version           string   `json:"version"`
	ProtectionEnabled bool     `json:"protection_enabled"`
	Running           bool     `json:"running"`
	DNSAddresses      []string `json:"dns_addresses"`
	DNSPort           int      `json:"dns_port"`
	HTTPPort          int      `json:"http_port"`
}

type Stats struct {
	TimeUnits             string           `json:"time_units"`
	NumDNSQueries         int              `json:"num_dns_queries"`
	NumBlockedFiltering   int              `json:"num_blocked_filtering"`
	NumReplacedSafebrowse int              `json:"num_replaced_safebrowsing"`
	NumReplacedParental   int              `json:"num_replaced_parental"`
	AvgProcessingTime     float64          `json:"avg_processing_time"`
	TopQueried            []map[string]int `json:"top_queried_domains"`
	TopBlocked            []map[string]int `json:"top_blocked_domains"`
	TopClients            []map[string]int `json:"top_clients"`
}

type QueryLogEntry struct {
	Time     string `json:"time"`
	Client   string `json:"client"`
	Reason   string `json:"reason"`
	Status   string `json:"status"`
	Upstream string `json:"upstream"`
	Elapsed  string `json:"elapsedMs"`
	Question struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"question"`
	Rules []struct {
		Text         string `json:"text"`
		FilterListID int    `json:"filter_list_id"`
	} `json:"rules"`
}

type QueryLog struct {
	Data   []QueryLogEntry `json:"data"`
	Oldest string          `json:"oldest"`
}

type Filter struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Enabled     bool   `json:"enabled"`
	RulesCount  int    `json:"rules_count"`
	LastUpdated string `json:"last_updated"`
}

type FilteringStatus struct {
	Enabled   bool     `json:"enabled"`
	Interval  int      `json:"interval"`
	Filters   []Filter `json:"filters"`
	UserRules []string `json:"user_rules"`
}

type CheckResult struct {
	Reason string `json:"reason"`
	Rules  []struct {
		Text         string `json:"text"`
		FilterListID int    `json:"filter_list_id"`
	} `json:"rules"`
	CanonName string   `json:"cname,omitempty"`
	IPList    []string `json:"ip_addrs,omitempty"`
}

type AutoClient struct {
	IP     string `json:"ip"`
	Name   string `json:"name"`
	Source string `json:"source"`
	WhoIs  any    `json:"whois_info"`
}

type Clients struct {
	Clients     []map[string]any `json:"clients"`
	AutoClients []AutoClient     `json:"auto_clients"`
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+"/control/"+path, rdr)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.Username, c.Password)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return fmt.Errorf("adguard %s %s: %s: %s", method, path, res.Status, strings.TrimSpace(string(data)))
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

func (c *Client) Status(ctx context.Context) (*Status, error) {
	var s Status
	return &s, c.do(ctx, http.MethodGet, "status", nil, &s)
}

func (c *Client) Stats(ctx context.Context) (*Stats, error) {
	var s Stats
	return &s, c.do(ctx, http.MethodGet, "stats", nil, &s)
}

// QueryLog fetches recent entries. status is "" | "blocked" | "processed" | "whitelisted" ...
func (c *Client) QueryLog(ctx context.Context, limit int, search, status string) (*QueryLog, error) {
	q := url.Values{}
	q.Set("limit", fmt.Sprint(limit))
	if search != "" {
		q.Set("search", search)
	}
	if status != "" {
		q.Set("response_status", status)
	}
	var l QueryLog
	return &l, c.do(ctx, http.MethodGet, "querylog?"+q.Encode(), nil, &l)
}

// SetProtection toggles filtering. durationMs > 0 disables temporarily (only valid when enabled=false).
func (c *Client) SetProtection(ctx context.Context, enabled bool, durationMs int64) error {
	body := map[string]any{"enabled": enabled}
	if !enabled && durationMs > 0 {
		body["duration"] = durationMs
	}
	return c.do(ctx, http.MethodPost, "protection", body, nil)
}

func (c *Client) FilteringStatus(ctx context.Context) (*FilteringStatus, error) {
	var f FilteringStatus
	return &f, c.do(ctx, http.MethodGet, "filtering/status", nil, &f)
}

func (c *Client) SetFilterEnabled(ctx context.Context, f Filter, enabled bool) error {
	body := map[string]any{
		"url":       f.URL,
		"whitelist": false,
		"data":      map[string]any{"name": f.Name, "url": f.URL, "enabled": enabled},
	}
	return c.do(ctx, http.MethodPost, "filtering/set_url", body, nil)
}

// RefreshFilters blocks while AdGuard re-downloads every list; allow minutes.
func (c *Client) RefreshFilters(ctx context.Context) (updated int, err error) {
	slow := *c
	slow.HTTP = &http.Client{Timeout: 5 * time.Minute}
	var out struct {
		Updated int `json:"updated"`
	}
	return out.Updated, slow.do(ctx, http.MethodPost, "filtering/refresh", map[string]any{"whitelist": false}, &out)
}

func (c *Client) CheckHost(ctx context.Context, host string) (*CheckResult, error) {
	var r CheckResult
	return &r, c.do(ctx, http.MethodGet, "filtering/check_host?name="+url.QueryEscape(host), nil, &r)
}

func (c *Client) SetUserRules(ctx context.Context, rules []string) error {
	return c.do(ctx, http.MethodPost, "filtering/set_rules", map[string]any{"rules": rules}, nil)
}

// AddUserRule appends a rule unless it is already present.
func (c *Client) AddUserRule(ctx context.Context, rule string) (added bool, err error) {
	st, err := c.FilteringStatus(ctx)
	if err != nil {
		return false, err
	}
	for _, r := range st.UserRules {
		if strings.TrimSpace(r) == rule {
			return false, nil
		}
	}
	return true, c.SetUserRules(ctx, append(st.UserRules, rule))
}

// RemoveUserRule drops every rule that mentions host (allow or block form).
func (c *Client) RemoveUserRule(ctx context.Context, host string) (removed int, err error) {
	st, err := c.FilteringStatus(ctx)
	if err != nil {
		return 0, err
	}
	keep := st.UserRules[:0]
	for _, r := range st.UserRules {
		if strings.Contains(r, "||"+host+"^") {
			removed++
			continue
		}
		keep = append(keep, r)
	}
	if removed == 0 {
		return 0, nil
	}
	return removed, c.SetUserRules(ctx, keep)
}

func (c *Client) Clients(ctx context.Context) (*Clients, error) {
	var cl Clients
	return &cl, c.do(ctx, http.MethodGet, "clients", nil, &cl)
}

// Raw performs an arbitrary /control request and returns the body.
func (c *Client) Raw(ctx context.Context, method, path string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+"/control/"+strings.TrimPrefix(path, "/"), body)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return data, fmt.Errorf("adguard %s %s: %s", method, path, res.Status)
	}
	return data, nil
}

func AllowRule(host string) string { return "@@||" + host + "^$important" }
func BlockRule(host string) string { return "||" + host + "^" }

type Rewrite struct {
	Domain string `json:"domain"`
	Answer string `json:"answer"`
}

func (c *Client) Rewrites(ctx context.Context) ([]Rewrite, error) {
	var r []Rewrite
	return r, c.do(ctx, http.MethodGet, "rewrite/list", nil, &r)
}

func (c *Client) AddRewrite(ctx context.Context, r Rewrite) error {
	return c.do(ctx, http.MethodPost, "rewrite/add", r, nil)
}

func (c *Client) DeleteRewrite(ctx context.Context, r Rewrite) error {
	return c.do(ctx, http.MethodPost, "rewrite/delete", r, nil)
}

type BlockedService struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type BlockedServices struct {
	Schedule map[string]any `json:"schedule"`
	IDs      []string       `json:"ids"`
}

func (c *Client) AllServices(ctx context.Context) ([]BlockedService, error) {
	var out struct {
		BlockedServices []BlockedService `json:"blocked_services"`
	}
	return out.BlockedServices, c.do(ctx, http.MethodGet, "blocked_services/all", nil, &out)
}

func (c *Client) BlockedServices(ctx context.Context) (*BlockedServices, error) {
	var b BlockedServices
	return &b, c.do(ctx, http.MethodGet, "blocked_services/get", nil, &b)
}

func (c *Client) SetBlockedServices(ctx context.Context, b *BlockedServices) error {
	if b.Schedule == nil {
		b.Schedule = map[string]any{"time_zone": "UTC"}
	}
	if b.IDs == nil {
		b.IDs = []string{}
	}
	return c.do(ctx, http.MethodPut, "blocked_services/update", b, nil)
}

// DNSInfo is the subset of /dns_info most people care about; Raw holds the rest.
type DNSInfo struct {
	UpstreamDNS    []string `json:"upstream_dns"`
	FallbackDNS    []string `json:"fallback_dns"`
	BootstrapDNS   []string `json:"bootstrap_dns"`
	UpstreamMode   string   `json:"upstream_mode"`
	CacheEnabled   bool     `json:"cache_enabled"`
	CacheOptimist  bool     `json:"cache_optimistic"`
	EnableDNSSEC   bool     `json:"dnssec_enabled"`
	ProtectionOn   bool     `json:"protection_enabled"`
	BlockingMode   string   `json:"blocking_mode"`
	RateLimit      int      `json:"ratelimit"`
	UpstreamTimout int      `json:"upstream_timeout"`
}

func (c *Client) DNSInfo(ctx context.Context) (*DNSInfo, error) {
	var d DNSInfo
	return &d, c.do(ctx, http.MethodGet, "dns_info", nil, &d)
}

// SetUpstreams updates only the upstream list; other dns_config fields stay as they are.
func (c *Client) SetUpstreams(ctx context.Context, upstreams []string) error {
	return c.do(ctx, http.MethodPost, "dns_config", map[string]any{"upstream_dns": upstreams}, nil)
}

type TestUpstreamsResult map[string]string

func (c *Client) TestUpstreams(ctx context.Context, upstreams []string) (TestUpstreamsResult, error) {
	var r TestUpstreamsResult
	body := map[string]any{"upstream_dns": upstreams, "bootstrap_dns": []string{"1.1.1.1", "9.9.9.9"}}
	return r, c.do(ctx, http.MethodPost, "test_upstream_dns", body, &r)
}

type VersionInfo struct {
	NewVersion    string `json:"new_version"`
	Announcement  string `json:"announcement"`
	CanAutoupdate bool   `json:"can_autoupdate"`
	Disabled      bool   `json:"disabled"`
}

func (c *Client) CheckVersion(ctx context.Context) (*VersionInfo, error) {
	var v VersionInfo
	return &v, c.do(ctx, http.MethodPost, "version.json", map[string]any{"recheck_now": true}, &v)
}

func (c *Client) Update(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "update", nil, nil)
}

// WaitRule polls check_host until the host reports the wanted reason or the ctx ends.
func (c *Client) WaitRule(ctx context.Context, host, wantReason string) bool {
	t := time.NewTicker(300 * time.Millisecond)
	defer t.Stop()
	for {
		r, err := c.CheckHost(ctx, host)
		if err == nil && r.Reason == wantReason {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
		}
	}
}

type AccessList struct {
	AllowedClients    []string `json:"allowed_clients"`
	DisallowedClients []string `json:"disallowed_clients"`
	BlockedHosts      []string `json:"blocked_hosts"`
}

func (c *Client) Access(ctx context.Context) (*AccessList, error) {
	var a AccessList
	return &a, c.do(ctx, http.MethodGet, "access/list", nil, &a)
}

func (c *Client) SetAccess(ctx context.Context, a *AccessList) error {
	for _, p := range []*[]string{&a.AllowedClients, &a.DisallowedClients, &a.BlockedHosts} {
		if *p == nil {
			*p = []string{}
		}
	}
	return c.do(ctx, http.MethodPost, "access/set", a, nil)
}

type SafeSearch struct {
	Enabled    bool `json:"enabled"`
	Bing       bool `json:"bing"`
	DuckDuckGo bool `json:"duckduckgo"`
	Ecosia     bool `json:"ecosia"`
	Google     bool `json:"google"`
	Pixabay    bool `json:"pixabay"`
	Yandex     bool `json:"yandex"`
	YouTube    bool `json:"youtube"`
}

func (c *Client) SafeSearch(ctx context.Context) (*SafeSearch, error) {
	var s SafeSearch
	return &s, c.do(ctx, http.MethodGet, "safesearch/status", nil, &s)
}

func (c *Client) SetSafeSearch(ctx context.Context, s *SafeSearch) error {
	return c.do(ctx, http.MethodPut, "safesearch/settings", s, nil)
}

type enabledOnly struct {
	Enabled bool `json:"enabled"`
}

// Toggle drives the enable/disable pairs: feature is "safebrowsing" or "parental".
func (c *Client) Toggle(ctx context.Context, feature string, on bool) error {
	verb := "disable"
	if on {
		verb = "enable"
	}
	return c.do(ctx, http.MethodPost, feature+"/"+verb, nil, nil)
}

func (c *Client) ToggleStatus(ctx context.Context, feature string) (bool, error) {
	var e enabledOnly
	return e.Enabled, c.do(ctx, http.MethodGet, feature+"/status", nil, &e)
}

type TLSStatus struct {
	Enabled        bool   `json:"enabled"`
	ServerName     string `json:"server_name"`
	ForceHTTPS     bool   `json:"force_https"`
	PortHTTPS      int    `json:"port_https"`
	PortDoT        int    `json:"port_dns_over_tls"`
	PortDoQ        int    `json:"port_dns_over_quic"`
	ValidCert      bool   `json:"valid_cert"`
	ValidChain     bool   `json:"valid_chain"`
	ValidKey       bool   `json:"valid_key"`
	NotAfter       string `json:"not_after"`
	Subject        string `json:"subject"`
	Issuer         string `json:"issuer"`
	ServePlainDNS  bool   `json:"serve_plain_dns"`
	WarningMessage string `json:"warning_validation"`
}

func (c *Client) TLS(ctx context.Context) (*TLSStatus, error) {
	var t TLSStatus
	return &t, c.do(ctx, http.MethodGet, "tls/status", nil, &t)
}

type DHCPLease struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Expires  string `json:"expires,omitempty"`
}

type DHCPStatus struct {
	Enabled      bool        `json:"enabled"`
	Interface    string      `json:"interface_name"`
	V4           any         `json:"v4"`
	Leases       []DHCPLease `json:"leases"`
	StaticLeases []DHCPLease `json:"static_leases"`
}

func (c *Client) DHCP(ctx context.Context) (*DHCPStatus, error) {
	var d DHCPStatus
	return &d, c.do(ctx, http.MethodGet, "dhcp/status", nil, &d)
}

// PersistentClient is the editable client record; IDs are IPs, CIDRs, MACs or ClientIDs.
type PersistentClient struct {
	Name              string   `json:"name"`
	IDs               []string `json:"ids"`
	Tags              []string `json:"tags"`
	UseGlobalSettings bool     `json:"use_global_settings"`
	FilteringEnabled  bool     `json:"filtering_enabled"`
	ParentalEnabled   bool     `json:"parental_enabled"`
	SafebrowsingOn    bool     `json:"safebrowsing_enabled"`
	UseGlobalServices bool     `json:"use_global_blocked_services"`
	BlockedServices   []string `json:"blocked_services"`
	Upstreams         []string `json:"upstreams"`
	SafeSearch        struct {
		Enabled bool `json:"enabled"`
	} `json:"safe_search"`
}

func (c *Client) AddClient(ctx context.Context, p *PersistentClient) error {
	fillClient(p)
	return c.do(ctx, http.MethodPost, "clients/add", p, nil)
}

func (c *Client) UpdateClient(ctx context.Context, name string, p *PersistentClient) error {
	fillClient(p)
	return c.do(ctx, http.MethodPost, "clients/update", map[string]any{"name": name, "data": p}, nil)
}

func (c *Client) DeleteClient(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodPost, "clients/delete", map[string]any{"name": name}, nil)
}

func fillClient(p *PersistentClient) {
	for _, s := range []*[]string{&p.IDs, &p.Tags, &p.BlockedServices, &p.Upstreams} {
		if *s == nil {
			*s = []string{}
		}
	}
}

type LogConfig struct {
	Enabled           bool     `json:"enabled"`
	IntervalMs        int64    `json:"interval"`
	AnonymizeClientIP bool     `json:"anonymize_client_ip"`
	Ignored           []string `json:"ignored"`
}

func (c *Client) QueryLogConfig(ctx context.Context) (*LogConfig, error) {
	var l LogConfig
	return &l, c.do(ctx, http.MethodGet, "querylog/config", nil, &l)
}

func (c *Client) SetQueryLogConfig(ctx context.Context, l *LogConfig) error {
	if l.Ignored == nil {
		l.Ignored = []string{}
	}
	return c.do(ctx, http.MethodPut, "querylog/config/update", l, nil)
}

func (c *Client) StatsConfig(ctx context.Context) (*LogConfig, error) {
	var l LogConfig
	return &l, c.do(ctx, http.MethodGet, "stats/config", nil, &l)
}

func (c *Client) SetStatsConfig(ctx context.Context, l *LogConfig) error {
	if l.Ignored == nil {
		l.Ignored = []string{}
	}
	body := map[string]any{"enabled": l.Enabled, "interval": l.IntervalMs, "ignored": l.Ignored}
	return c.do(ctx, http.MethodPut, "stats/config/update", body, nil)
}

func (c *Client) ClearQueryLog(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "querylog_clear", nil, nil)
}

func (c *Client) ResetStats(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "stats_reset", nil, nil)
}
