// Package adguardtest is an in-memory fake of the AdGuard Home /control API for tests.
package adguardtest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// Server holds mutable state that handlers read and write. Tests inspect it directly.
type Server struct {
	*httptest.Server
	mu sync.Mutex

	User, Pass string
	Protection bool
	UserRules  []string
	Filters    []map[string]any
	Rewrites   []map[string]string
	Blocked    []string
	Upstreams  []string
	Access     map[string][]string
	SafeSearch map[string]bool
	Toggles    map[string]bool
	Clients    []map[string]any
	LogConfig  map[string]any
	StatsConf  map[string]any
	Calls      []string
	Cleared    int
	Reset      int
	Updated    int
	NewVersion string
	CanUpdate  bool
	// FailPath makes every request to this path return 500.
	FailPath string
}

func New() *Server {
	s := &Server{
		User: "u", Pass: "p", Protection: true,
		UserRules: []string{"||ads.example^"},
		Filters: []map[string]any{
			{"id": 1, "name": "AdGuard DNS filter", "url": "https://a/x.txt", "enabled": true, "rules_count": 100},
			{"id": 2, "name": "OISD big", "url": "https://o/x.txt", "enabled": false, "rules_count": 200},
		},
		Rewrites:   []map[string]string{{"domain": "nas.lan", "answer": "10.0.0.5"}},
		Blocked:    []string{"tiktok"},
		Upstreams:  []string{"https://dns.cloudflare.com/dns-query"},
		Access:     map[string][]string{"allowed_clients": {}, "disallowed_clients": {"10.0.0.99"}, "blocked_hosts": {"version.bind"}},
		SafeSearch: map[string]bool{"enabled": false, "google": true},
		Toggles:    map[string]bool{"safebrowsing": true, "parental": false},
		Clients:    []map[string]any{{"name": "nas", "ids": []any{"10.0.0.5"}}},
		LogConfig:  map[string]any{"enabled": true, "interval": float64(30 * 86_400_000), "anonymize_client_ip": false, "ignored": []string{}},
		StatsConf:  map[string]any{"enabled": true, "interval": float64(30 * 86_400_000), "ignored": []string{}},
		NewVersion: "v0.108.0", CanUpdate: true,
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *Server) write(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, p, _ := r.BasicAuth()
	if u != s.User || p != s.Pass {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/control/")
	s.Calls = append(s.Calls, r.Method+" "+path)
	if s.FailPath != "" && path == s.FailPath {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
		return
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	switch path {
	case "status":
		s.write(w, map[string]any{"version": "v0.107.50", "protection_enabled": s.Protection, "running": true, "dns_addresses": []string{"127.0.0.1", "10.0.0.2"}, "dns_port": 53})
	case "stats":
		s.write(w, map[string]any{"num_dns_queries": 1000, "num_blocked_filtering": 100, "avg_processing_time": 0.012,
			"top_clients": []map[string]int{{"10.0.0.5": 500}}, "top_blocked_domains": []map[string]int{{"ads.example": 40}}, "top_queried_domains": []map[string]int{{"example.com": 90}}})
	case "querylog":
		q := r.URL.Query()
		entries := []map[string]any{
			{"time": "2026-09-14T10:00:00Z", "client": "10.0.0.5", "reason": "NotFilteredNotFound", "question": map[string]string{"name": "example.com", "type": "A"}},
			{"time": "2026-09-14T10:00:01Z", "client": "10.0.0.6", "reason": "FilteredBlackList", "question": map[string]string{"name": "ads.example", "type": "A"}, "rules": []map[string]any{{"text": "||ads.example^", "filter_list_id": 0}}},
		}
		var out []map[string]any
		for _, e := range entries {
			if q.Get("response_status") == "blocked" && e["reason"] != "FilteredBlackList" {
				continue
			}
			if q.Get("search") != "" && !strings.Contains(e["question"].(map[string]string)["name"], q.Get("search")) {
				continue
			}
			out = append(out, e)
		}
		s.write(w, map[string]any{"data": out, "oldest": "2026-09-01T00:00:00Z"})
	case "protection":
		s.Protection, _ = body["enabled"].(bool)
	case "filtering/status":
		s.write(w, map[string]any{"enabled": true, "interval": 24, "filters": s.Filters, "user_rules": s.UserRules})
	case "filtering/set_rules":
		s.UserRules = nil
		for _, x := range body["rules"].([]any) {
			s.UserRules = append(s.UserRules, x.(string))
		}
	case "filtering/set_url":
		d := body["data"].(map[string]any)
		for _, f := range s.Filters {
			if f["url"] == d["url"] {
				f["enabled"] = d["enabled"]
			}
		}
	case "filtering/refresh":
		s.write(w, map[string]int{"updated": 2})
	case "filtering/check_host":
		name := r.URL.Query().Get("name")
		reason := "NotFilteredNotFound"
		var rules []map[string]any
		for _, ru := range s.UserRules {
			if strings.Contains(ru, "||"+name+"^") {
				reason = "FilteredBlackList"
				if strings.HasPrefix(ru, "@@") {
					reason = "NotFilteredWhiteList"
				}
				rules = append(rules, map[string]any{"text": ru, "filter_list_id": 0})
			}
		}
		s.write(w, map[string]any{"reason": reason, "rules": rules})
	case "clients":
		s.write(w, map[string]any{"clients": s.Clients, "auto_clients": []map[string]any{{"ip": "10.0.0.7", "name": "phone", "source": "rDNS"}}})
	case "clients/add":
		s.Clients = append(s.Clients, body)
	case "clients/update":
		for i, c := range s.Clients {
			if c["name"] == body["name"] {
				s.Clients[i] = body["data"].(map[string]any)
			}
		}
	case "clients/delete":
		keep := s.Clients[:0]
		for _, c := range s.Clients {
			if c["name"] != body["name"] {
				keep = append(keep, c)
			}
		}
		s.Clients = keep
	case "rewrite/list":
		s.write(w, s.Rewrites)
	case "rewrite/add":
		s.Rewrites = append(s.Rewrites, map[string]string{"domain": body["domain"].(string), "answer": body["answer"].(string)})
	case "rewrite/delete":
		keep := s.Rewrites[:0]
		for _, x := range s.Rewrites {
			if x["domain"] != body["domain"] || x["answer"] != body["answer"] {
				keep = append(keep, x)
			}
		}
		s.Rewrites = keep
	case "blocked_services/all":
		s.write(w, map[string]any{"blocked_services": []map[string]string{{"id": "tiktok", "name": "TikTok"}, {"id": "roblox", "name": "Roblox"}}})
	case "blocked_services/get":
		s.write(w, map[string]any{"schedule": map[string]any{"time_zone": "UTC"}, "ids": s.Blocked})
	case "blocked_services/update":
		s.Blocked = nil
		for _, x := range body["ids"].([]any) {
			s.Blocked = append(s.Blocked, x.(string))
		}
	case "dns_info":
		s.write(w, map[string]any{"upstream_dns": s.Upstreams, "fallback_dns": []string{"9.9.9.9"}, "bootstrap_dns": []string{"1.1.1.1"}, "upstream_mode": "parallel", "cache_enabled": true, "cache_optimistic": true, "dnssec_enabled": true, "protection_enabled": s.Protection, "blocking_mode": "default"})
	case "dns_config":
		s.Upstreams = nil
		for _, x := range body["upstream_dns"].([]any) {
			s.Upstreams = append(s.Upstreams, x.(string))
		}
	case "test_upstream_dns":
		out := map[string]string{}
		for _, x := range body["upstream_dns"].([]any) {
			out[x.(string)] = "OK"
		}
		s.write(w, out)
	case "version.json":
		s.write(w, map[string]any{"new_version": s.NewVersion, "can_autoupdate": s.CanUpdate})
	case "update":
		s.Updated++
	case "access/list":
		s.write(w, s.Access)
	case "access/set":
		for k := range s.Access {
			s.Access[k] = nil
			if v, ok := body[k].([]any); ok {
				for _, x := range v {
					s.Access[k] = append(s.Access[k], x.(string))
				}
			}
		}
	case "safesearch/status":
		s.write(w, s.SafeSearch)
	case "safesearch/settings":
		s.SafeSearch["enabled"], _ = body["enabled"].(bool)
	case "safebrowsing/status", "parental/status":
		s.write(w, map[string]bool{"enabled": s.Toggles[strings.Split(path, "/")[0]]})
	case "safebrowsing/enable", "parental/enable":
		s.Toggles[strings.Split(path, "/")[0]] = true
	case "safebrowsing/disable", "parental/disable":
		s.Toggles[strings.Split(path, "/")[0]] = false
	case "tls/status":
		s.write(w, map[string]any{"enabled": true, "server_name": "dns.example", "port_https": 443, "port_dns_over_tls": 853, "port_dns_over_quic": 853, "valid_cert": true, "valid_chain": true, "valid_key": true, "not_after": "2027-01-01T00:00:00Z", "serve_plain_dns": true, "warning_validation": "self-signed"})
	case "dhcp/status":
		s.write(w, map[string]any{"enabled": false, "interface_name": "eth0", "leases": []map[string]string{{"ip": "10.0.0.9", "mac": "aa:bb", "hostname": "x", "expires": "2026-09-15T00:00:00Z"}}, "static_leases": []map[string]string{{"ip": "10.0.0.5", "mac": "cc:dd", "hostname": "nas"}}})
	case "querylog/config":
		s.write(w, s.LogConfig)
	case "querylog/config/update":
		for k, v := range body {
			s.LogConfig[k] = v
		}
	case "stats/config":
		s.write(w, s.StatsConf)
	case "stats/config/update":
		for k, v := range body {
			s.StatsConf[k] = v
		}
	case "querylog_clear":
		s.Cleared++
	case "stats_reset":
		s.Reset++
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("no such endpoint"))
	}
}

// Called reports whether a "METHOD path" entry was recorded.
func (s *Server) Called(call string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.Calls {
		if c == call {
			return true
		}
	}
	return false
}
