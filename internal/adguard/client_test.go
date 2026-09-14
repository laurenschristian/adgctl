package adguard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func fake(t *testing.T, rules *[]string) *Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/control/status", func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		if u != "u" || p != "p" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(Status{Version: "v1", ProtectionEnabled: true})
	})
	mux.HandleFunc("/control/filtering/status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(FilteringStatus{UserRules: *rules})
	})
	mux.HandleFunc("/control/filtering/set_rules", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Rules []string }
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		*rules = body.Rules
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return New(srv.URL+"/", "u", "p")
}

func TestStatusAuthAndTrim(t *testing.T) {
	rules := []string{}
	c := fake(t, &rules)
	s, err := c.Status(context.Background())
	if err != nil || s.Version != "v1" || !s.ProtectionEnabled {
		t.Fatalf("status: %+v %v", s, err)
	}
	c.Password = "wrong"
	if _, err := c.Status(context.Background()); err == nil {
		t.Fatal("expected 401 error")
	}
}

func TestAddAndRemoveUserRule(t *testing.T) {
	rules := []string{"||ads.example^"}
	c := fake(t, &rules)
	ctx := context.Background()

	added, err := c.AddUserRule(ctx, AllowRule("ok.example"))
	if err != nil || !added || len(rules) != 2 {
		t.Fatalf("add: added=%v rules=%v err=%v", added, rules, err)
	}
	added, _ = c.AddUserRule(ctx, AllowRule("ok.example"))
	if added {
		t.Fatal("duplicate rule should not be added twice")
	}
	n, err := c.RemoveUserRule(ctx, "ok.example")
	if err != nil || n != 1 || len(rules) != 1 || rules[0] != "||ads.example^" {
		t.Fatalf("remove: n=%d rules=%v err=%v", n, rules, err)
	}
}
