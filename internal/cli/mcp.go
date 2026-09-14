package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/laurenschristian/adgctl/internal/adguard"
)

func mcpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run as an MCP server over stdio (for Claude, Cursor, etc.)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return mcpServer(client).Run(cmd.Context(), &mcp.StdioTransport{})
		},
	}
}

type hostIn struct {
	Host string `json:"host" jsonschema:"domain name, e.g. tracker.example.com"`
}
type hostsIn struct {
	Hosts []string `json:"hosts" jsonschema:"domain names to add rules for"`
}
type logIn struct {
	Limit  int    `json:"limit,omitempty" jsonschema:"max entries, default 50"`
	Search string `json:"search,omitempty" jsonschema:"domain or client IP substring"`
	Status string `json:"status,omitempty" jsonschema:"filter: blocked, processed, whitelisted, or empty for all"`
}
type offIn struct {
	Minutes int `json:"minutes,omitempty" jsonschema:"disable for this many minutes; 0 = until re-enabled"`
}
type filterIn struct {
	NameContains string `json:"name_contains" jsonschema:"case-insensitive substring of the blocklist name"`
	Enabled      bool   `json:"enabled"`
}
type addClientIn struct {
	Name            string   `json:"name"`
	IDs             []string `json:"ids" jsonschema:"IPs, CIDRs, MACs or ClientIDs"`
	Tags            []string `json:"tags,omitempty" jsonschema:"e.g. device_phone, user_child"`
	Upstreams       []string `json:"upstreams,omitempty" jsonschema:"per-client upstream servers"`
	BlockedServices []string `json:"blocked_services,omitempty" jsonschema:"per-client blocked service ids"`
	NoFilter        bool     `json:"no_filter,omitempty" jsonschema:"bypass filtering for this client"`
}
type msgOut struct {
	Message string `json:"message"`
}

func mcpServer(c *adguard.Client) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "adgctl", Version: Version}, nil)

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_status", Description: "AdGuard Home version and whether protection is on."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, *adguard.Status, error) {
			st, err := c.Status(ctx)
			return nil, st, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_stats", Description: "Query/blocked counts, top clients, top blocked domains for the stats window."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, *adguard.Stats, error) {
			st, err := c.Stats(ctx)
			return nil, st, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_query_log", Description: "Recent DNS queries. Use status=blocked to see what was blocked, search to narrow by domain or client."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in logIn) (*mcp.CallToolResult, []adguard.QueryLogEntry, error) {
			if in.Limit <= 0 {
				in.Limit = 50
			}
			l, err := c.QueryLog(ctx, in.Limit, in.Search, in.Status)
			if err != nil {
				return nil, nil, err
			}
			return nil, l.Data, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_check_host", Description: "Explain how a host would be filtered and which rule/list matched."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in hostIn) (*mcp.CallToolResult, *adguard.CheckResult, error) {
			r, err := c.CheckHost(ctx, in.Host)
			return nil, r, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_allow", Description: "Add allow rules (@@||host^$important) so the hosts are never blocked."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in hostsIn) (*mcp.CallToolResult, msgOut, error) {
			return ruleTool(ctx, c, in.Hosts, adguard.AllowRule, "allowed")
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_block", Description: "Add block rules (||host^) for the hosts."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in hostsIn) (*mcp.CallToolResult, msgOut, error) {
			return ruleTool(ctx, c, in.Hosts, adguard.BlockRule, "blocked")
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_unrule", Description: "Remove user rules that mention the hosts (both allow and block forms)."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in hostsIn) (*mcp.CallToolResult, msgOut, error) {
			total := 0
			for _, h := range in.Hosts {
				n, err := c.RemoveUserRule(ctx, h)
				if err != nil {
					return nil, msgOut{}, err
				}
				total += n
			}
			return nil, msgOut{Message: fmt.Sprintf("removed %d rule(s)", total)}, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_user_rules", Description: "List custom user rules."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, []string, error) {
			st, err := c.FilteringStatus(ctx)
			if err != nil {
				return nil, nil, err
			}
			return nil, st.UserRules, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_filters", Description: "List blocklists with enabled state and rule counts."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, []adguard.Filter, error) {
			st, err := c.FilteringStatus(ctx)
			if err != nil {
				return nil, nil, err
			}
			return nil, st.Filters, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_set_filter", Description: "Enable or disable blocklists whose name contains a substring."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in filterIn) (*mcp.CallToolResult, msgOut, error) {
			st, err := c.FilteringStatus(ctx)
			if err != nil {
				return nil, msgOut{}, err
			}
			n := 0
			for _, f := range st.Filters {
				if containsFold(f.Name, in.NameContains) {
					if err := c.SetFilterEnabled(ctx, f, in.Enabled); err != nil {
						return nil, msgOut{}, err
					}
					n++
				}
			}
			return nil, msgOut{Message: fmt.Sprintf("updated %d list(s)", n)}, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_protection_on", Description: "Enable filtering."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, msgOut, error) {
			return nil, msgOut{Message: "protection on"}, c.SetProtection(ctx, true, 0)
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_protection_off", Description: "Disable filtering, optionally for N minutes."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in offIn) (*mcp.CallToolResult, msgOut, error) {
			return nil, msgOut{Message: fmt.Sprintf("protection off (%d min, 0 = indefinite)", in.Minutes)},
				c.SetProtection(ctx, false, int64(in.Minutes)*60_000)
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_clients", Description: "Known and auto-discovered clients."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, *adguard.Clients, error) {
			cl, err := c.Clients(ctx)
			return nil, cl, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_rewrites", Description: "List DNS rewrites (local domain overrides)."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, []adguard.Rewrite, error) {
			r, err := c.Rewrites(ctx)
			return nil, r, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_add_rewrite", Description: "Add a DNS rewrite: domain (wildcards like *.lan ok) to an IP or CNAME target."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in adguard.Rewrite) (*mcp.CallToolResult, msgOut, error) {
			return nil, msgOut{Message: "added " + in.Domain + " -> " + in.Answer}, c.AddRewrite(ctx, in)
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_delete_rewrite", Description: "Delete a DNS rewrite (exact domain and answer)."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in adguard.Rewrite) (*mcp.CallToolResult, msgOut, error) {
			return nil, msgOut{Message: "deleted " + in.Domain}, c.DeleteRewrite(ctx, in)
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_blocked_services", Description: "Currently blocked services (ids) and the full catalog of service ids."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, map[string]any, error) {
			b, err := c.BlockedServices(ctx)
			if err != nil {
				return nil, nil, err
			}
			all, err := c.AllServices(ctx)
			if err != nil {
				return nil, nil, err
			}
			return nil, map[string]any{"blocked": b.IDs, "available": all}, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_set_blocked_services", Description: "Replace the blocked services list with these ids."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			IDs []string `json:"ids"`
		}) (*mcp.CallToolResult, msgOut, error) {
			b, err := c.BlockedServices(ctx)
			if err != nil {
				return nil, msgOut{}, err
			}
			b.IDs = in.IDs
			return nil, msgOut{Message: fmt.Sprintf("%d service(s) blocked", len(in.IDs))}, c.SetBlockedServices(ctx, b)
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_dns_info", Description: "Upstream/fallback/bootstrap servers, cache and blocking mode."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, *adguard.DNSInfo, error) {
			d, err := c.DNSInfo(ctx)
			return nil, d, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_test_upstreams", Description: "Test a list of upstream servers (or the configured ones if empty) and report OK/error per server."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Upstreams []string `json:"upstreams,omitempty"`
		}) (*mcp.CallToolResult, adguard.TestUpstreamsResult, error) {
			ups := in.Upstreams
			if len(ups) == 0 {
				d, err := c.DNSInfo(ctx)
				if err != nil {
					return nil, nil, err
				}
				ups = d.UpstreamDNS
			}
			r, err := c.TestUpstreams(ctx, ups)
			return nil, r, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_set_upstreams", Description: "Replace the upstream DNS server list (e.g. https://dns.cloudflare.com/dns-query, tls://1.1.1.1)."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Upstreams []string `json:"upstreams"`
		}) (*mcp.CallToolResult, msgOut, error) {
			return nil, msgOut{Message: "upstreams set"}, c.SetUpstreams(ctx, in.Upstreams)
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_version", Description: "Installed AdGuard Home version and whether a newer release exists."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, map[string]any, error) {
			st, err := c.Status(ctx)
			if err != nil {
				return nil, nil, err
			}
			v, err := c.CheckVersion(ctx)
			if err != nil {
				return nil, nil, err
			}
			return nil, map[string]any{"current": st.Version, "latest": v.NewVersion, "can_autoupdate": v.CanAutoupdate}, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_refresh_filters", Description: "Force re-download of all blocklists. Slow (tens of seconds)."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, msgOut, error) {
			n, err := c.RefreshFilters(ctx)
			return nil, msgOut{Message: fmt.Sprintf("updated %d list(s)", n)}, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_access", Description: "Allowed/disallowed client lists and blocked hostnames."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, *adguard.AccessList, error) {
			a, err := c.Access(ctx)
			return nil, a, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_set_access", Description: "Replace access lists. Omit a field to keep it."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			AllowedClients    *[]string `json:"allowed_clients,omitempty"`
			DisallowedClients *[]string `json:"disallowed_clients,omitempty"`
			BlockedHosts      *[]string `json:"blocked_hosts,omitempty"`
		}) (*mcp.CallToolResult, msgOut, error) {
			a, err := c.Access(ctx)
			if err != nil {
				return nil, msgOut{}, err
			}
			if in.AllowedClients != nil {
				a.AllowedClients = *in.AllowedClients
			}
			if in.DisallowedClients != nil {
				a.DisallowedClients = *in.DisallowedClients
			}
			if in.BlockedHosts != nil {
				a.BlockedHosts = *in.BlockedHosts
			}
			return nil, msgOut{Message: "access lists updated"}, c.SetAccess(ctx, a)
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_safety_features", Description: "State of safe search, safe browsing and parental control."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, map[string]bool, error) {
			ss, err := c.SafeSearch(ctx)
			if err != nil {
				return nil, nil, err
			}
			sb, err := c.ToggleStatus(ctx, "safebrowsing")
			if err != nil {
				return nil, nil, err
			}
			pc, err := c.ToggleStatus(ctx, "parental")
			if err != nil {
				return nil, nil, err
			}
			return nil, map[string]bool{"safesearch": ss.Enabled, "safebrowsing": sb, "parental": pc}, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_set_safety_feature", Description: "Turn safesearch, safebrowsing or parental on/off."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Feature string `json:"feature" jsonschema:"safesearch | safebrowsing | parental"`
			Enabled bool   `json:"enabled"`
		}) (*mcp.CallToolResult, msgOut, error) {
			var err error
			switch in.Feature {
			case "safesearch":
				var ss *adguard.SafeSearch
				if ss, err = c.SafeSearch(ctx); err == nil {
					ss.Enabled = in.Enabled
					err = c.SetSafeSearch(ctx, ss)
				}
			case "safebrowsing", "parental":
				err = c.Toggle(ctx, in.Feature, in.Enabled)
			default:
				return nil, msgOut{}, fmt.Errorf("unknown feature %q", in.Feature)
			}
			return nil, msgOut{Message: in.Feature + " updated"}, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_tls", Description: "Encryption (HTTPS/DoT/DoQ) status and certificate validity."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, *adguard.TLSStatus, error) {
			t, err := c.TLS(ctx)
			return nil, t, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_dhcp", Description: "DHCP server status and leases."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, *adguard.DHCPStatus, error) {
			d, err := c.DHCP(ctx)
			return nil, d, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_add_client", Description: "Create a named persistent client (ids = IPs, CIDRs, MACs, ClientIDs) with optional per-client settings."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in addClientIn) (*mcp.CallToolResult, msgOut, error) {
			p := &adguard.PersistentClient{Name: in.Name, IDs: in.IDs, Tags: in.Tags, Upstreams: in.Upstreams, BlockedServices: in.BlockedServices,
				UseGlobalSettings: !in.NoFilter && len(in.BlockedServices) == 0, FilteringEnabled: !in.NoFilter, UseGlobalServices: len(in.BlockedServices) == 0}
			return nil, msgOut{Message: "added client " + in.Name}, c.AddClient(ctx, p)
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_delete_client", Description: "Delete a named persistent client."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Name string `json:"name"`
		}) (*mcp.CallToolResult, msgOut, error) {
			return nil, msgOut{Message: "deleted client " + in.Name}, c.DeleteClient(ctx, in.Name)
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_log_config", Description: "Query log retention/anonymization and stats window."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, map[string]any, error) {
			l, err := c.QueryLogConfig(ctx)
			if err != nil {
				return nil, nil, err
			}
			st, err := c.StatsConfig(ctx)
			if err != nil {
				return nil, nil, err
			}
			return nil, map[string]any{"querylog": l, "stats": st}, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "adguard_set_log_config", Description: "Set query log retention days, stats window days, and/or client IP anonymization."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			QueryLogDays *int  `json:"querylog_days,omitempty"`
			StatsDays    *int  `json:"stats_days,omitempty"`
			Anonymize    *bool `json:"anonymize_client_ip,omitempty"`
		}) (*mcp.CallToolResult, msgOut, error) {
			const day = int64(86_400_000)
			if in.QueryLogDays != nil || in.Anonymize != nil {
				l, err := c.QueryLogConfig(ctx)
				if err != nil {
					return nil, msgOut{}, err
				}
				if in.QueryLogDays != nil {
					l.IntervalMs = int64(*in.QueryLogDays) * day
				}
				if in.Anonymize != nil {
					l.AnonymizeClientIP = *in.Anonymize
				}
				if err := c.SetQueryLogConfig(ctx, l); err != nil {
					return nil, msgOut{}, err
				}
			}
			if in.StatsDays != nil {
				st, err := c.StatsConfig(ctx)
				if err != nil {
					return nil, msgOut{}, err
				}
				st.IntervalMs = int64(*in.StatsDays) * day
				if err := c.SetStatsConfig(ctx, st); err != nil {
					return nil, msgOut{}, err
				}
			}
			return nil, msgOut{Message: "log config updated"}, nil
		})

	return s
}

func ruleTool(ctx context.Context, c *adguard.Client, hosts []string, mk func(string) string, verb string) (*mcp.CallToolResult, msgOut, error) {
	added := 0
	for _, h := range hosts {
		ok, err := c.AddUserRule(ctx, mk(h))
		if err != nil {
			return nil, msgOut{}, err
		}
		if ok {
			added++
		}
	}
	return nil, msgOut{Message: fmt.Sprintf("%s %d of %d host(s); rules apply after AdGuard rebuilds its filter engine, usually 10-30s", verb, added, len(hosts))}, nil
}

func containsFold(s, sub string) bool {
	return sub != "" && strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
