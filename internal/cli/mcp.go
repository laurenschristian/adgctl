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
	return nil, msgOut{Message: fmt.Sprintf("%s %d of %d host(s); rules apply within a few seconds", verb, added, len(hosts))}, nil
}

func containsFold(s, sub string) bool {
	return sub != "" && strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
