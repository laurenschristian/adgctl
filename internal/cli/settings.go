package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/laurenschristian/adgctl/internal/adguard"
)

func accessCmd() *cobra.Command {
	var allow, deny, hosts []string
	c := &cobra.Command{Use: "access", Short: "Client access lists (allowed / disallowed clients, blocked hostnames)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := ctx()
			defer cancel()
			if cmd.Flags().Changed("allow") || cmd.Flags().Changed("deny") || cmd.Flags().Changed("hosts") {
				a, err := client.Access(ctx)
				if err != nil {
					return err
				}
				if cmd.Flags().Changed("allow") {
					a.AllowedClients = allow
				}
				if cmd.Flags().Changed("deny") {
					a.DisallowedClients = deny
				}
				if cmd.Flags().Changed("hosts") {
					a.BlockedHosts = hosts
				}
				if err := client.SetAccess(ctx, a); err != nil {
					return err
				}
				fmt.Println("access lists updated")
			}
			a, err := client.Access(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return emit(a)
			}
			table([][]string{
				{"allowed clients", strings.Join(a.AllowedClients, ", ")},
				{"disallowed clients", strings.Join(a.DisallowedClients, ", ")},
				{"blocked hosts", strings.Join(a.BlockedHosts, ", ")},
			})
			return nil
		}}
	c.Flags().StringSliceVar(&allow, "allow", nil, "replace allowed clients (IPs/CIDRs/ClientIDs); empty = everyone")
	c.Flags().StringSliceVar(&deny, "deny", nil, "replace disallowed clients")
	c.Flags().StringSliceVar(&hosts, "hosts", nil, "replace blocked hostnames")
	return c
}

func safesearchCmd() *cobra.Command {
	c := &cobra.Command{Use: "safesearch [on|off]", Short: "Enforce safe search on Google, YouTube, Bing, DDG, etc.", Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, a []string) error {
			ctx, cancel := ctx()
			defer cancel()
			s, err := client.SafeSearch(ctx)
			if err != nil {
				return err
			}
			if len(a) == 1 {
				s.Enabled = a[0] == "on"
				if err := client.SetSafeSearch(ctx, s); err != nil {
					return err
				}
			}
			if flagJSON {
				return emit(s)
			}
			fmt.Printf("safesearch: %s\n", onOff(s.Enabled))
			return nil
		}}
	return c
}

func toggleCmd(feature, short string) *cobra.Command {
	return &cobra.Command{Use: feature + " [on|off]", Short: short, Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, a []string) error {
			ctx, cancel := ctx()
			defer cancel()
			if len(a) == 1 {
				if err := client.Toggle(ctx, feature, a[0] == "on"); err != nil {
					return err
				}
			}
			on, err := client.ToggleStatus(ctx, feature)
			if err != nil {
				return err
			}
			if flagJSON {
				return emit(map[string]bool{"enabled": on})
			}
			fmt.Printf("%s: %s\n", feature, onOff(on))
			return nil
		}}
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func tlsCmd() *cobra.Command {
	return &cobra.Command{Use: "tls", Short: "Encryption status (HTTPS, DoT, DoQ) and certificate validity",
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := ctx()
			defer cancel()
			t, err := client.TLS(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return emit(t)
			}
			table([][]string{
				{"enabled", fmt.Sprint(t.Enabled)},
				{"server_name", t.ServerName},
				{"https", fmt.Sprintf("port %d force=%v", t.PortHTTPS, t.ForceHTTPS)},
				{"dot/doq", fmt.Sprintf("%d / %d", t.PortDoT, t.PortDoQ)},
				{"cert", fmt.Sprintf("valid=%v chain=%v key=%v expires=%s", t.ValidCert, t.ValidChain, t.ValidKey, t.NotAfter)},
				{"plain dns", fmt.Sprint(t.ServePlainDNS)},
			})
			if t.WarningMessage != "" {
				fmt.Println("warning:", t.WarningMessage)
			}
			return nil
		}}
}

func dhcpCmd() *cobra.Command {
	return &cobra.Command{Use: "dhcp", Short: "DHCP server status and leases (read-only)",
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := ctx()
			defer cancel()
			d, err := client.DHCP(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return emit(d)
			}
			fmt.Printf("dhcp: %s  interface: %s  leases: %d  static: %d\n", onOff(d.Enabled), d.Interface, len(d.Leases), len(d.StaticLeases))
			rows := [][]string{}
			for _, l := range append(d.StaticLeases, d.Leases...) {
				rows = append(rows, []string{l.IP, l.MAC, l.Hostname, l.Expires})
			}
			table(rows)
			return nil
		}}
}

func clientCmd() *cobra.Command {
	c := &cobra.Command{Use: "client", Short: "Manage persistent (named) clients"}
	var ids, tags, upstreams, services []string
	var noFilter bool
	add := &cobra.Command{Use: "add <name>", Short: "Create a named client from --ids", Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, a []string) error {
			ctx, cancel := ctx()
			defer cancel()
			p := &adguard.PersistentClient{Name: a[0], IDs: ids, Tags: tags, Upstreams: upstreams, BlockedServices: services,
				UseGlobalSettings: !noFilter && len(services) == 0, FilteringEnabled: !noFilter, UseGlobalServices: len(services) == 0}
			if err := client.AddClient(ctx, p); err != nil {
				return err
			}
			fmt.Println("added client", a[0])
			return nil
		}}
	add.Flags().StringSliceVar(&ids, "ids", nil, "IPs, CIDRs, MACs or ClientIDs (required)")
	add.Flags().StringSliceVar(&tags, "tags", nil, "tags, e.g. device_phone,user_child")
	add.Flags().StringSliceVar(&upstreams, "upstreams", nil, "per-client upstream servers")
	add.Flags().StringSliceVar(&services, "block-services", nil, "per-client blocked service ids")
	add.Flags().BoolVar(&noFilter, "no-filter", false, "bypass filtering for this client")
	_ = add.MarkFlagRequired("ids")

	rm := &cobra.Command{Use: "rm <name>", Short: "Delete a named client", Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, a []string) error {
			ctx, cancel := ctx()
			defer cancel()
			if err := client.DeleteClient(ctx, a[0]); err != nil {
				return err
			}
			fmt.Println("deleted client", a[0])
			return nil
		}}
	c.AddCommand(add, rm, clientImportCmd())
	return c
}

func logConfigCmd() *cobra.Command {
	var days int
	var anon string
	var clearLog bool
	c := &cobra.Command{Use: "logconfig", Short: "Query log retention and anonymization",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := ctx()
			defer cancel()
			if clearLog {
				if err := client.ClearQueryLog(ctx); err != nil {
					return err
				}
				fmt.Println("query log cleared")
			}
			l, err := client.QueryLogConfig(ctx)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("days") || cmd.Flags().Changed("anonymize") {
				if cmd.Flags().Changed("days") {
					l.IntervalMs = int64(days) * 24 * int64(time.Hour/time.Millisecond)
				}
				if cmd.Flags().Changed("anonymize") {
					l.AnonymizeClientIP = anon == "on"
				}
				if err := client.SetQueryLogConfig(ctx, l); err != nil {
					return err
				}
			}
			if flagJSON {
				return emit(l)
			}
			fmt.Printf("enabled=%v retention=%dd anonymize_client_ip=%v\n", l.Enabled, l.IntervalMs/86_400_000, l.AnonymizeClientIP)
			return nil
		}}
	c.Flags().IntVar(&days, "days", 0, "retention in days (1, 7, 30, 90)")
	c.Flags().StringVar(&anon, "anonymize", "", "on|off: mask client IPs in the log")
	c.Flags().BoolVar(&clearLog, "clear", false, "delete the whole query log")
	return c
}

func statsConfigCmd() *cobra.Command {
	var days int
	var reset bool
	c := &cobra.Command{Use: "statsconfig", Short: "Statistics window",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := ctx()
			defer cancel()
			if reset {
				if err := client.ResetStats(ctx); err != nil {
					return err
				}
				fmt.Println("stats reset")
			}
			l, err := client.StatsConfig(ctx)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("days") {
				l.IntervalMs = int64(days) * 24 * int64(time.Hour/time.Millisecond)
				if err := client.SetStatsConfig(ctx, l); err != nil {
					return err
				}
			}
			if flagJSON {
				return emit(l)
			}
			fmt.Printf("enabled=%v window=%dd\n", l.Enabled, l.IntervalMs/86_400_000)
			return nil
		}}
	c.Flags().IntVar(&days, "days", 0, "window in days (1, 7, 30, 90)")
	c.Flags().BoolVar(&reset, "reset", false, "zero the statistics")
	return c
}
