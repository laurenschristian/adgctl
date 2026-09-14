// Package cli wires the cobra commands.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/laurenschristian/adgctl/internal/adguard"
	"github.com/laurenschristian/adgctl/internal/config"
)

var (
	Version = "dev"

	flagURL  string
	flagUser string
	flagJSON bool

	client *adguard.Client
)

func Root() *cobra.Command {
	root := &cobra.Command{
		Use:           "adgctl",
		Short:         "CLI and MCP server for AdGuard Home",
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if cmd.Name() == "init" || cmd.Name() == "help" {
				return nil
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if flagURL != "" {
				cfg.URL = flagURL
			}
			if flagUser != "" {
				cfg.Username = flagUser
			}
			if err := cfg.Resolve(); err != nil {
				return err
			}
			client = adguard.New(cfg.URL, cfg.Username, cfg.Password)
			return nil
		},
	}
	root.PersistentFlags().StringVar(&flagURL, "url", "", "AdGuard Home URL (env ADG_URL)")
	root.PersistentFlags().StringVar(&flagUser, "user", "", "username (env ADG_USER)")
	root.PersistentFlags().BoolVar(&flagJSON, "json", false, "print raw JSON")

	root.AddCommand(
		initCmd(), statusCmd(), statsCmd(), logCmd(), blockedCmd(),
		onCmd(), offCmd(), checkCmd(), allowCmd(), blockCmd(), unruleCmd(),
		rulesCmd(), filtersCmd(), refreshCmd(), clientsCmd(), rawCmd(), mcpCmd(),
		rewritesCmd(), servicesCmd(), upstreamsCmd(), versionCmd(),
	)
	return root
}

func ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

func emit(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func table(rows [][]string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	for _, r := range rows {
		fmt.Fprintln(w, strings.Join(r, "\t"))
	}
	w.Flush()
}

func initCmd() *cobra.Command {
	var url, user, pass, passCmd string
	c := &cobra.Command{
		Use:   "init",
		Short: "Write " + config.Path(),
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg := &config.Config{URL: url, Username: user, Password: pass, PasswordCmd: passCmd}
			if pass != "" && passCmd != "" {
				return fmt.Errorf("use --password or --password-cmd, not both")
			}
			if err := config.Save(cfg); err != nil {
				return err
			}
			fmt.Println("wrote", config.Path())
			return nil
		},
	}
	c.Flags().StringVar(&url, "url", "http://127.0.0.1:3000", "AdGuard Home URL")
	c.Flags().StringVar(&user, "user", "", "username")
	c.Flags().StringVar(&pass, "password", "", "password (stored in plain text, 0600)")
	c.Flags().StringVar(&passCmd, "password-cmd", "", `shell command that prints the password, e.g. "security find-generic-password -s adguard -w"`)
	_ = c.MarkFlagRequired("user")
	return c
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use: "status", Short: "Server version and protection state",
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := ctx()
			defer cancel()
			s, err := client.Status(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return emit(s)
			}
			state := "on"
			if !s.ProtectionEnabled {
				state = "OFF"
			}
			table([][]string{
				{"version", s.Version},
				{"protection", state},
				{"running", fmt.Sprint(s.Running)},
				{"dns", fmt.Sprintf("%s:%d", firstNonLoopback(s.DNSAddresses), s.DNSPort)},
			})
			return nil
		},
	}
}

func firstNonLoopback(addrs []string) string {
	for _, a := range addrs {
		if !strings.HasPrefix(a, "127.") && a != "::1" && !strings.Contains(a, "%") && !strings.HasPrefix(a, "172.") {
			return a
		}
	}
	if len(addrs) > 0 {
		return addrs[0]
	}
	return "?"
}

func statsCmd() *cobra.Command {
	return &cobra.Command{
		Use: "stats", Short: "Query and block counts, top clients and domains",
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := ctx()
			defer cancel()
			s, err := client.Stats(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return emit(s)
			}
			pct := 0.0
			if s.NumDNSQueries > 0 {
				pct = 100 * float64(s.NumBlockedFiltering) / float64(s.NumDNSQueries)
			}
			fmt.Printf("queries %d  blocked %d (%.1f%%)  avg %.1f ms\n\n", s.NumDNSQueries, s.NumBlockedFiltering, pct, s.AvgProcessingTime*1000)
			fmt.Println("top clients")
			table(topRows(s.TopClients, 8))
			fmt.Println("\ntop blocked")
			table(topRows(s.TopBlocked, 10))
			return nil
		},
	}
}

func topRows(m []map[string]int, n int) [][]string {
	var rows [][]string
	for i, e := range m {
		if i >= n {
			break
		}
		for k, v := range e {
			rows = append(rows, []string{"  " + k, fmt.Sprint(v)})
		}
	}
	return rows
}

func logCmd() *cobra.Command {
	var limit int
	var search string
	c := &cobra.Command{
		Use: "log", Short: "Recent queries (optionally filtered by --search)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return printLog(limit, search, "")
		},
	}
	c.Flags().IntVarP(&limit, "limit", "n", 50, "entries")
	c.Flags().StringVarP(&search, "search", "s", "", "domain or client substring")
	return c
}

func blockedCmd() *cobra.Command {
	var limit int
	var search string
	c := &cobra.Command{
		Use: "blocked", Short: "Recent blocked queries",
		RunE: func(_ *cobra.Command, _ []string) error {
			return printLog(limit, search, "blocked")
		},
	}
	c.Flags().IntVarP(&limit, "limit", "n", 50, "entries")
	c.Flags().StringVarP(&search, "search", "s", "", "domain or client substring")
	return c
}

func printLog(limit int, search, status string) error {
	ctx, cancel := ctx()
	defer cancel()
	l, err := client.QueryLog(ctx, limit, search, status)
	if err != nil {
		return err
	}
	if flagJSON {
		return emit(l.Data)
	}
	rows := make([][]string, 0, len(l.Data))
	for _, e := range l.Data {
		t := e.Time
		if len(t) >= 19 {
			t = t[11:19]
		}
		rule := ""
		if len(e.Rules) > 0 {
			rule = e.Rules[0].Text
		}
		rows = append(rows, []string{t, e.Client, e.Question.Name, e.Reason, rule})
	}
	table(rows)
	return nil
}

func onCmd() *cobra.Command {
	return &cobra.Command{
		Use: "on", Short: "Enable protection",
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := ctx()
			defer cancel()
			if err := client.SetProtection(ctx, true, 0); err != nil {
				return err
			}
			fmt.Println("protection on")
			return nil
		},
	}
}

func offCmd() *cobra.Command {
	var minutes int
	c := &cobra.Command{
		Use: "off", Short: "Disable protection (temporarily with --for)",
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := ctx()
			defer cancel()
			if err := client.SetProtection(ctx, false, int64(minutes)*60_000); err != nil {
				return err
			}
			if minutes > 0 {
				fmt.Printf("protection off for %d min\n", minutes)
			} else {
				fmt.Println("protection off until re-enabled")
			}
			return nil
		},
	}
	c.Flags().IntVar(&minutes, "for", 10, "minutes (0 = indefinitely)")
	return c
}

func checkCmd() *cobra.Command {
	return &cobra.Command{
		Use: "check <host>", Short: "Show how a host would be filtered and by which rule", Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			ctx, cancel := ctx()
			defer cancel()
			r, err := client.CheckHost(ctx, args[0])
			if err != nil {
				return err
			}
			if flagJSON {
				return emit(r)
			}
			fmt.Println(r.Reason)
			for _, ru := range r.Rules {
				fmt.Printf("  %s  (list %d)\n", ru.Text, ru.FilterListID)
			}
			return nil
		},
	}
}

func allowCmd() *cobra.Command {
	return &cobra.Command{
		Use: "allow <host>...", Short: "Add an allow rule (@@||host^$important)", Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return addRules(args, adguard.AllowRule, "allowed", "NotFilteredWhiteList")
		},
	}
}

func blockCmd() *cobra.Command {
	return &cobra.Command{
		Use: "block <host>...", Short: "Add a block rule (||host^)", Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return addRules(args, adguard.BlockRule, "blocked", "FilteredBlackList")
		},
	}
}

func addRules(hosts []string, mk func(string) string, verb, want string) error {
	ctx, cancel := ctx()
	defer cancel()
	for _, h := range hosts {
		added, err := client.AddUserRule(ctx, mk(h))
		if err != nil {
			return err
		}
		if !added {
			fmt.Println("already present:", h)
			continue
		}
		wctx, wcancel := context.WithTimeout(ctx, 45*time.Second)
		live := client.WaitRule(wctx, h, want)
		wcancel()
		if live {
			fmt.Println(verb, h)
		} else {
			fmt.Println(verb, h, "(rule saved, not yet live after 45s)")
		}
	}
	return nil
}

func unruleCmd() *cobra.Command {
	return &cobra.Command{
		Use: "unrule <host>...", Short: "Remove user rules mentioning a host", Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			ctx, cancel := ctx()
			defer cancel()
			for _, h := range args {
				n, err := client.RemoveUserRule(ctx, h)
				if err != nil {
					return err
				}
				fmt.Printf("%s: removed %d\n", h, n)
			}
			return nil
		},
	}
}

func rulesCmd() *cobra.Command {
	return &cobra.Command{
		Use: "rules", Short: "List user rules",
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := ctx()
			defer cancel()
			st, err := client.FilteringStatus(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return emit(st.UserRules)
			}
			for _, r := range st.UserRules {
				fmt.Println(r)
			}
			return nil
		},
	}
}

func filtersCmd() *cobra.Command {
	var enable, disable string
	c := &cobra.Command{
		Use: "filters", Short: "List blocklists; --enable/--disable by name substring",
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := ctx()
			defer cancel()
			st, err := client.FilteringStatus(ctx)
			if err != nil {
				return err
			}
			if enable != "" || disable != "" {
				want, needle := true, enable
				if disable != "" {
					want, needle = false, disable
				}
				for _, f := range st.Filters {
					if strings.Contains(strings.ToLower(f.Name), strings.ToLower(needle)) {
						if err := client.SetFilterEnabled(ctx, f, want); err != nil {
							return err
						}
						fmt.Printf("%s -> enabled=%v\n", f.Name, want)
					}
				}
				return nil
			}
			if flagJSON {
				return emit(st.Filters)
			}
			rows := make([][]string, 0, len(st.Filters))
			for _, f := range st.Filters {
				state := "off"
				if f.Enabled {
					state = "on"
				}
				rows = append(rows, []string{state, fmt.Sprint(f.RulesCount), f.Name})
			}
			table(rows)
			return nil
		},
	}
	c.Flags().StringVar(&enable, "enable", "", "enable lists whose name contains this")
	c.Flags().StringVar(&disable, "disable", "", "disable lists whose name contains this")
	return c
}

func refreshCmd() *cobra.Command {
	return &cobra.Command{
		Use: "refresh", Short: "Force-update all blocklists",
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			fmt.Println("refreshing lists (this blocks until AdGuard finishes)...")
			n, err := client.RefreshFilters(ctx)
			if err != nil {
				return err
			}
			fmt.Printf("updated %d list(s)\n", n)
			return nil
		},
	}
}

func clientsCmd() *cobra.Command {
	return &cobra.Command{
		Use: "clients", Short: "Known clients (persistent + auto-discovered)",
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := ctx()
			defer cancel()
			cl, err := client.Clients(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return emit(cl)
			}
			rows := [][]string{}
			for _, c := range cl.Clients {
				rows = append(rows, []string{fmt.Sprint(c["ids"]), fmt.Sprint(c["name"]), "persistent"})
			}
			for _, c := range cl.AutoClients {
				rows = append(rows, []string{c.IP, c.Name, c.Source})
			}
			table(rows)
			return nil
		},
	}
}

func rawCmd() *cobra.Command {
	var method, data string
	c := &cobra.Command{
		Use: "raw <path>", Short: "Call any /control/<path> endpoint", Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			ctx, cancel := ctx()
			defer cancel()
			var body *strings.Reader
			if data != "" {
				body = strings.NewReader(data)
			}
			var out []byte
			var err error
			if body != nil {
				out, err = client.Raw(ctx, method, args[0], body)
			} else {
				out, err = client.Raw(ctx, method, args[0], nil)
			}
			os.Stdout.Write(out)
			if len(out) > 0 && out[len(out)-1] != '\n' {
				fmt.Println()
			}
			return err
		},
	}
	c.Flags().StringVarP(&method, "method", "X", "GET", "HTTP method")
	c.Flags().StringVarP(&data, "data", "d", "", "JSON body")
	return c
}
