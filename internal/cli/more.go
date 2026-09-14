package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/laurenschristian/adgctl/internal/adguard"
)

func rewritesCmd() *cobra.Command {
	c := &cobra.Command{Use: "rewrites", Short: "DNS rewrites (local overrides)",
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := ctx()
			defer cancel()
			r, err := client.Rewrites(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return emit(r)
			}
			rows := make([][]string, 0, len(r))
			for _, x := range r {
				rows = append(rows, []string{x.Domain, x.Answer})
			}
			table(rows)
			return nil
		}}
	c.AddCommand(
		&cobra.Command{Use: "add <domain> <answer>", Short: "Add a rewrite (answer = IP or CNAME target)", Args: cobra.ExactArgs(2),
			RunE: func(_ *cobra.Command, a []string) error {
				ctx, cancel := ctx()
				defer cancel()
				if err := client.AddRewrite(ctx, adguard.Rewrite{Domain: a[0], Answer: a[1]}); err != nil {
					return err
				}
				fmt.Println("added", a[0], "->", a[1])
				return nil
			}},
		&cobra.Command{Use: "rm <domain> [answer]", Short: "Remove rewrites for a domain", Args: cobra.RangeArgs(1, 2),
			RunE: func(_ *cobra.Command, a []string) error {
				ctx, cancel := ctx()
				defer cancel()
				all, err := client.Rewrites(ctx)
				if err != nil {
					return err
				}
				n := 0
				for _, r := range all {
					if r.Domain == a[0] && (len(a) == 1 || r.Answer == a[1]) {
						if err := client.DeleteRewrite(ctx, r); err != nil {
							return err
						}
						n++
					}
				}
				fmt.Printf("removed %d\n", n)
				return nil
			}},
	)
	return c
}

func servicesCmd() *cobra.Command {
	var all bool
	c := &cobra.Command{Use: "services", Short: "Blocked services (per-app blocking)",
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := ctx()
			defer cancel()
			if all {
				list, err := client.AllServices(ctx)
				if err != nil {
					return err
				}
				if flagJSON {
					return emit(list)
				}
				for _, s := range list {
					fmt.Printf("%-24s %s\n", s.ID, s.Name)
				}
				return nil
			}
			b, err := client.BlockedServices(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return emit(b)
			}
			fmt.Println(strings.Join(b.IDs, "\n"))
			return nil
		}}
	c.Flags().BoolVar(&all, "all", false, "list every service id AdGuard knows")
	c.AddCommand(
		&cobra.Command{Use: "block <id>...", Short: "Block services by id (see --all)", Args: cobra.MinimumNArgs(1),
			RunE: func(_ *cobra.Command, a []string) error { return editServices(a, true) }},
		&cobra.Command{Use: "unblock <id>...", Short: "Unblock services by id", Args: cobra.MinimumNArgs(1),
			RunE: func(_ *cobra.Command, a []string) error { return editServices(a, false) }},
	)
	return c
}

func editServices(ids []string, block bool) error {
	ctx, cancel := ctx()
	defer cancel()
	b, err := client.BlockedServices(ctx)
	if err != nil {
		return err
	}
	set := map[string]bool{}
	for _, id := range b.IDs {
		set[id] = true
	}
	for _, id := range ids {
		if block {
			set[id] = true
		} else {
			delete(set, id)
		}
	}
	b.IDs = b.IDs[:0]
	for id := range set {
		b.IDs = append(b.IDs, id)
	}
	if err := client.SetBlockedServices(ctx, b); err != nil {
		return err
	}
	fmt.Printf("%d service(s) blocked\n", len(b.IDs))
	return nil
}

func upstreamsCmd() *cobra.Command {
	var set []string
	var test bool
	c := &cobra.Command{Use: "upstreams", Short: "Show, test, or set upstream DNS servers",
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if len(set) > 0 {
				if err := client.SetUpstreams(ctx, set); err != nil {
					return err
				}
				fmt.Println("upstreams set")
			}
			d, err := client.DNSInfo(ctx)
			if err != nil {
				return err
			}
			if test {
				res, err := client.TestUpstreams(ctx, d.UpstreamDNS)
				if err != nil {
					return err
				}
				if flagJSON {
					return emit(res)
				}
				for u, r := range res {
					fmt.Printf("%-45s %s\n", u, r)
				}
				return nil
			}
			if flagJSON {
				return emit(d)
			}
			table([][]string{
				{"upstream", strings.Join(d.UpstreamDNS, ", ")},
				{"fallback", strings.Join(d.FallbackDNS, ", ")},
				{"bootstrap", strings.Join(d.BootstrapDNS, ", ")},
				{"mode", d.UpstreamMode},
				{"cache", fmt.Sprintf("enabled=%v optimistic=%v", d.CacheEnabled, d.CacheOptimist)},
				{"dnssec", fmt.Sprint(d.EnableDNSSEC)},
				{"blocking_mode", d.BlockingMode},
			})
			return nil
		}}
	c.Flags().StringSliceVar(&set, "set", nil, "replace upstream list, e.g. --set https://dns.cloudflare.com/dns-query,tls://1.1.1.1")
	c.Flags().BoolVar(&test, "test", false, "test each configured upstream")
	return c
}

func versionCmd() *cobra.Command {
	var update bool
	c := &cobra.Command{Use: "version", Short: "AdGuard Home version and available update (--update to apply)",
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			st, err := client.Status(ctx)
			if err != nil {
				return err
			}
			v, err := client.CheckVersion(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return emit(map[string]any{"current": st.Version, "check": v})
			}
			fmt.Println("current:", st.Version)
			if v.NewVersion == "" || v.NewVersion == st.Version {
				fmt.Println("up to date")
				return nil
			}
			fmt.Println("available:", v.NewVersion, " can_autoupdate:", v.CanAutoupdate)
			if update {
				if !v.CanAutoupdate {
					return fmt.Errorf("this install cannot self-update (docker image: pull a new tag instead)")
				}
				if err := client.Update(ctx); err != nil {
					return err
				}
				fmt.Println("update started; AdGuard restarts itself")
			}
			return nil
		}}
	c.Flags().BoolVar(&update, "update", false, "apply the update if AdGuard can self-update")
	return c
}
