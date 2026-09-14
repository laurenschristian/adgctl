package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/laurenschristian/adgctl/internal/adguard"
)

// importEntry is what `eerox export --adguard` prints: one named client per device.
type importEntry struct {
	Name string   `json:"name"`
	IDs  []string `json:"ids"`
	Tags []string `json:"tags,omitempty"`
}

func clientImportCmd() *cobra.Command {
	var file string
	var update, dryRun bool
	c := &cobra.Command{
		Use:   "import",
		Short: "Create named clients from JSON [{name, ids, tags}] on stdin or --file (eerox export --adguard)",
		RunE: func(_ *cobra.Command, _ []string) error {
			var r io.Reader = os.Stdin
			if file != "" {
				f, err := os.Open(file)
				if err != nil {
					return err
				}
				defer func() { _ = f.Close() }()
				r = f
			}
			var entries []importEntry
			if err := json.NewDecoder(r).Decode(&entries); err != nil {
				return fmt.Errorf("decode: %w", err)
			}
			ctx, cancel := ctx()
			defer cancel()
			existing, err := client.Clients(ctx)
			if err != nil {
				return err
			}
			byName, byID := map[string]bool{}, map[string]string{}
			for _, e := range existing.Clients {
				name, _ := e["name"].(string)
				byName[name] = true
				if ids, ok := e["ids"].([]any); ok {
					for _, id := range ids {
						if s, ok := id.(string); ok {
							byID[strings.ToLower(s)] = name
						}
					}
				}
			}
			added, updated, skipped := 0, 0, 0
			for _, e := range entries {
				if e.Name == "" || len(e.IDs) == 0 {
					skipped++
					continue
				}
				p := &adguard.PersistentClient{Name: e.Name, IDs: e.IDs, Tags: e.Tags,
					UseGlobalSettings: true, FilteringEnabled: true, UseGlobalServices: true}
				switch {
				case byName[e.Name]:
					if !update {
						skipped++
						continue
					}
					if !dryRun {
						if err := client.UpdateClient(ctx, e.Name, p); err != nil {
							return fmt.Errorf("%s: %w", e.Name, err)
						}
					}
					updated++
					fmt.Println("update", e.Name, strings.Join(e.IDs, ","))
				default:
					if owner := claimedBy(byID, e.IDs); owner != "" {
						fmt.Printf("skip %s: %s already belongs to %q\n", e.Name, strings.Join(e.IDs, ","), owner)
						skipped++
						continue
					}
					if !dryRun {
						if err := client.AddClient(ctx, p); err != nil {
							return fmt.Errorf("%s: %w", e.Name, err)
						}
					}
					for _, id := range e.IDs {
						byID[strings.ToLower(id)] = e.Name
					}
					byName[e.Name] = true
					added++
					fmt.Println("add", e.Name, strings.Join(e.IDs, ","))
				}
			}
			mode := ""
			if dryRun {
				mode = " (dry run)"
			}
			fmt.Printf("added %d, updated %d, skipped %d%s\n", added, updated, skipped, mode)
			return nil
		},
	}
	c.Flags().StringVar(&file, "file", "", "read JSON from a file instead of stdin")
	c.Flags().BoolVar(&update, "update", false, "overwrite ids/tags of clients that already exist by name")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "print the plan, change nothing")
	return c
}

func claimedBy(byID map[string]string, ids []string) string {
	for _, id := range ids {
		if owner, ok := byID[strings.ToLower(id)]; ok {
			return owner
		}
	}
	return ""
}
