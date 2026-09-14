# adgctl

CLI and MCP server for [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome). One static binary, talks to the REST API, no dependencies on the AdGuard host.

```
adgctl status                 # version, protection on/off
adgctl stats                  # queries, blocked %, top clients, top blocked
adgctl blocked -n 30          # what was blocked recently, and by which rule
adgctl check mask.icloud.com  # why a host is (not) blocked
adgctl allow mask.icloud.com  # @@||host^$important
adgctl block ads.example.com  # ||host^
adgctl unrule ads.example.com # drop user rules for a host
adgctl off --for 15           # pause protection 15 minutes
adgctl on
adgctl filters                # blocklists, rule counts
adgctl filters --disable "Ultimate"
adgctl refresh                # update blocklists now (blocks until done)
adgctl rewrites               # local DNS overrides
adgctl rewrites add nas.lan 10.0.0.5
adgctl rewrites rm nas.lan
adgctl services               # blocked services (ids); --all lists the catalog
adgctl services block tiktok wechat
adgctl services unblock tiktok
adgctl upstreams              # upstream / fallback / bootstrap / cache
adgctl upstreams --test
adgctl upstreams --set https://dns.cloudflare.com/dns-query,tls://1.1.1.1
adgctl version                # AdGuard version + update check (--update)
adgctl clients
adgctl raw querylog?limit=5   # any /control endpoint
adgctl mcp                    # MCP server over stdio
```

Add `--json` to any command for machine-readable output.

## Install

```
go install github.com/laurenschristian/adgctl@latest
```

Or grab a binary from [Releases](https://github.com/laurenschristian/adgctl/releases).

## Configure

Flags, then env, then a config file (`~/.config/adgctl/config.yaml` on Linux, `~/Library/Application Support/adgctl/config.yaml` on macOS, or `$ADGCTL_CONFIG`).

```
adgctl init --url http://10.0.0.2:3000 --user admin --password-cmd "security find-generic-password -s adguard -w"
```

`password-cmd` is any shell command that prints the password, so the secret can live in a keychain, `pass`, `op read`, `bw get password`, or sops. `--password` stores it in plain text with mode 0600 if you prefer.

Env: `ADG_URL`, `ADG_USER`, `ADG_PASS`, `ADG_PASS_CMD`, `ADGCTL_CONFIG`.

## MCP

`adgctl mcp` exposes the same operations as tools: `adguard_status`, `adguard_stats`, `adguard_query_log`, `adguard_check_host`, `adguard_allow`, `adguard_block`, `adguard_unrule`, `adguard_user_rules`, `adguard_filters`, `adguard_set_filter`, `adguard_protection_on`, `adguard_protection_off`, `adguard_clients`, `adguard_rewrites`, `adguard_add_rewrite`, `adguard_delete_rewrite`, `adguard_blocked_services`, `adguard_set_blocked_services`, `adguard_dns_info`, `adguard_test_upstreams`, `adguard_set_upstreams`, `adguard_version`, `adguard_refresh_filters`.

Claude Code:

```
claude mcp add adguard -- adgctl mcp
```

Any client that speaks stdio MCP (Cursor, Claude Desktop, Zed) works the same: command `adgctl`, args `["mcp"]`, and the `ADG_*` env vars or a config file.

Ask things like "why is quickbooks failing on the office network" and the agent can check the query log, find the blocked host, and add an allow rule.

## Coverage

Wraps the endpoints people actually touch: status, stats, query log, protection toggle, user rules, check_host, blocklists (list/enable/disable/refresh), DNS rewrites, blocked services, upstream config and test, clients (read), version and update. Everything else is one `adgctl raw <path>` away. Not wrapped: DHCP, TLS, access lists, safe search, parental, client CRUD.

## Notes

- Allow rules use `$important` so they beat every blocklist.
- Saving user rules makes AdGuard rebuild its whole filter engine; with a few million rules that takes 10-30s. `allow` and `block` poll `check_host` and return once the rule is live (45s cap). A blocked answer may also stay cached for `blocked_response_ttl` (10s default).
- `off --for 0` disables protection until you turn it back on. Check `status` if blocking ever looks dead: an indefinite off is easy to forget.

MIT.
