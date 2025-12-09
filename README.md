# Callback Guard

Callback Guard is a small, focused HTTP proxy designed to protect services that need to perform outgoing HTTP requests
on behalf of incoming callbacks or webhooks. It prevents requests from reaching private or otherwise sensitive network
ranges unless explicitly allowed, and offers a simple way to add request-level protections without changing application
code.

## Why this exists

- Many applications receive callbacks or webhooks that include URLs or hosts to fetch. If those URLs are not validated,
  they can be abused to make requests to internal services (SSRF) or other protected networks.
- Callback Guard provides a single, auditable network boundary that enforces IP and host-level allowlists and optional
  basic authentication, making it easier to safely handle external callback-driven requests.
- A lot of projects need to implement HTTP callbacks but their underlying tech or framework makes IP filtering difficult
  or awkward to implement (for example, Laravel and other web frameworks often lack simple, centralized outbound IP
  filtering for application-level HTTP clients). Callback Guard offloads that responsibility to a dedicated proxy so
  teams don’t have to retrofit complex filtering into their existing stack.

## What it does (high level)

- Acts as an outbound HTTP proxy for services that need to fetch or relay URLs provided by external callbacks.
- Resolves hosts and blocks requests that would reach private/internal IP ranges unless they are explicitly whitelisted.
- Supports a host whitelist to allow certain known destinations even if their resolved IPs would otherwise be blocked.
- Supports a blacklist (denylist) to explicitly block hosts or IP ranges — blacklist rules take precedence over
  whitelist rules.
- Optional basic proxy authentication to restrict who can use the proxy.
- Lightweight, configurable, and can watch and reload configuration at runtime (when enabled).

### Per-user overrides

Callback Guard supports per-user override rules keyed by username. Overrides allow you to define whitelist and blacklist
entries that apply specifically to requests authenticated as a given user. This is useful when different clients or
internal services need distinct outbound rules.

Where to configure:

- Add an `overrides` mapping in your YAML config. Each key is a username (matching the username clients present via
  Proxy Basic auth). The value is an object with `whitelist` and `blacklist` sections using the same `ip` and `host`
  shapes as the global config.

Precedence rules (applied in this exact order):

1. User-scoped host blacklist (deny)
2. User-scoped IP blacklist (deny)
3. User-scoped host whitelist (allow)
4. User-scoped IP whitelist (allow)
5. Global host blacklist (deny)
6. Global IP blacklist (deny)
7. Global host whitelist (allow)
8. Global IP whitelist (allow)

Notes on semantics:

- Blacklists are conservative: if any resolved IP for a hostname appears in a blacklist (user or global), the request is
  denied.
- Host patterns without an explicit port only match when the destination port is 80 or 443 (same as global host rules).
- Per-user overrides are considered only when the request is authenticated and the username matches an entry in
  `overrides`.
  If the proxy is running without auth enabled, `overrides` has no effect.

Example per-user overrides (config.yaml):

```yaml
listen: ":8080"
handle_redirect: true
auth:
  alice: "$2a$10$..."   # bcrypt hash for user "alice"
  bob: "$2a$10$..."

whitelist:
  ip: [ "203.0.113.0/24" ]
  host: [ "public.example.com" ]
blacklist:
  ip: [ "10.0.0.0/8", "192.168.0.0/16" ]
  host: [ "*.malicious.local" ]

overrides:
  alice:
    whitelist:
      host: [ "internal.example.com" ]
      ip: [ "10.5.7.8" ]
    blacklist:
      host: [ "danger.internal.local" ]
  bob:
    whitelist:
      host: [ "staging.example.local:8080" ]
    blacklist:
      ip: [ "10.0.0.0/8" ]
```

Behavior examples:

- A request authenticated as `alice` to `internal.example.com:80` will be allowed by the user host whitelist even if the
  global policy would block its resolved IPs.
- A request authenticated as `bob` to `10.1.2.3` will be denied because `bob`'s user IP blacklist contains `10.0.0.0/8`.
- A request authenticated as `alice` to `danger.internal.local` will be denied due to `alice`'s user host blacklist (
  user-level
  blacklist takes precedence over user whitelist and global lists).

## CLI and flags

The proxy has two main flags that control configuration loading and live reloads:

- `--config <path>`: path to a YAML config file. This flag is optional when not using `--watch`.
- `--watch`: enable watching the config file and live-reloading on changes. When `--watch` is used, `--config` is
  required.

Behavior summary:

- If `--config` is omitted and `--watch` is not set, the proxy runs with a small in-memory default config:
    - `listen: ":8080"`
    - no auth configured
    - empty whitelist and blacklist lists

  This mode is convenient for quick local testing, but production use should provide a config file.

- If `--config` is provided, the proxy loads that YAML and applies its rules (and `--watch` can be used to reload it).
- If `--watch` is set but `--config` is not provided, the program will exit with an error — live reload requires a file
  to watch.

Examples:

- Run with default in-memory config (no file):

```powershell
.\callback-guard.exe
```

- Run with a config file (no watching):

```powershell
.\callback-guard.exe -config .\config.yaml
```

- Run with a config file and live reload:

```powershell
.\callback-guard.exe -config .\config.yaml -watch
```

## Blacklist (denylist)

The blacklist provides a way to explicitly deny destinations even if they would otherwise be permitted by the whitelist.
It accepts the same configuration shapes and host-pattern semantics as the whitelist:

- `blacklist.ip` — list of IPs or CIDR ranges (e.g. `10.0.0.0/8`, `192.0.2.1`).
- `blacklist.host` — list of host patterns. Patterns use simple wildcard matching (same rules as the whitelist).

Host pattern semantics:

- A pattern without a port (e.g. `internal.example.com` or `*.example.com`) only matches when the destination port is 80
  or 443.
- A pattern with an explicit port (e.g. `example.com:8080` or `*.example.com:8443`) matches the host:port combination.

Priority rules:

- Blacklist checks run before whitelist checks. If a host pattern matches the blacklist or any resolved IP falls within
  a
  blacklisted CIDR, the request is denied immediately regardless of whitelist entries.

## When to use it

- You accept external callbacks or webhooks that include user-provided URLs and you need to fetch or validate those URLs
  safely.
- You want a simple network-level guard to prevent server-side request forgery (SSRF) without changing application code.
- Your framework or runtime makes it difficult to centrally enforce outbound IP restrictions and you prefer an
  opinionated proxy to handle that for you.

## Example usage

1) Minimal config (config.yaml)

   ```yaml
   listen: ":8080"
   handle_redirect: true
   whitelist:
     ip: [ ]        # CIDR or IP entries to allow even if private
     host: [ "example.com" ] # host patterns allowed even if they resolve to private IPs
   # auth: false    # or provide a map of username:bcrypt-hash
   ```

2) Config with blacklist example

   ```yaml
   listen: ":8080"
   handle_redirect: true
   whitelist:
     ip: [ "203.0.113.0/24" ]
     host: [ "allowed.example.com", "*.partners.example.org" ]
   blacklist:
     ip: [ "10.0.0.0/8", "192.168.0.0/16" ]
     host: [ "bad.example.com", "*.malicious.local" ]
   # auth: { "proxyuser": "$2a$10$..." }
   ```

   Notes:
    - In the example above, any request that matches `blacklist.host` or resolves to an IP in `blacklist.ip` will be
      rejected even if the same host or IP also appears in the whitelist. This enforces a deny-first model for
      explicitly
      blocked destinations.

3) Start the proxy

   Run the binary pointing at your config:
   ```shell
   callback-guard -config config.yaml
   ```

4) Generate a bcrypt password hash (for auth entries)

   The binary includes a helper to generate bcrypt hashes for credentials used in the config. For an interactive prompt
   or
   piping a password:

    - Interactive (prompts for password):
      ```shell
      callback-guard bcrypt
      ```

    - From a pipeline (echoing a password):
      ```shell
      echo "supersecret" | callback-guard bcrypt
      ```
      Add the produced hash into your config under the `auth` map.

## Notes and best practices

- Treat this proxy as a safety boundary: combine host and IP allowlists with application-level validations when
  possible.
- Keep an audit log of which services are permitted to use the proxy (combine with network-level controls and
  authentication).
- The project intentionally focuses on request safety and simplicity rather than being a full-featured forward proxy.
- Use the blacklist to explicitly deny known-bad hosts or private ranges you want to ensure are never contacted even if
  a whitelist might otherwise permit them.

## License

This project is licensed under the MIT License — see [LICENSE](./LICENSE) for details.
