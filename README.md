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
- Supports a blacklist (denylist) to explicitly block hosts or IP ranges — blacklist rules take precedence over whitelist rules.
- Optional basic proxy authentication to restrict who can use the proxy.
- Lightweight, configurable, and can watch and reload configuration at runtime (when enabled).

### Blacklist (denylist)

The blacklist provides a way to explicitly deny destinations even if they would otherwise be permitted by the whitelist.
It accepts the same configuration shapes and host-pattern semantics as the whitelist:

- `blacklist.ip` — list of IPs or CIDR ranges (e.g. `10.0.0.0/8`, `192.0.2.1`).
- `blacklist.host` — list of host patterns. Patterns use simple wildcard matching (same rules as the whitelist).

Host pattern semantics:
- A pattern without a port (e.g. `internal.example.com` or `*.example.com`) only matches when the destination port is 80 or 443.
- A pattern with an explicit port (e.g. `example.com:8080` or `*.example.com:8443`) matches the host:port combination.

Priority rules:
- Blacklist checks run before whitelist checks. If a host pattern matches the blacklist or any resolved IP falls within a
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
     rejected even if the same host or IP also appears in the whitelist. This enforces a deny-first model for explicitly
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
