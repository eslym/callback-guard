package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

// -------------------------
// Config types
// -------------------------

type TimeoutConfig struct {
	Read  string `yaml:"read"`
	Write string `yaml:"write"`
	Idle  string `yaml:"idle"`
}

type WhitelistConfig struct {
	IP   []string `yaml:"ip"`
	Host []string `yaml:"host"`
}

// OverrideEntry Per-user override entry in YAML
type OverrideEntry struct {
	Whitelist WhitelistConfig `yaml:"whitelist"`
	Blacklist WhitelistConfig `yaml:"blacklist"`
}

type Config struct {
	Listen         string                   `yaml:"listen"`
	Auth           interface{}              `yaml:"auth"` // map[string]string | false | null
	HandleRedirect bool                     `yaml:"handle_redirect"`
	Timeout        TimeoutConfig            `yaml:"timeout"`
	Whitelist      WhitelistConfig          `yaml:"whitelist"`
	Blacklist      WhitelistConfig          `yaml:"blacklist"`
	Overrides      map[string]OverrideEntry `yaml:"overrides"`
}

// -------------------------
// Built-in private ranges
// -------------------------

var (
	extraPrivateCIDRs = []string{
		// IPv4
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local
		"100.64.0.0/10",  // CGNAT
		"0.0.0.0/8",      // "this" network
		"224.0.0.0/4",    // multicast
		"240.0.0.0/4",    // reserved
		// IPv6
		"::1/128",   // loopback
		"fc00::/7",  // unique-local
		"fe80::/10", // link-local
	}

	privateNets []*net.IPNet
)

func init() {
	for _, cidr := range extraPrivateCIDRs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatalf("invalid builtin private cidr %q: %v", cidr, err)
		}
		privateNets = append(privateNets, ipnet)
	}
}

// -------------------------
// Helpers: parsing config
// -------------------------

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	return &cfg, nil
}

func parseDurationOrDefault(s string, def time.Duration, name string) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		log.Printf("invalid %s timeout %q, using default %s: %v", name, s, def, err)
		return def
	}
	return d
}

func parseIPWhitelist(list []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, part := range list {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			_, ipnet, err := net.ParseCIDR(part)
			if err != nil {
				log.Fatalf("invalid CIDR in whitelist.ip: %q: %v", part, err)
			}
			nets = append(nets, ipnet)
		} else {
			ip := net.ParseIP(part)
			if ip == nil {
				log.Fatalf("invalid IP in whitelist.ip: %q", part)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			ipnet := &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(bits, bits),
			}
			nets = append(nets, ipnet)
		}
	}
	return nets
}

func parseHostWhitelist(list []string) []string {
	var out []string
	for _, part := range list {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

// -------------------------
// Auth settings
// -------------------------

type AuthSettings struct {
	Enabled bool
	Users   map[string][]byte // username -> bcrypt hash bytes
}

// cfg.Auth: map[string]string | false | null
func buildAuthSettings(raw interface{}) (*AuthSettings, error) {
	if raw == nil {
		return &AuthSettings{Enabled: false, Users: nil}, nil
	}

	switch v := raw.(type) {
	case bool:
		if !v {
			return &AuthSettings{Enabled: false, Users: nil}, nil
		}
		return nil, fmt.Errorf("auth: true is not allowed; use map[username]bcrypt or false")
	case map[string]interface{}:
		users := make(map[string][]byte, len(v))
		for user, hv := range v {
			hs, ok := hv.(string)
			if !ok {
				return nil, fmt.Errorf("auth: hash for user %q must be string", user)
			}
			users[user] = []byte(hs)
		}
		if len(users) == 0 {
			return &AuthSettings{Enabled: false, Users: nil}, nil
		}
		return &AuthSettings{Enabled: true, Users: users}, nil
	default:
		return nil, fmt.Errorf("auth: unsupported type %T (expected map or false)", v)
	}
}

// -------------------------
// Private / whitelist logic
// -------------------------

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip.IsPrivate() {
		return true
	}
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// unified helper that checks if an IP is contained in any of the provided networks
func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func isAllowedIP(ip net.IP, whitelist []*net.IPNet) bool {
	if !isPrivateIP(ip) {
		return true
	}
	return ipInNets(ip, whitelist)
}

func wildcardMatch(pattern, s string) bool {
	ok, err := path.Match(pattern, s)
	if err != nil {
		return false
	}
	return ok
}

// host:port is checked against patterns from host list (whitelist/blacklist).
//
// Semantics:
//   - "*" (no port) matches any host, but ONLY when dst port is 80 or 443.
//   - If pattern has "host:port", it's matched against "host:port" (with wildcard).
//   - If pattern has no ":", it's matched against host only, but ONLY when dst port is 80 or 443.
func hostInList(host, port string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}

	hostport := net.JoinHostPort(host, port)

	for _, pat := range patterns {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}

		if !strings.Contains(pat, ":") {
			// Enforce "only 80/443 when port not specified in pattern"
			if port != "80" && port != "443" {
				continue
			}
			if wildcardMatch(pat, host) {
				return true
			}
			continue
		}

		// Pattern with explicit port
		if wildcardMatch(pat, hostport) {
			return true
		}
	}

	return false
}

// -------------------------
// DNS + dialing
// -------------------------

type UserOverrides struct {
	ipWhitelist   []*net.IPNet
	hostWhitelist []string
	ipBlacklist   []*net.IPNet
	hostBlacklist []string
}

type SafeDialer struct {
	inner         net.Dialer
	ipWhitelist   []*net.IPNet
	hostWhitelist []string
	ipBlacklist   []*net.IPNet
	hostBlacklist []string
	// per-user overrides
	userOverrides map[string]*UserOverrides
}

// Context key for authenticated username
type contextKey string

const userContextKey contextKey = "proxy-user"

func (sd *SafeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", address, err)
	}

	// Try to obtain authenticated username from context
	var ips []net.IP
	user, _ := ctx.Value(userContextKey).(string)
	if user != "" {
		if uo, ok := sd.userOverrides[user]; ok {
			// user host blacklist -> immediate deny
			if hostInList(host, port, uo.hostBlacklist) {
				return nil, fmt.Errorf("host %q is blacklisted for user %s", host, user)
			}

			// Resolve host into IPs (works for IP literal too).
			ips, err = resolveHost(ctx, host)
			if err != nil {
				return nil, err
			}

			// If any resolved IP is blacklisted for user, deny immediately.
			for _, ip := range ips {
				if ipInNets(ip, uo.ipBlacklist) {
					return nil, fmt.Errorf("host %q resolves to blacklisted IP %s for user %s", host, ip.String(), user)
				}
			}

			// User whitelisted host -> allow (fast path)
			if hostInList(host, port, uo.hostWhitelist) {
				return sd.inner.DialContext(ctx, network, address)
			}

			// User IP whitelist -> allow if any resolved IP is allowed per user whitelist
			for _, ip := range ips {
				if isAllowedIP(ip, uo.ipWhitelist) {
					dest := net.JoinHostPort(ip.String(), port)
					return sd.inner.DialContext(ctx, network, dest)
				}
			}
			// user override did not grant or deny -> fallthrough to global checks below using the resolved ips
		}
	}

	// If host pattern explicitly blacklists this host: deny immediately (global blacklist)
	if hostInList(host, port, sd.hostBlacklist) {
		return nil, fmt.Errorf("host %q is blacklisted", host)
	}

	// Resolve host into IPs if we haven't already via user override
	if ips == nil {
		ips, err = resolveHost(ctx, host)
		if err != nil {
			return nil, err
		}
	}

	// If any resolved IP is blacklisted globally, deny immediately (blacklist overrides whitelist).
	for _, ip := range ips {
		if ipInNets(ip, sd.ipBlacklist) {
			return nil, fmt.Errorf("host %q resolves to blacklisted IP %s", host, ip.String())
		}
	}

	// Whitelisted host: allow (fast path) since we've already asserted no blacklisted IPs.
	if hostInList(host, port, sd.hostWhitelist) {
		return sd.inner.DialContext(ctx, network, address)
	}

	for _, ip := range ips {
		if isAllowedIP(ip, sd.ipWhitelist) {
			dest := net.JoinHostPort(ip.String(), port)
			return sd.inner.DialContext(ctx, network, dest)
		}
	}

	return nil, fmt.Errorf("all IPs for host %q are private and not whitelisted", host)
}

func resolveHost(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// -------------------------
// Proxy server
// -------------------------

type ProxyServer struct {
	transport      *http.Transport
	dialer         *SafeDialer
	authEnabled    bool
	authUsers      map[string][]byte // username -> bcrypt hash
	handleRedirect bool
}

func newProxyServer(
	ipWhitelist []*net.IPNet,
	hostWhitelist []string,
	ipBlacklist []*net.IPNet,
	hostBlacklist []string,
	userOverrides map[string]*UserOverrides,
	auth *AuthSettings,
	handleRedirect bool,
) *ProxyServer {
	sd := &SafeDialer{
		inner: net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		ipWhitelist:   ipWhitelist,
		hostWhitelist: hostWhitelist,
		ipBlacklist:   ipBlacklist,
		hostBlacklist: hostBlacklist,
		userOverrides: userOverrides,
	}

	tr := &http.Transport{
		Proxy:               nil, // no upstream proxy
		DialContext:         sd.DialContext,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	var enabled bool
	var users map[string][]byte
	if auth != nil && auth.Enabled && len(auth.Users) > 0 {
		enabled = true
		users = auth.Users
	}

	return &ProxyServer{
		transport:      tr,
		dialer:         sd,
		authEnabled:    enabled,
		authUsers:      users,
		handleRedirect: handleRedirect,
	}
}

func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ok, user := p.checkAuth(w, r)
	if !ok {
		return
	}

	// Attach authenticated username (if any) to the request context so DialContext can consult user overrides.
	if user != "" {
		r = r.WithContext(context.WithValue(r.Context(), userContextKey, user))
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	p.handleHTTP(w, r)
}

// Proxy auth via Proxy-Authorization: Basic <base64(user:pass)>
// returns (ok, username)
func (p *ProxyServer) checkAuth(w http.ResponseWriter, r *http.Request) (bool, string) {
	if !p.authEnabled {
		return true, ""
	}

	h := r.Header.Get("Proxy-Authorization")
	if h == "" {
		w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return false, ""
	}

	const prefix = "Basic "
	if !strings.HasPrefix(h, prefix) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return false, ""
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len(prefix):]))
	if err != nil {
		w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return false, ""
	}

	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return false, ""
	}
	user, pass := parts[0], parts[1]

	hash, ok := p.authUsers[user]
	if !ok || bcrypt.CompareHashAndPassword(hash, []byte(pass)) != nil {
		w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return false, ""
	}

	// Don't forward internal auth header upstream.
	r.Header.Del("Proxy-Authorization")
	return true, user
}

// Handle HTTP (non-CONNECT)
func (p *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""

	removeHopByHopHeaders(outReq.Header)

	// X-Forwarded-For
	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if prior := outReq.Header.Get("X-Forwarded-For"); prior != "" {
			outReq.Header.Set("X-Forwarded-For", prior+", "+clientIP)
		} else {
			outReq.Header.Set("X-Forwarded-For", clientIP)
		}
	}

	var (
		resp *http.Response
		err  error
	)
	if p.handleRedirect {
		resp, err = p.roundTripWithRedirects(outReq)
	} else {
		resp, err = p.transport.RoundTrip(outReq)
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("proxy error: %v", err), http.StatusBadGateway)
		return
	}
	defer closeQuietly(resp.Body)

	removeHopByHopHeaders(resp.Header)

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// Handle HTTPS via CONNECT tunnel
func (p *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	ctx := r.Context()
	dstConn, err := p.dialer.DialContext(ctx, "tcp", r.Host)
	if err != nil {
		http.Error(w, fmt.Sprintf("connect to %s failed: %v", r.Host, err), http.StatusForbidden)
		return
	}

	clientConn, buf, err := hj.Hijack()
	if err != nil {
		_ = dstConn.Close()
		return
	}
	defer closeQuietly(clientConn)

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		_ = dstConn.Close()
		return
	}

	go func() {
		defer closeQuietly(dstConn)
		_, _ = io.Copy(dstConn, buf)
	}()

	_, _ = io.Copy(clientConn, dstConn)
}

// -------------------------
// Redirect handling
// -------------------------

func isRedirectStatus(code int) bool {
	return code == http.StatusMovedPermanently || // 301
		code == http.StatusFound || // 302
		code == http.StatusSeeOther || // 303
		code == http.StatusTemporaryRedirect || // 307
		code == http.StatusPermanentRedirect // 308
}

func cloneHeader(h http.Header) http.Header {
	dst := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		dst[k] = vv2
	}
	return dst
}

// GET/HEAD redirects only, up to 10 hops
func (p *ProxyServer) roundTripWithRedirects(req *http.Request) (*http.Response, error) {
	const maxRedirects = 10

	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return p.transport.RoundTrip(req)
	}

	currReq := req

	for i := 0; i <= maxRedirects; i++ {
		resp, err := p.transport.RoundTrip(currReq)
		if err != nil {
			return nil, err
		}

		if !isRedirectStatus(resp.StatusCode) {
			return resp, nil
		}

		loc := resp.Header.Get("Location")
		if loc == "" {
			return resp, nil
		}

		_ = resp.Body.Close()

		newURL, err := currReq.URL.Parse(loc)
		if err != nil {
			return nil, fmt.Errorf("invalid redirect location %q: %w", loc, err)
		}

		newReq, err := http.NewRequestWithContext(currReq.Context(), http.MethodGet, newURL.String(), nil)
		if err != nil {
			return nil, err
		}
		newReq.Header = cloneHeader(currReq.Header)
		newReq.RequestURI = ""
		removeHopByHopHeaders(newReq.Header)

		currReq = newReq
	}

	return nil, fmt.Errorf("stopped after %d redirects", maxRedirects)
}

// -------------------------
// Close helper
// -------------------------

func closeQuietly(c io.Closer) {
	_ = c.Close()
}

// -------------------------
// Header helpers
// -------------------------

var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(h http.Header) {
	for _, k := range hopHeaders {
		h.Del(k)
	}
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			f = strings.TrimSpace(f)
			if f != "" {
				h.Del(f)
			}
		}
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// -------------------------
// Config watcher
// -------------------------

func watchConfig(path string, handler *atomic.Value) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("config watch error: %v", err)
		return
	}
	defer closeQuietly(watcher)

	dir := filepath.Dir(path)
	base := filepath.Base(path)

	if err := watcher.Add(dir); err != nil {
		log.Printf("config watch add dir error: %v", err)
		return
	}

	log.Printf("watching config %s for changes", path)

	for {
		select {
		case ev, ok := <-watcher.Events:
			if !ok {
				return
			}
			if filepath.Base(ev.Name) != base {
				continue
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			// small debounce
			time.Sleep(150 * time.Millisecond)

			cfg, err := loadConfig(path)
			if err != nil {
				log.Printf("config reload failed: %v", err)
				continue
			}

			authSettings, err := buildAuthSettings(cfg.Auth)
			if err != nil {
				log.Printf("config reload auth error: %v", err)
				continue
			}

			ipWhitelist := parseIPWhitelist(cfg.Whitelist.IP)
			hostWhitelist := parseHostWhitelist(cfg.Whitelist.Host)
			ipBlacklist := parseIPWhitelist(cfg.Blacklist.IP)
			hostBlacklist := parseHostWhitelist(cfg.Blacklist.Host)

			// parse per-user overrides
			userOverrides := make(map[string]*UserOverrides, len(cfg.Overrides))
			for user, entry := range cfg.Overrides {
				uipW := parseIPWhitelist(entry.Whitelist.IP)
				hipW := parseHostWhitelist(entry.Whitelist.Host)
				uipB := parseIPWhitelist(entry.Blacklist.IP)
				hipB := parseHostWhitelist(entry.Blacklist.Host)
				userOverrides[user] = &UserOverrides{
					ipWhitelist:   uipW,
					hostWhitelist: hipW,
					ipBlacklist:   uipB,
					hostBlacklist: hipB,
				}
			}

			newProxy := newProxyServer(ipWhitelist, hostWhitelist, ipBlacklist, hostBlacklist, userOverrides, authSettings, cfg.HandleRedirect)
			handler.Store(http.Handler(newProxy))

			log.Printf("reloaded config from %s", path)

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("config watch error: %v", err)
		}
	}
}

// -------------------------
// bcrypt subcommand
// -------------------------

func bcryptSubcommand(args []string) {
	fs := flag.NewFlagSet("bcrypt", flag.ExitOnError)
	cost := fs.Int("cost", bcrypt.DefaultCost, "bcrypt cost factor")
	_ = fs.Parse(args)

	// Detect whether stdin is a terminal or being piped.
	fi, err := os.Stdin.Stat()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: cannot stat stdin: %v\n", err)
		os.Exit(1)
	}
	isTerminal := (fi.Mode() & os.ModeCharDevice) != 0

	var password string

	if !isTerminal {
		// Read password from stdin (pipeline / file), no confirmation.
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error reading password from stdin: %v\n", err)
			os.Exit(1)
		}
		password = strings.TrimRight(string(data), "\r\n")
		if password == "" {
			_, _ = fmt.Fprintln(os.Stderr, "error: empty password from stdin")
			os.Exit(1)
		}
	} else {
		// Interactive: no echo, with confirmation.
		_, _ = fmt.Fprint(os.Stderr, "Enter password: ")
		p1, err := term.ReadPassword(int(os.Stdin.Fd()))
		_, _ = fmt.Fprintln(os.Stderr)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error reading password: %v\n", err)
			os.Exit(1)
		}

		_, _ = fmt.Fprint(os.Stderr, "Confirm password: ")
		p2, err := term.ReadPassword(int(os.Stdin.Fd()))
		_, _ = fmt.Fprintln(os.Stderr)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error reading confirmation: %v\n", err)
			os.Exit(1)
		}

		if subtle.ConstantTimeCompare(p1, p2) != 1 {
			_, _ = fmt.Fprintln(os.Stderr, "error: passwords do not match")
			os.Exit(1)
		}

		if len(p1) == 0 {
			_, _ = fmt.Fprintln(os.Stderr, "error: empty password")
			os.Exit(1)
		}

		password = string(p1)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), *cost)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error generating bcrypt hash: %v\n", err)
		os.Exit(1)
	}

	// Hash only, no extra formatting.
	_, _ = fmt.Println(string(hash))
}

// -------------------------
// main / CLI
// -------------------------

func main() {
	// Subcommand dispatch: callback-guard bcrypt ...
	if len(os.Args) > 1 && os.Args[1] == "bcrypt" {
		bcryptSubcommand(os.Args[2:])
		return
	}

	// Read defaults from environment variables
	envConfig := os.Getenv("CALLBACK_GUARD_CONFIG")
	watchDefault := false
	if v := os.Getenv("CALLBACK_GUARD_WATCH"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			watchDefault = b
		}
	}

	configPath := flag.String("config", envConfig, "path to config file (required when -watch)")
	watch := flag.Bool("watch", watchDefault, "watch config and auto-reload")
	flag.Parse()

	var cfg *Config
	if *configPath == "" {
		if *watch {
			log.Fatalf("-watch requires --config to be set (or set CALLBACK_GUARD_CONFIG)")
		}
		// No config provided and not watching: use sane defaults in-memory and warn.
		log.Printf("warning: no config provided (CALLBACK_GUARD_CONFIG empty); using default in-memory config")
		cfg = &Config{Listen: ":8080"}
	} else {
		// config path provided (via flag or env) — check existence
		if _, err := os.Stat(*configPath); err != nil {
			if os.IsNotExist(err) {
				if *watch {
					log.Fatalf("config file %s does not exist; -watch requires an existing config file", *configPath)
				}
				// not watching: warn and fall back to in-memory default
				log.Printf("warning: config file %s does not exist; using default in-memory config", *configPath)
				cfg = &Config{Listen: ":8080"}
			} else {
				log.Fatalf("failed to stat config %s: %v", *configPath, err)
			}
		} else {
			var err error
			cfg, err = loadConfig(*configPath)
			if err != nil {
				log.Fatalf("failed to load config %s: %v", *configPath, err)
			}
		}
	}

	authSettings, err := buildAuthSettings(cfg.Auth)
	if err != nil {
		log.Fatalf("auth config error: %v", err)
	}

	ipWhitelist := parseIPWhitelist(cfg.Whitelist.IP)
	hostWhitelist := parseHostWhitelist(cfg.Whitelist.Host)
	ipBlacklist := parseIPWhitelist(cfg.Blacklist.IP)
	hostBlacklist := parseHostWhitelist(cfg.Blacklist.Host)

	// parse per-user overrides
	userOverrides := make(map[string]*UserOverrides, len(cfg.Overrides))
	for user, entry := range cfg.Overrides {
		uipW := parseIPWhitelist(entry.Whitelist.IP)
		hipW := parseHostWhitelist(entry.Whitelist.Host)
		uipB := parseIPWhitelist(entry.Blacklist.IP)
		hipB := parseHostWhitelist(entry.Blacklist.Host)
		userOverrides[user] = &UserOverrides{
			ipWhitelist:   uipW,
			hostWhitelist: hipW,
			ipBlacklist:   uipB,
			hostBlacklist: hipB,
		}
	}

	readTimeout := parseDurationOrDefault(cfg.Timeout.Read, 10*time.Second, "read")
	writeTimeout := parseDurationOrDefault(cfg.Timeout.Write, 10*time.Second, "write")
	idleTimeout := parseDurationOrDefault(cfg.Timeout.Idle, 60*time.Second, "idle")

	proxy := newProxyServer(ipWhitelist, hostWhitelist, ipBlacklist, hostBlacklist, userOverrides, authSettings, cfg.HandleRedirect)

	var handler atomic.Value
	handler.Store(http.Handler(proxy))

	server := &http.Server{
		Addr: cfg.Listen,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler.Load().(http.Handler).ServeHTTP(w, r)
		}),
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	log.Printf("callback-guard listening on %s", cfg.Listen)
	log.Printf("handle_redirect=%v", cfg.HandleRedirect)
	if authSettings.Enabled {
		log.Printf("auth enabled for %d user(s)", len(authSettings.Users))
	}
	if len(ipWhitelist) > 0 {
		log.Printf("IP whitelist entries: %d", len(ipWhitelist))
	}
	if len(hostWhitelist) > 0 {
		log.Printf("Host whitelist patterns: %v", hostWhitelist)
	}
	if len(ipBlacklist) > 0 {
		log.Printf("IP blacklist entries: %d", len(ipBlacklist))
	}
	if len(hostBlacklist) > 0 {
		log.Printf("Host blacklist patterns: %v", hostBlacklist)
	}

	if *watch {
		// watch requires a config path; this is already enforced above
		go watchConfig(*configPath, &handler)
	}

	log.Fatal(server.ListenAndServe())
}
