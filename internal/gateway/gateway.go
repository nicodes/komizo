// Package gateway routes HTTP through a stable per-application process. Route
// admission and generation accounting share one lock, so a drained generation
// cannot acquire a late request after a successful switch.
package gateway

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
)

const MaxConfigBytes = 1 << 20

type Route struct {
	Service string   `json:"service"`
	Hosts   []string `json:"hosts"`
	Target  string   `json:"target"`
}

type Config struct {
	App            string   `json:"app"`
	Generation     string   `json:"generation"`
	Parent         string   `json:"parent,omitempty"`
	Routes         []Route  `json:"routes"`
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
}

type Status struct {
	Epoch      string `json:"epoch"`
	Generation string `json:"generation"`
	Active     bool   `json:"active"`
	Requests   uint64 `json:"requests"`
}

type generation struct {
	config   Config
	proxies  []*httputil.ReverseProxy
	requests uint64
}

type Gateway struct {
	mu          sync.Mutex
	epoch       string
	active      *generation
	generations map[string]*generation
	transport   http.RoundTripper
}

func New(config Config, transport http.RoundTripper) (*Gateway, error) {
	if transport == nil {
		transport = &http.Transport{Proxy: nil}
	}
	g := &Gateway{epoch: rand.Text(), generations: map[string]*generation{}, transport: transport}
	if err := g.Swap(config); err != nil {
		return nil, err
	}
	return g, nil
}

// Swap is an atomic admission barrier, not a process restart or connection
// close. Requests admitted before the switch retain their original generation.
// A generation identifier cannot be reused for different routing configuration.
func (g *Gateway) Swap(config Config) error {
	config, err := canonical(config)
	if err != nil {
		return err
	}
	next := &generation{config: config}
	for _, route := range config.Routes {
		u, _ := url.Parse(route.Target) // checked by canonical
		proxy := &httputil.ReverseProxy{
			Transport: g.transport,
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(u)
				r.Out.Host = r.In.Host
				// Retain the existing per-app gate behavior: Host is preserved.
				// Do not accept client-supplied forwarding headers as authority.
				r.SetXForwarded()
				if trustedPeer(r.In.RemoteAddr, config.TrustedProxies) {
					if forwarded := r.In.Header.Get("X-Forwarded-For"); validForwarded(forwarded) {
						r.Out.Header.Set("X-Forwarded-For", forwarded)
					}
					if proto := r.In.Header.Get("X-Forwarded-Proto"); proto == "http" || proto == "https" {
						r.Out.Header.Set("X-Forwarded-Proto", proto)
					}
				}
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				http.Error(w, "upstream unavailable", http.StatusBadGateway)
			},
		}
		next.proxies = append(next.proxies, proxy)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active != nil && g.active.config.App != config.App {
		return errors.New("gateway application scope cannot change")
	}
	if existing, ok := g.generations[config.Generation]; ok {
		if !reflect.DeepEqual(existing.config, config) {
			return errors.New("generation cannot be reused with different routes")
		}
		if existing != g.active {
			return errors.New("a retired generation cannot be reopened")
		}
		return nil
	}
	if g.active != nil && config.Parent != g.active.config.Generation {
		return errors.New("gateway generation changed before route switch")
	}
	g.generations[config.Generation] = next
	g.active = next
	return nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	g.mu.Lock()
	current := g.active
	var proxy *httputil.ReverseProxy
	best := -1
	for i, route := range current.config.Routes {
		for _, pattern := range route.Hosts {
			score := matchHost(host, pattern)
			if score > best {
				best, proxy = score, current.proxies[i]
			}
		}
	}
	if proxy != nil {
		current.requests++
	}
	g.mu.Unlock()
	if proxy == nil {
		http.NotFound(w, r)
		return
	}
	defer func() {
		g.mu.Lock()
		current.requests--
		g.mu.Unlock()
	}()
	proxy.ServeHTTP(w, r)
}

func (g *Gateway) Current() (Config, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c := g.active.config
	c.TrustedProxies = slices.Clone(c.TrustedProxies)
	c.Routes = slices.Clone(c.Routes)
	for i := range c.Routes {
		c.Routes[i].Hosts = slices.Clone(c.Routes[i].Hosts)
	}
	return c, g.epoch
}

func (g *Gateway) Status(id string) (Status, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	gen, ok := g.generations[id]
	if !ok {
		return Status{}, errors.New("generation is unknown; absence is not drain evidence")
	}
	return Status{g.epoch, id, gen == g.active, gen.requests}, nil
}

func (g *Gateway) Forget(id string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	gen, ok := g.generations[id]
	if !ok {
		return nil
	}
	if gen == g.active || gen.requests != 0 {
		return errors.New("generation still admits or owns requests")
	}
	delete(g.generations, id)
	return nil
}

// Admin must be bound separately on an operator-private Unix socket. Never mount
// it on the public traffic handler. Controller is responsible for durable desired
// config before PUT; the process starts from that config after a restart.
func (g *Gateway) Admin() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /routes", func(w http.ResponseWriter, r *http.Request) {
		config, epoch := g.Current()
		writeJSON(w, struct {
			Config Config `json:"config"`
			Epoch  string `json:"epoch"`
		}{config, epoch})
	})
	mux.HandleFunc("PUT /routes", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		config, err := Decode(io.LimitReader(r.Body, MaxConfigBytes+1))
		if err != nil || g.Swap(config) != nil {
			http.Error(w, "invalid or conflicting route generation", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /generations/{id}", func(w http.ResponseWriter, r *http.Request) {
		status, err := g.Status(r.PathValue("id"))
		if err != nil {
			http.Error(w, "generation unknown", http.StatusNotFound)
			return
		}
		writeJSON(w, status)
	})
	mux.HandleFunc("DELETE /generations/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := g.Forget(r.PathValue("id")); err != nil {
			http.Error(w, "generation not drained", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func Decode(reader io.Reader) (Config, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxConfigBytes+1))
	if err != nil || len(data) > MaxConfigBytes {
		return Config{}, errors.New("cannot read bounded gateway configuration")
	}
	var config Config
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if err := d.Decode(&config); err != nil {
		return Config{}, errors.New("invalid gateway configuration")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return Config{}, errors.New("gateway configuration has trailing data")
	}
	return canonical(config)
}

func canonical(config Config) (Config, error) {
	if !validID(config.App) || !validID(config.Generation) || config.Routes == nil {
		return Config{}, errors.New("gateway requires a generation and explicit routes")
	}
	config.Routes = slices.Clone(config.Routes)
	config.TrustedProxies = slices.Clone(config.TrustedProxies)
	for _, prefix := range config.TrustedProxies {
		if _, err := netip.ParsePrefix(prefix); err != nil {
			return Config{}, errors.New("trusted proxies must be explicit IP prefixes")
		}
	}
	slices.Sort(config.TrustedProxies)
	seen := map[string]bool{}
	services := map[string]bool{}
	for i := range config.Routes {
		route := &config.Routes[i]
		if !validID(route.Service) || services[route.Service] || len(route.Hosts) == 0 {
			return Config{}, errors.New("invalid or duplicate gateway service")
		}
		services[route.Service] = true
		u, err := url.Parse(route.Target)
		if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
			return Config{}, errors.New("gateway target must be a private HTTP origin")
		}
		route.Hosts = slices.Clone(route.Hosts)
		for j, host := range route.Hosts {
			host = strings.ToLower(host)
			if !validHost(host) || seen[host] {
				return Config{}, errors.New("invalid or duplicate gateway hostname")
			}
			seen[host], route.Hosts[j] = true, host
		}
		slices.Sort(route.Hosts)
	}
	slices.SortFunc(config.Routes, func(a, b Route) int { return strings.Compare(a.Service, b.Service) })
	return config, nil
}

func validID(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func validHost(host string) bool {
	host = strings.TrimPrefix(host, "*.")
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func matchHost(host, pattern string) int {
	if host == pattern {
		return 1000 + len(pattern)
	}
	if strings.HasPrefix(pattern, "*.") && strings.HasSuffix(host, pattern[1:]) && len(host) > len(pattern)-1 {
		if label := strings.TrimSuffix(host, pattern[1:]); !strings.Contains(label, ".") {
			return len(pattern)
		}
	}
	return -1
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func trustedPeer(remote string, prefixes []string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, value := range prefixes {
		prefix, _ := netip.ParsePrefix(value)
		if prefix.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}

func validForwarded(value string) bool {
	if value == "" {
		return false
	}
	for _, address := range strings.Split(value, ",") {
		if _, err := netip.ParseAddr(strings.TrimSpace(address)); err != nil {
			return false
		}
	}
	return true
}
