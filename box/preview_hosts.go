package box

import (
	"fmt"
	"regexp"
	"strings"
)

// HostFor keeps each app/PR in one DNS label so one wildcard covers the host.
// Without SHARED_DOMAIN, existing per-app domains and URLs are unchanged.
func (k PreviewKnob) HostFor(app string, pr int) string {
	if shared := k.SharedDomainFor(app); shared != "" {
		return fmt.Sprintf("%s-pr%d.%s", app, pr, shared)
	}
	return PreviewHost(pr, k.DomainFor(app))
}

func (k PreviewKnob) APIHostFor(app string, pr int) string {
	host := k.HostFor(app, pr)
	label, domain, _ := strings.Cut(host, ".")
	return label + "-api." + domain
}

// Persisted names describe the running preview even if the host knob changes.
func (r PreviewRecord) WebHost(k PreviewKnob) string {
	if r.Host != "" {
		return r.Host
	}
	return PreviewHost(r.PR, k.legacyDomainFor(r.App))
}

func (r PreviewRecord) PublicAPIHost(k PreviewKnob) string {
	if len(r.Images) < 2 {
		return ""
	}
	if r.APIHost != "" {
		return r.APIHost
	}
	label, domain, _ := strings.Cut(r.WebHost(k), ".")
	return label + "-api." + domain
}

var previewDNSLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
var previewTLD = regexp.MustCompile(`^[a-z]{2,}$`)
var sharedPreviewLabel = regexp.MustCompile(`^[a-z][a-z0-9-]*-pr[1-9][0-9]*(-api)?$`)

func (k PreviewKnob) validateHosts(app string, pr int) error {
	if k.SharedDomainFor(app) == "" {
		return nil
	}
	host := k.APIHostFor(app, pr)
	if len(host) > 253 || !strings.Contains(k.SharedDomainFor(app), ".") {
		return fmt.Errorf("SHARED_DOMAIN does not produce a valid preview hostname")
	}
	labels := strings.Split(host, ".")
	if !previewTLD.MatchString(labels[len(labels)-1]) {
		return fmt.Errorf("SHARED_DOMAIN must have an alphabetic top-level domain")
	}
	for _, label := range labels {
		if len(label) > 63 || !previewDNSLabel.MatchString(label) {
			return fmt.Errorf("SHARED_DOMAIN or app name does not produce valid DNS labels")
		}
	}
	return nil
}

func sharedPreviewAskAllow(host, domain string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	domain = strings.ToLower(strings.TrimSpace(domain))
	label, ok := strings.CutSuffix(host, "."+domain)
	return domain != "" && ok && len(label) <= 63 && sharedPreviewLabel.MatchString(label)
}

// Per-app opt-in permits a canary before changing the rest of a host.
func (k PreviewKnob) SharedDomainFor(app string) string {
	if d := previewKnobGet(k.body, "SHARED_DOMAIN."+app); d != "" {
		return d
	}
	return k.SharedDomain
}

// PreviewTarget is a read-only answer used before building or writing auth
// settings. It never creates resources or claims that a preview is running.
type PreviewTarget struct {
	App     string `json:"app"`
	PR      int    `json:"pr"`
	Domain  string `json:"domain"`
	Host    string `json:"host"`
	APIHost string `json:"api_host"`
}

func ResolvePreview(k PreviewKnob, app string, pr int, hasAPI bool) (PreviewTarget, error) {
	var target PreviewTarget
	if err := validatePreviewArgs(app, pr); err != nil {
		return target, err
	}
	if err := k.validateHosts(app, pr); err != nil {
		return target, err
	}
	target = PreviewTarget{App: app, PR: pr, Domain: k.DomainFor(app), Host: k.HostFor(app, pr)}
	if hasAPI {
		target.APIHost = k.APIHostFor(app, pr)
	}
	return target, nil
}

func (k PreviewKnob) SharedAskAllow(host string) bool {
	if sharedPreviewAskAllow(host, k.SharedDomain) {
		return true
	}
	for _, line := range strings.Split(k.body, "\n") {
		key, _, ok := strings.Cut(line, "=")
		if !ok || !strings.HasPrefix(key, "SHARED_DOMAIN.") {
			continue
		}
		app := strings.TrimPrefix(key, "SHARED_DOMAIN.")
		domain := k.SharedDomainFor(app)
		if !previewAppChars.MatchString(app) || !sharedPreviewAskAllow(host, domain) {
			continue
		}
		// A per-app opt-in may only permit that app, not arbitrary sibling names.
		label := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), "."+strings.ToLower(domain))
		if strings.HasPrefix(label, app+"-pr") && previewPRDigits.MatchString(strings.TrimSuffix(strings.TrimPrefix(label, app+"-pr"), "-api")) {
			return true
		}
	}
	return false
}
