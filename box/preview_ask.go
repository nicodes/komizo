package box

import (
	"net/http"
)

// The on-demand-TLS ask, narrowly re-enabled.
//
// The #132 fail-closed guard -- a route that needs on-demand issuance with no
// ask module refuses the rewrite -- is untouched and stays. This is the
// answer when an operator has explicitly pointed the proxy's ask URL here:
// pr-<N> and pr-<N>-api under the preview domain may cause a certificate to
// exist, and NOTHING else may. The matcher is PreviewAskAllow; this is its
// HTTP edge, so the scoping is testable over the wire and not only in the
// unit table.

// PreviewAskHandler answers the ask endpoint. Caddy passes the hostname it
// was asked for as ?domain=. 200 is "issue it"; anything else is a refusal,
// and a refusal is the whole point.
func PreviewAskHandler(domain string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("domain")
		if PreviewAskAllow(host, domain) {
			w.WriteHeader(http.StatusOK)
			return
		}
		// One answer for every no, and no detail beyond it: which names ARE
		// allowed is not the caller's business -- the same shape as the box's
		// own API refusals.
		http.Error(w, "not a preview name", http.StatusForbidden)
	})
}
