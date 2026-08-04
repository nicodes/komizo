package box

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// The box, answering for itself.
//
// design/registry.md in komizo-be decides that a server's data lives on the
// server: the service keeps liveness, current problems and who owns what, and
// everything else -- the report, the readings, the history -- stays here. This
// is the half that serves it.
//
// READ-ONLY, and that is structural rather than a promise. There is no route
// here that writes anything, and the process runs as komizo_monitor: no shell,
// no docker group, no doas, nothing under the state directory. Compromise it
// and you get what a reader was going to be given anyway.
//
// It reads the two files rootd already writes. There is no database on
// customer servers -- appify.md §9 priced a process on other people's
// production machines as needing to be "small, read-only, and updatable, and it
// is yours forever", and a schema is none of those. The files ARE the store.
//
// The shapes below are permanent from the moment this ships. Every response is
// a versioned document for the same reason the report is one: the box and
// whatever reads it are separate releases, and a document that does not state
// its schema is one the reader has to guess at.

// APIVersion is the schema of the documents this serves.
//
// Its own number, not box.Version. The report's schema and this API's shape
// change for different reasons -- a new field in the report does not alter what
// these routes are -- and one number covering both would force a version bump
// on readers that were not affected.
const APIVersion = 1

// APIConfig is what the handler needs to answer.
type APIConfig struct {
	// ServerID is this box's id, from the credential enrolment wrote. A box
	// with none refuses every request: no token can name it, which is the right
	// answer for a machine no registry has heard of.
	ServerID string
	// RegistryKey verifies read tokens. Planted at enrolment; see token.go.
	RegistryKey ed25519.PublicKey

	// ReportPath and HistoryPath are the files rootd writes.
	ReportPath  string
	HistoryPath string

	// Now is injectable so expiry is testable without sleeping.
	Now func() time.Time
}

// ReportResponse is the current state, whole.
type ReportResponse struct {
	V      int    `json:"v"`
	Report Report `json:"report"`
}

func (r ReportResponse) Schema() int { return r.V }

// HistoryResponse is what the box was, over a window.
//
// The samples are as they were recorded -- cumulative counters, not rates.
// box/system.go explains why and it holds here too: a rate needs two readings,
// and the reader owning the subtraction keeps the interval explicit rather than
// assumed. Serving pre-computed rates would bake in an interval that a late
// poll makes wrong, and it cannot be recovered afterwards.
type HistoryResponse struct {
	V       int      `json:"v"`
	From    int64    `json:"from"`
	To      int64    `json:"to"`
	Samples []Sample `json:"samples"`
}

func (h HistoryResponse) Schema() int { return h.V }

// Handler is the box's read API.
//
// Every route requires a token signed by the registry and named for THIS box.
// There is no unauthenticated route, not even a health check: a box that would
// tell a stranger it is a komizo box is a box that has said something about
// somebody's infrastructure to whoever asked.
func Handler(cfg APIConfig) http.Handler {
	if cfg.Now == nil {
		cfg.Now = Now
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/report", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(cfg, r) {
			refuse(w)
			return
		}
		rep, err := ReadReport(cfg.ReportPath)
		if err != nil {
			// The agent has not written one yet, or the file is mid-rewrite.
			// Not an error about the CALLER, and not a 200 with an empty
			// document either -- an empty report reads as a broken box.
			http.Error(w, "no report yet", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, ReportResponse{V: APIVersion, Report: rep})
	})

	mux.HandleFunc("GET /v1/history", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(cfg, r) {
			refuse(w)
			return
		}
		from, to, ok := window(r, cfg.Now())
		if !ok {
			http.Error(w, "from and to must be unix seconds, and from must not be after to", http.StatusBadRequest)
			return
		}
		samples, err := ReadSamples(cfg.HistoryPath, from, to)
		if err != nil {
			// A box that has never been polled has no history file. An empty
			// window is the honest answer -- there is nothing wrong with the
			// machine, there is simply nothing recorded yet.
			samples = nil
		}
		writeJSON(w, HistoryResponse{V: APIVersion, From: from, To: to, Samples: samples})
	})

	// Anything else, including an unknown path, answers exactly as an
	// unauthorized request does. A 404 that is distinguishable from a 401 tells
	// an unauthenticated caller which routes exist.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { refuse(w) })
	return mux
}

// authorized decides whether this request may read this box.
func authorized(cfg APIConfig, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	tok, ok := cutBearer(auth)
	if !ok {
		return false
	}
	return VerifyReadToken(cfg.RegistryKey, tok, cfg.ServerID, cfg.Now()) == nil
}

func cutBearer(h string) (string, bool) {
	const p = "Bearer "
	if len(h) <= len(p) || h[:len(p)] != p {
		return "", false
	}
	return h[len(p):], true
}

// refuse is the single answer to every request that is not allowed.
//
// One status, one body, no detail. Whether the token was absent, expired,
// forged or minted for a different box is not the caller's business, and the
// difference between "no such route" and "not allowed" would map this API for
// somebody who cannot use it.
func refuse(w http.ResponseWriter) {
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// window parses the requested range, defaulting to the last hour.
func window(r *http.Request, now time.Time) (from, to int64, ok bool) {
	q := r.URL.Query()
	to = now.Unix()
	from = now.Add(-time.Hour).Unix()
	if v := q.Get("to"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		to = n
	}
	if v := q.Get("from"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		from = n
	}
	if from > to {
		return 0, 0, false
	}
	return from, to, true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	// nosniff, because this is served through a proxy to a browser: a JSON
	// document a browser decides to treat as HTML is a document that can run.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(v)
}
