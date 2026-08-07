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

	// OperatorKeys are the devices this box takes orders from, from the same
	// credential -- see operator.go. PUBLIC, so this process holding them grants
	// it nothing: verifying with a public key is not signing.
	//
	// Empty on a box nobody has given a device to, which is every box until an
	// operator plants one. Since komizo-be#72 took away the token-only reads,
	// such a box answers NOTHING -- every route below wants an envelope signed
	// by a key in here, and there are none. It says so at startup rather than
	// leaving the app to show an empty screen.
	OperatorKeys []ed25519.PublicKey

	// ReportPath and HistoryPath are the files rootd writes.
	ReportPath  string
	HistoryPath string

	// InboxDir is where a signed command is left for rootd, and ResultsDir is
	// where rootd leaves what happened. Two directions, two directories, each
	// owned by whoever writes into it -- see inbox.go.
	InboxDir   string
	ResultsDir string
	// LogsDir is where rootd leaves each app's recent output. Root writes it
	// because the account serving this has no docker group -- see logs.go.
	LogsDir string

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
	// THE TWO READS, ASKED FOR BY A DEVICE. There is no other way to ask.
	//
	// komizo-be#58 added these beside a `GET /v1/report` and `GET /v1/history`
	// that took the registry's token and nothing else. komizo-be#72 is their
	// removal, and it is the half of #58 that actually closes the hole: while
	// the GETs were served, whoever held the service's signing key could read
	// every enrolled box, and the signed routes beside them changed nothing
	// about that. A second door is not narrowed by adding a better one.
	//
	// THIS BREAKS OLD CALLERS, DELIBERATELY. An app that still asks the unsigned
	// way now gets `refuse` from the catch-all below. That is why it waited for
	// its own release: boxes are updated by hand, one at a time, so the client
	// had to be able to speak the signed form to every box before the unsigned
	// form could go.
	//
	// A BOX THAT PREDATES THESE ROUTES ANSWERS 401, NOT 404, and the difference
	// matters more than it looks. The catch-all matches an unknown path
	// deliberately -- a 404 distinguishable from a 401 tells an unauthenticated
	// caller which routes exist -- so an old box refuses a perfectly good token.
	//
	// app-only.md §6 records that a 401 is the one status the app turns into
	// "enrol this box again", which is a ROOT action on the operator's own
	// machine. Getting that wrong would have komizo's own client ask every
	// operator in the fleet to do the exact thing §6 names as the lever a
	// breached service wants to pull. The app's answer is that 403 and 409 have
	// their own sentences (komizo-be#120) rather than becoming that prompt.
	mux.HandleFunc("POST /v1/report", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(cfg, r) {
			refuse(w)
			return
		}
		if _, ok := verifiedRead(cfg, w, r, OpReportRead); !ok {
			return
		}
		rep, err := ReadReport(cfg.ReportPath)
		if err != nil {
			http.Error(w, "no report yet", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, ReportResponse{V: APIVersion, Report: rep})
	})

	mux.HandleFunc("POST /v1/history", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(cfg, r) {
			refuse(w)
			return
		}
		c, ok := verifiedRead(cfg, w, r, OpHistoryRead)
		if !ok {
			return
		}
		// FROM THE ARGUMENTS, not from the query string. The point of this route
		// is that what is being asked for was signed, and a window taken from
		// the URL is a window anybody who relayed the request could change.
		from, to, ok := signedWindow(c, cfg.Now())
		if !ok {
			http.Error(w, "from and to must be unix seconds, and from must not be after to", http.StatusBadRequest)
			return
		}
		samples, err := ReadSamples(cfg.HistoryPath, from, to)
		if err != nil {
			samples = nil
		}
		writeJSON(w, HistoryResponse{V: APIVersion, From: from, To: to, Samples: samples})
	})

	// What an app has been saying. NOT a read like the others: §5 asks that logs
	// be authorised by the device rather than by the registry, so this takes a
	// signed envelope as well as a token -- see logs.go.
	mux.HandleFunc("POST /v1/logs", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(cfg, r) {
			refuse(w)
			return
		}
		serveLog(cfg, w, r)
	})

	// Telling this box something. A POST, and the only route here that is not a
	// read -- see write.go for why it still does not act.
	mux.HandleFunc("POST /v1/commands", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(cfg, r) {
			refuse(w)
			return
		}
		postCommand(cfg, w, r)
	})

	// And what happened to one. A read, authorised like every other read: the
	// caller is asking about a command it sent.
	mux.HandleFunc("GET /v1/commands/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(cfg, r) {
			refuse(w)
			return
		}
		getResult(cfg, w, r)
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


// parseWindow is what a window IS, wherever the two values came from.
//
// The default is the last hour, and it is stated once: two copies of a default
// is two answers to "what does asking for nothing mean", and nothing would have
// failed if they drifted.
func parseWindow(get func(string) string, now time.Time) (from, to int64, ok bool) {
	to = now.Unix()
	from = now.Add(-time.Hour).Unix()
	if v := get("to"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		to = n
	}
	if v := get("from"); v != "" {
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

// signedWindow is the same window, taken from what was SIGNED.
//
// The whole point of the signed history route is that the request came from a
// particular device -- and a window read from the URL is a window anything that
// relayed the request could rewrite without breaking the signature.
//
// ONE PARSER, not two. read.go's own header blames a duplicated block for the
// log route drifting into reading c.Args["app"] directly while every other path
// used AppOf, and the first version of this function was that same duplication
// in the same diff. What differs between the two routes is WHERE the values come
// from, so that is the only thing that differs here.
func signedWindow(c Command, now time.Time) (from, to int64, ok bool) {
	return parseWindow(func(k string) string { return c.Args[k] }, now)
}

func writeJSON(w http.ResponseWriter, v any) { writeJSONStatus(w, http.StatusOK, v) }

// writeJSONStatus writes the headers BEFORE the status, which is the only order
// that works.
//
// WriteHeader flushes what is set at the moment it is called and ignores
// everything added after -- so a route that wrote 202 and then called writeJSON
// sent its body as text/plain with no nosniff at all. That was the one
// browser-reachable POST on this API, and nosniff is load-bearing here: a JSON
// document a browser decides to treat as HTML is a document that can run.
func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
