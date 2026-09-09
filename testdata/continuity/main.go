// Synthetic HTTP service for isolated rollout controls. Not an application or
// production readiness check. No credentials, filesystem state or external calls.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	release := flag.String("release", "fixture", "synthetic release name")
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "data: %s-start\n\n", *release)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			return
		case <-time.After(500 * time.Millisecond):
			fmt.Fprintf(w, "data: %s-complete\n\n", *release)
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, *release)
	})
	log.Fatal(http.ListenAndServe(":8080", mux))
}
