// A real application fixture: HTTP admission, background work and resumable
// streams share lifecycle state. The adapter talks to PID 1 over a local socket;
// it cannot manufacture proof from gateway accounting or its own process exit.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) == 7 && os.Args[1] == "lifecycle" {
		millis, err := strconv.ParseInt(os.Args[6], 10, 64)
		if err != nil {
			os.Exit(64)
		}
		ctx, cancel := context.WithDeadline(context.Background(), time.UnixMilli(millis))
		defer cancel()
		client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", "/run/lifecycle.sock")
		}}}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://local/"+os.Args[2], nil)
		if err != nil {
			os.Exit(64)
		}
		response, err := client.Do(request)
		if err != nil {
			os.Exit(1)
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			os.Exit(2)
		}
		fmt.Printf("komizo-lifecycle-v1 %s %s\n", os.Args[2], os.Args[3])
		return
	}
	// argv: serve BODY READY [refuse-drain|ignore-term]
	if len(os.Args) < 4 {
		os.Exit(64)
	}
	mode := ""
	if len(os.Args) > 4 {
		mode = os.Args[4]
	}
	var mu sync.Mutex
	quiesced, sealed, drained := false, false, false
	requests, jobs := 0, 0
	streams := make(chan struct{})
	go func() {
		for {
			mu.Lock()
			if quiesced {
				mu.Unlock()
				return
			}
			jobs++
			mu.Unlock()
			if mode == "slow-job" {
				fmt.Println("background-started")
				time.Sleep(2 * time.Second)
			} else {
				time.Sleep(100 * time.Millisecond) // already accepted background work
			}
			mu.Lock()
			jobs--
			mu.Unlock()
		}
	}()
	public := &http.Server{Addr: ":8080", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if sealed {
			mu.Unlock()
			http.Error(w, "sealed", 503)
			return
		}
		requests++
		mu.Unlock()
		defer func() { mu.Lock(); requests--; mu.Unlock() }()
		if r.URL.Path == "/readyz" && os.Args[3] != "true" {
			http.Error(w, "not ready", 503)
			return
		}
		if r.URL.Path == "/slow" {
			w.WriteHeader(200)
			w.(http.Flusher).Flush() // the test now knows admission is counted
			time.Sleep(time.Second)
		}
		if r.URL.Path == "/stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "id: resume-1\ndata: work\n\n")
			w.(http.Flusher).Flush()
			select {
			case <-streams:
			case <-r.Context().Done():
			}
			return
		}
		io.WriteString(w, os.Args[2])
	})}
	admin := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", 405)
			return
		}
		mu.Lock()
		switch r.URL.Path {
		case "/quiesce":
			if !quiesced {
				quiesced = true
				close(streams)
			}
		case "/seal":
			if !quiesced {
				mu.Unlock()
				http.Error(w, "order", 409)
				return
			}
			sealed = true
		case "/drain":
			if !sealed || mode == "refuse-drain" {
				mu.Unlock()
				http.Error(w, "not drained", 409)
				return
			}
			for requests != 0 || jobs != 0 {
				mu.Unlock()
				select {
				case <-r.Context().Done():
					return
				case <-time.After(time.Millisecond):
				}
				mu.Lock()
			}
			drained = true
		default:
			mu.Unlock()
			http.Error(w, "unknown", 404)
			return
		}
		mu.Unlock()
		w.WriteHeader(200)
	})}
	listener, err := net.Listen("unix", "/run/lifecycle.sock")
	if err != nil {
		panic(err)
	}
	go admin.Serve(listener)
	go public.ListenAndServe()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	for range signals {
		if mode == "ignore-term" {
			fmt.Println("ignored-term")
			continue
		}
		mu.Lock()
		ok := quiesced && sealed && drained && requests == 0 && jobs == 0
		mu.Unlock()
		if !ok {
			os.Exit(73)
		}
		// Keep this below the rollout operation budget while allowing heavily
		// loaded one-CPU CI hosts to finish Go's graceful HTTP shutdown.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if public.Shutdown(ctx) != nil {
			cancel()
			os.Exit(74)
		}
		cancel()
		return
	}
}
