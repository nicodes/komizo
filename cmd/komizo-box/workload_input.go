package main

import (
	"context"
	"io"
	"time"
)

// The CLI owns the input descriptor. A failed read ends that process; an SSH
// peer that never finishes its payload cannot retain a privileged reader.
func readWorkloadInput(parent context.Context, input io.Reader, maximum int64) ([]byte, error) {
	if err := parent.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	type result struct {
		body []byte
		err  error
	}
	ready := make(chan result, 1)
	go func() { body, err := io.ReadAll(io.LimitReader(input, maximum+1)); ready <- result{body, err} }()
	select {
	case value := <-ready:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return value.body, value.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
