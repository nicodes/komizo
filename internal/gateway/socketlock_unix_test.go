//go:build linux || darwin

package gateway

import (
	"net"
	"os"
	"syscall"
	"testing"
)

func TestConnectionRefusedRequiresPositiveEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"refused", syscall.ECONNREFUSED, true},
		{"wrapped", &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, true},
		{"permission", syscall.EACCES, false},
		{"missing", os.ErrNotExist, false},
		{"timeout", os.ErrDeadlineExceeded, false},
		{"success", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := connectionRefused(tc.err); got != tc.want {
				t.Fatalf("connectionRefused(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
