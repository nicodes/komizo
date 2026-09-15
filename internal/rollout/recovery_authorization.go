package rollout

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	recoveryAuthorizationLimit = 64 << 10
	recoveryProtocolLimit      = 4 << 10
)

var systemRecoveryAuthorizationRoot = "/etc/komizo/rollout-recoveries"

type recoveryAuthorizationWire struct {
	Version        int                    `json:"version"`
	App            string                 `json:"app"`
	Transaction    string                 `json:"transaction"`
	Service        string                 `json:"service"`
	Old            RecoveryIncarnationPin `json:"old"`
	Candidate      RecoveryIncarnationPin `json:"candidate"`
	VerifierPath   string                 `json:"verifier_path"`
	VerifierSHA256 string                 `json:"verifier_sha256"`
	VerifierArgs   []string               `json:"verifier_args,omitempty"`
	UID            uint32                 `json:"uid"`
	GID            uint32                 `json:"gid"`
	Overall        string                 `json:"overall"`
	Retire         string                 `json:"retire"`
}

func recoveryAuthorizationPath(app string) string {
	return filepath.Join(systemRecoveryAuthorizationRoot, app+".json")
}

func LoadRecoveryAuthorization(path string) (RecoveryAuthorization, error) {
	var authorization RecoveryAuthorization
	info, statErr := os.Lstat(path)
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !ownedByCurrent(info) {
		return authorization, errors.New("recovery authorization must be an owned mode-0600 regular file")
	}
	data, err := readPrivateRecord(path, recoveryAuthorizationLimit)
	if err != nil {
		return authorization, errors.New("recovery authorization must be a private bounded regular file")
	}
	defer clear(data)
	var wire recoveryAuthorizationWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || ensureJSONEnd(decoder) != nil {
		return authorization, errors.New("invalid recovery authorization")
	}
	overall, overallErr := time.ParseDuration(wire.Overall)
	retire, retireErr := time.ParseDuration(wire.Retire)
	authorization = RecoveryAuthorization{Version: wire.Version, App: wire.App, Transaction: wire.Transaction, Service: wire.Service,
		Old: wire.Old, Candidate: wire.Candidate, VerifierPath: wire.VerifierPath, VerifierSHA256: wire.VerifierSHA256,
		VerifierArgs: slices.Clone(wire.VerifierArgs), UID: wire.UID, GID: wire.GID, Overall: overall, Retire: retire, Digest: hash(data)}
	if overallErr != nil || retireErr != nil || authorization.Version != 1 || !scopeName(authorization.App) || !scopeName(authorization.Transaction) || !scopeName(authorization.Service) ||
		!filepath.IsAbs(authorization.VerifierPath) || !lowerHex(authorization.VerifierSHA256, 64) || authorization.UID == 0 || authorization.GID == 0 ||
		authorization.Overall <= 0 || authorization.Overall > 8*time.Minute || authorization.Retire <= 0 || authorization.Retire > 5*time.Minute || len(authorization.VerifierArgs) > 16 ||
		!validRecoveryPin(authorization.Old, true) || !validRecoveryPin(authorization.Candidate, false) {
		return RecoveryAuthorization{}, errors.New("recovery authorization has invalid scope, pin, verifier, identity, or budget")
	}
	for _, arg := range authorization.VerifierArgs {
		if len(arg) > 4096 || strings.ContainsAny(arg, "\x00\r\n") {
			return RecoveryAuthorization{}, errors.New("recovery verifier argv is invalid")
		}
	}
	return authorization, nil
}

func validRecoveryPin(pin RecoveryIncarnationPin, old bool) bool {
	if !lowerHex(pin.ID, 64) || pin.StartedAt == "" || !scopeName(pin.Generation) || !lowerHex(pin.Identity, 64) {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, pin.StartedAt); err != nil {
		return false
	}
	if old {
		if pin.ExitCode == 0 || pin.FinishedAt == "" {
			return false
		}
		_, err := time.Parse(time.RFC3339Nano, pin.FinishedAt)
		return err == nil
	}
	return pin.ExitCode == 0 && pin.FinishedAt == ""
}

func lowerHex(value string, length int) bool {
	return len(value) == length && !strings.ContainsFunc(value, func(c rune) bool {
		return !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f')
	})
}

// ProcessRecoveryVerifier executes one checksum-pinned regular file by its
// already-open descriptor. It neither resolves the path a second time nor
// inherits the root environment. Raw stdout/stderr is never published.
type ProcessRecoveryVerifier struct{ Authorization RecoveryAuthorization }

func (v *ProcessRecoveryVerifier) Open(ctx context.Context, challenge RecoveryChallenge) (RecoverySession, error) {
	a := v.Authorization
	if deadline, ok := ctx.Deadline(); !ok || ctx.Err() != nil || challenge.Version != 1 || challenge.Nonce == "" || challenge.App != a.App || challenge.Transaction != a.Transaction || challenge.Service != a.Service || challenge.Old != a.Old || challenge.Candidate != a.Candidate ||
		challenge.DeadlineUnixMillis <= time.Now().UnixMilli() || time.UnixMilli(challenge.DeadlineUnixMillis).After(deadline) || challenge.OverallDeadlineUnixMillis < challenge.DeadlineUnixMillis || challenge.OverallDeadlineUnixMillis > time.Now().Add(8*time.Minute).UnixMilli() {
		return nil, errors.New("recovery verifier requires a live bounded challenge")
	}
	file, err := openPinnedVerifier(a)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	stdin, stdout, command, err := recoveryVerifierCommand(ctx, file, a)
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return nil, errors.New("recovery verifier could not start")
	}
	session := &processRecoverySession{command: command, stdin: stdin, output: bufio.NewReader(io.LimitReader(stdout, recoveryProtocolLimit)), nonce: challenge.Nonce, waited: make(chan error, 1)}
	go func() { session.waited <- command.Wait() }()
	body, _ := json.Marshal(challenge)
	body = append(body, '\n')
	if len(body) > recoveryProtocolLimit {
		session.Preserve()
		return nil, errors.New("recovery verifier challenge exceeds protocol limit")
	}
	handshake, cancel := context.WithDeadline(ctx, time.UnixMilli(challenge.DeadlineUnixMillis))
	defer cancel()
	if _, err := stdin.Write(body); err != nil {
		session.Preserve()
		return nil, errors.New("recovery verifier did not accept its fixed challenge")
	}
	line := session.readLine(handshake)
	valid := line == "komizo-recovery-verifier-v1 fenced-empty "+challenge.Nonce+"\n"
	if challenge.AlreadyActivated {
		valid = valid || line == "komizo-recovery-verifier-v1 activated "+challenge.Nonce+"\n"
	}
	if !valid {
		session.Preserve()
		return nil, errors.New("recovery verifier did not return the exact safe-state proof")
	}
	return session, nil
}

func openPinnedVerifier(a RecoveryAuthorization) (*os.File, error) {
	info, err := os.Lstat(a.VerifierPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || info.Mode().Perm()&0o222 != 0 || info.Mode().Perm()&0o001 == 0 || info.Size() <= 0 || info.Size() > 64<<20 || !ownedByCurrent(info) {
		return nil, errors.New("recovery verifier is not an owned non-writable executable")
	}
	file, err := os.Open(a.VerifierPath)
	if err != nil {
		return nil, errors.New("cannot open recovery verifier")
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		file.Close()
		return nil, errors.New("recovery verifier changed while opening")
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, io.LimitReader(file, 64<<20+1)); err != nil {
		file.Close()
		return nil, errors.New("cannot hash recovery verifier")
	}
	if hex.EncodeToString(digest.Sum(nil)) != a.VerifierSHA256 {
		file.Close()
		return nil, errors.New("recovery verifier checksum does not match authorization")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, errors.New("cannot rewind recovery verifier")
	}
	return file, nil
}

type processRecoverySession struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	output  *bufio.Reader
	nonce   string
	waited  chan error
	once    sync.Once
}

func (s *processRecoverySession) readLine(ctx context.Context) string {
	result := make(chan string, 1)
	go func() {
		line, err := s.output.ReadString('\n')
		if err != nil || len(line) > 512 {
			result <- ""
			return
		}
		result <- line
	}()
	select {
	case line := <-result:
		return line
	case <-ctx.Done():
		return ""
	}
}

func (s *processRecoverySession) Release(ctx context.Context) error {
	select {
	case <-s.waited:
		s.once.Do(func() {})
		return errors.New("recovery verifier exited before release")
	default:
	}
	if _, err := io.WriteString(s.stdin, "release "+s.nonce+"\n"); err != nil || s.readLine(ctx) != "komizo-recovery-verifier-v1 released "+s.nonce+"\n" {
		return errors.New("recovery verifier release acknowledgement is invalid")
	}
	_ = s.stdin.Close()
	type remainder struct {
		data []byte
		err  error
	}
	remainderResult := make(chan remainder, 1)
	go func() {
		data, err := io.ReadAll(s.output)
		remainderResult <- remainder{data, err}
	}()
	var extra []byte
	var extraErr error
	select {
	case remainder := <-remainderResult:
		extra, extraErr = remainder.data, remainder.err
	case <-ctx.Done():
		return errors.New("recovery verifier did not close output within the operation deadline")
	}
	select {
	case err := <-s.waited:
		if err != nil {
			s.once.Do(func() {})
			return errors.New("recovery verifier failed after release acknowledgement")
		}
		if extraErr != nil || len(extra) != 0 {
			s.once.Do(func() {})
			return errors.New("recovery verifier emitted unexpected output")
		}
		s.once.Do(func() {})
		return nil
	case <-ctx.Done():
		return errors.New("recovery verifier did not exit within the operation deadline")
	}
}

func (s *processRecoverySession) Preserve() {
	s.once.Do(func() {
		_ = s.stdin.Close()
		killRecoveryVerifier(s.command)
		select {
		case <-s.waited:
		case <-time.After(time.Second):
		}
	})
}

var _ RecoveryVerifier = (*ProcessRecoveryVerifier)(nil)
