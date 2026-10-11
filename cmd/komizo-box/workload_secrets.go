package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/workload"
)

var secretName = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)
var secretFile = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

func runWorkloadSecrets(args []string) error {
	fs := flag.NewFlagSet("workload "+args[0], flag.ContinueOnError)
	policy := fs.String("policy", "", "protected workload authority")
	name := fs.String("name", "", "owner secret name")
	asFile := fs.Bool("file", false, "owner secret file")
	uid := fs.Int("uid", 0, "file owner UID")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if os.Geteuid() != 0 || *policy == "" || fs.NArg() != 0 {
		return errors.New("secret authority requires the root executor and policy")
	}
	p, err := readWorkloadPolicy(*policy)
	if err != nil {
		return err
	}
	if args[0] == "legacy-secrets-allowed" {
		if p.RequireDeliveryAuthorization {
			return errors.New("legacy secret writes require migration to authenticated delivery")
		}
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(os.Stdin, 2*workload.MaxBytes+1))
	if err != nil || len(body) > 2*workload.MaxBytes {
		return errors.New("secret input exceeds its bound")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	unlock, err := box.LockDeployment(ctx, "", p.App)
	if err != nil {
		return err
	}
	defer unlock()
	if args[0] == "owner-secret" {
		if *asFile {
			if !secretFile.MatchString(*name) || *uid < 0 || len(body) == 0 || len(body) > workload.MaxBytes {
				return errors.New("invalid owner secret file")
			}
			dir := filepath.Join(p.AppDir, "secrets")
			if err := protectedReleaseDirectory(dir); err != nil {
				return err
			}
			return writeSecretFile(filepath.Join(dir, *name), body, *uid)
		}
		if *uid != 0 {
			return errors.New("UID applies only to file secrets")
		}
		return writeSecretSet(p.AppDir, map[string]string{*name: strings.TrimRight(string(body), "\n")})
	}
	if args[0] != "release-secrets" || *name != "" || *asFile || *uid != 0 {
		return errors.New("invalid release secret command")
	}
	proof, payload, found := bytes.Cut(body, []byte("\n"))
	if !found || len(proof) > 128<<10 || !bytes.HasPrefix(proof, []byte("komizo-release/v1:")) {
		return errors.New("release secrets require authenticated source proof")
	}
	envelopeBytes, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(string(proof), "komizo-release/v1:"))
	if err != nil {
		return errors.New("invalid release proof")
	}
	var envelope workload.ReleaseEnvelope
	if json.Unmarshal(envelopeBytes, &envelope) != nil {
		return errors.New("invalid release proof")
	}
	manifestBytes, err := base64.StdEncoding.DecodeString(envelope.Manifest)
	if err != nil {
		return errors.New("invalid release manifest")
	}
	var manifest workload.ReleaseManifest
	if json.Unmarshal(manifestBytes, &manifest) != nil {
		return errors.New("invalid release manifest")
	}
	// Authorization precedes even proof verification/network access. Admission
	// independently authenticates the workflow source and immutable image set.
	if err := checkDeliveryAuthorization(p, manifest.Revision, time.Now().UTC()); err != nil {
		return err
	}
	var set struct {
		Version int               `json:"version"`
		Secrets map[string]string `json:"secrets"`
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var extra any
	if dec.Decode(&set) != nil || dec.Decode(&extra) != io.EOF || set.Version != 1 {
		return errors.New("invalid release secret set")
	}
	if err := validateSecretSet(set.Secrets); err != nil {
		return err
	}
	dir := filepath.Join("/var/lib/komizo/releases", p.App)
	if err := protectedReleaseDirectory(dir); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(dir, ".secret-admission-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := admitWorkloadReleaseFrom(p, manifest.Revision, dir, filepath.Join(stage, "accepted.json"), bytes.NewReader(proof)); err != nil {
		return err
	}
	return writeSecretSet(p.AppDir, set.Secrets)
}

func validateSecretSet(values map[string]string) error {
	if len(values) < 1 || len(values) > 128 {
		return errors.New("secret set needs bounded distinct names")
	}
	bytes := 0
	for name, value := range values {
		if !secretName.MatchString(name) || strings.HasPrefix(name, "GITHUB_") || strings.HasPrefix(name, "RUNNER_") || name == "KOMIZO_DEPLOY_KEY" || value == "" || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("invalid secret name or value")
		}
		bytes += len(name) + len(value) + 2
	}
	if bytes > workload.MaxBytes {
		return errors.New("secret set exceeds its bound")
	}
	return nil
}

func writeSecretSet(directory string, values map[string]string) error {
	if err := validateSecretSet(values); err != nil {
		return err
	}
	path := filepath.Join(directory, "secrets.env")
	previous := []byte{}
	if _, err := os.Lstat(path); err == nil {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !workloadRootOwner(info) {
			return errors.New("existing secret store is not protected")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		previous, err = io.ReadAll(io.LimitReader(file, workload.MaxBytes+1))
		file.Close()
		if err != nil || len(previous) > workload.MaxBytes {
			return errors.New("existing secret set exceeds its bound")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	var out strings.Builder
	for _, line := range strings.Split(string(previous), "\n") {
		key, _, _ := strings.Cut(line, "=")
		if _, replaced := values[key]; !replaced && line != "" {
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		out.WriteString(name + "=" + values[name] + "\n")
	}
	if out.Len() > workload.MaxBytes {
		return errors.New("complete secret set exceeds its bound")
	}
	return writeSecretFile(path, []byte(out.String()), 0)
}

func writeSecretFile(path string, body []byte, uid int) error {
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("secret destination is not a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".secret-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if err := file.Chown(uid, 0); err != nil {
		file.Close()
		return err
	}
	_, writeErr := file.Write(body)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
