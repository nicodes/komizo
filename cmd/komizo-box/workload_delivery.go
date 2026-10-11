package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nicodes/komizo/internal/workload"
)

const deliveryStore = "/var/lib/komizo/delivery-authorizations"

func runWorkloadDelivery(args []string) error {
	fs := flag.NewFlagSet("workload "+args[0], flag.ContinueOnError)
	policy := fs.String("policy", "", "protected workload authority")
	wire := fs.String("authorization", "", "bounded base64 root-reviewed authorization")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if os.Geteuid() != 0 || fs.NArg() != 0 || *policy == "" {
		return errors.New("delivery authority requires the root operator and policy")
	}
	p, err := readWorkloadPolicy(*policy)
	if err != nil {
		return err
	}
	if args[0] == "delivery-enable" {
		if *wire != "" || p.SourceRepository == "" {
			return errors.New("delivery authorization requires authenticated source authority")
		}
		p.RequireDeliveryAuthorization = true
		return workload.WritePrivateJSON(*policy, p)
	}
	if args[0] != "delivery-authorize" || len(*wire) > 65536 {
		return errors.New("invalid delivery authorization command")
	}
	body, err := base64.StdEncoding.DecodeString(*wire)
	if err != nil {
		return errors.New("invalid delivery authorization encoding")
	}
	var authorization workload.DeliveryAuthorization
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var extra any
	if err := decoder.Decode(&authorization); err != nil || decoder.Decode(&extra) != io.EOF {
		return errors.New("invalid delivery authorization")
	}
	if err := authorization.Check(p, authorization.Revision, time.Now().UTC()); err != nil {
		return err
	}
	directory := filepath.Join(deliveryStore, p.App)
	if err := protectedReleaseDirectory(directory); err != nil {
		return err
	}
	return workload.WritePrivateJSON(filepath.Join(directory, authorization.Revision+".json"), authorization)
}

func checkDeliveryAuthorization(p workload.Policy, version string, now time.Time) error {
	return checkDeliveryAuthorizationAt(p, version, now, deliveryStore)
}

func checkDeliveryAuthorizationAt(p workload.Policy, version string, now time.Time, store string) error {
	if len(version) != 40 || strings.Trim(version, "0123456789abcdef") != "" {
		return errors.New("delivery authorization requires an exact commit")
	}
	if !p.RequireDeliveryAuthorization {
		return nil
	}
	var authorization workload.DeliveryAuthorization
	if err := readPrivateRelease(filepath.Join(store, p.App, version+".json"), &authorization); err != nil {
		return errors.New("protected delivery authorization is missing; inspect the actual merge before authorizing")
	}
	return authorization.Check(p, version, now)
}
