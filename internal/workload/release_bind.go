package workload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type ImageRun func(context.Context, ...string) (string, error)

// BindRelease pulls only policy-approved images, compares their Docker
// configuration IDs to the authenticated Build evidence, then freezes Compose
// to locally resolved registry digests. No service is started here.
func BindRelease(ctx context.Context, run ImageRun, p Policy, accepted ReleaseAcceptance, version, configImage string, compose []byte) ([]byte, error) {
	if p.SourceRepository == "" {
		return compose, nil
	}
	if err := accepted.Check(p, version); err != nil {
		return nil, err
	}
	m := accepted.Manifest
	if err := checkReleaseImage(ctx, run, m, configImage, configImage, false); err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := strictJSONMap(compose, &doc); err != nil {
		return nil, err
	}
	services, ok := doc["services"].(map[string]any)
	if !ok {
		return nil, errors.New("approved workload has no services")
	}
	for _, raw := range services {
		service, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid approved service")
		}
		image, ok := service["image"].(string)
		if !ok {
			return nil, errors.New("approved service has no image")
		}
		if !strings.HasPrefix(image, p.ImagePrefix) {
			continue
		} // upstreams were digest-required by Validate
		repository := strings.SplitN(image, "@", 2)[0]
		if colon := strings.LastIndex(repository, ":"); colon > strings.LastIndex(repository, "/") {
			repository = repository[:colon]
		}
		expectedRef := repository + ":" + version
		pinned, err := bindReleaseImage(ctx, run, m, image, expectedRef)
		if err != nil {
			return nil, err
		}
		service["image"] = pinned
	}
	return json.Marshal(doc)
}

func strictJSONMap(body []byte, out *map[string]any) error {
	if len(body) > MaxBytes || !json.Valid(body) {
		return errors.New("invalid approved workload")
	}
	if err := rejectDuplicateJSON(body); err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func inspectReleaseImage(ctx context.Context, run ImageRun, m ReleaseManifest, image, expectedRef string, pull bool) (string, error) {
	expected, ok := m.Images[expectedRef]
	if !ok {
		return "", errors.New("service image missing from authenticated release")
	}
	if pull {
		if _, err := run(ctx, "pull", "-q", image); err != nil {
			return "", errors.New("release image pull failed")
		}
	}
	body, err := run(ctx, "image", "inspect", image)
	if err != nil {
		return "", errors.New("release image inspection failed")
	}
	var images []struct {
		ID          string `json:"Id"`
		RepoDigests []string
		Descriptor  struct{ Digest string }
	}
	if json.Unmarshal([]byte(body), &images) != nil || len(images) != 1 {
		return "", errors.New("pulled image differs from authenticated Build evidence")
	}
	if images[0].ID != expected {
		// The containerd image store reports the manifest digest as Id. Read
		// the configuration from that immutable LOCAL image; checking a tag
		// or trusting a registry's claimed config digest would allow substitution.
		if !digest.MatchString(images[0].ID) || images[0].Descriptor.Digest != images[0].ID {
			return "", errors.New("pulled image differs from authenticated Build evidence")
		}
		actual, err := run(ctx, "config-digest", images[0].ID)
		if err != nil || strings.TrimSpace(actual) != expected {
			return "", errors.New("pulled image differs from authenticated Build evidence")
		}
	}
	repository := strings.TrimSuffix(expectedRef, ":"+m.Revision)
	for _, ref := range images[0].RepoDigests {
		if strings.HasPrefix(ref, repository+"@") && digest.MatchString(strings.TrimPrefix(ref, repository+"@")) {
			if strings.Contains(image, "@") && image != ref {
				return "", errors.New("declared digest differs from authenticated image")
			}
			return ref, nil
		}
	}
	return "", fmt.Errorf("authenticated image has no registry digest: %s", expectedRef)
}
func checkReleaseImage(ctx context.Context, run ImageRun, m ReleaseManifest, image, expectedRef string, pull bool) error {
	_, err := inspectReleaseImage(ctx, run, m, image, expectedRef, pull)
	return err
}
func bindReleaseImage(ctx context.Context, run ImageRun, m ReleaseManifest, image, expectedRef string) (string, error) {
	return inspectReleaseImage(ctx, run, m, image, expectedRef, true)
}

// BootstrapRelease is operator-only migration of known local artifacts. It
// performs no pulls and deliberately makes no claim that CI tested them.
func BootstrapRelease(ctx context.Context, run ImageRun, p Policy, version, configImage string, compose []byte, now time.Time) (ReleaseAcceptance, error) {
	var zero ReleaseAcceptance
	canonical, err := Validate(bytes.NewReader(compose), p, version)
	if err != nil {
		return zero, err
	}
	var doc map[string]any
	if err := json.Unmarshal(canonical, &doc); err != nil {
		return zero, err
	}
	refs := []string{configImage}
	services := doc["services"].(map[string]any)
	for _, raw := range services {
		image := raw.(map[string]any)["image"].(string)
		if strings.HasPrefix(image, p.ImagePrefix) {
			refs = append(refs, image)
		}
	}
	m := ReleaseManifest{Version: 1, Repository: p.SourceRepository, RepositoryID: p.RepositoryID, Revision: version, Images: map[string]string{}}
	for _, ref := range refs {
		if !strings.HasPrefix(ref, p.ImagePrefix) {
			return zero, errors.New("bootstrap image outside approved family")
		}
		repository := strings.SplitN(ref, "@", 2)[0]
		if colon := strings.LastIndex(repository, ":"); colon > strings.LastIndex(repository, "/") {
			repository = repository[:colon]
		}
		body, err := run(ctx, "image", "inspect", ref)
		if err != nil {
			return zero, errors.New("bootstrap image is not locally available")
		}
		var images []struct {
			ID string `json:"Id"`
		}
		if json.Unmarshal([]byte(body), &images) != nil || len(images) != 1 || !digest.MatchString(images[0].ID) {
			return zero, errors.New("invalid local bootstrap image identity")
		}
		m.Images[repository+":"+version] = images[0].ID
	}
	accepted := ReleaseAcceptance{Manifest: m, Authority: "operator-bootstrap", VerifiedAt: now}
	return accepted, accepted.Check(p, version)
}
