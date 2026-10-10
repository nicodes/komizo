package workload

import (
	"errors"
	"io"
	"regexp"
	"sort"
)

// JSONImageReferences enumerates images without evaluating Compose, environment
// files, includes or extensions. This is retention discovery, never admission.
func JSONImageReferences(input io.Reader) ([]string, error) {
	body, err := io.ReadAll(io.LimitReader(input, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := strictJSONMap(body, &doc); err != nil {
		return nil, err
	}
	services, ok := doc["services"].(map[string]any)
	if !ok || len(services) == 0 || len(services) > 32 {
		return nil, errors.New("image discovery requires bounded services")
	}
	plainRef := regexp.MustCompile(`^[A-Za-z0-9._/:@-]+$`)
	var refs []string
	for _, raw := range services {
		service, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid service for image discovery")
		}
		ref, ok := service["image"].(string)
		if !ok || len(ref) > 1024 || !plainRef.MatchString(ref) {
			return nil, errors.New("image discovery requires explicit references")
		}
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs, nil
}
