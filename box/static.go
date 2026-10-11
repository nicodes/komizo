package box

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
)

// StaticServing records the root executor's accepted serving mode. It is not
// a container, and never contributes to Running's actual container count.
type StaticServing struct {
	Version     int    `json:"version"`
	Revision    string `json:"revision"`
	TreeSHA256  string `json:"tree_sha256"`
	RouteSHA256 string `json:"route_sha256"`
	GateImage   string `json:"gate_image"`
	Proxy       string `json:"proxy"`
	Active      bool   `json:"active"`
}

var staticRevision = regexp.MustCompile(`^[a-f0-9]{40}$`)
var staticHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (p *Probe) staticServing(app App, inventory *dockerInventory) *StaticServing {
	// Protected executor records and unchanged generated routes establish the
	// last accepted configuration. Proxy health remains an independent check.
	policyFile := p.path(filepath.Join("/etc/komizo/workloads", app.Name+".json"))
	policyInfo, err := os.Lstat(policyFile)
	if err != nil || !policyInfo.Mode().IsRegular() || policyInfo.Mode().Perm()&0022 != 0 || policyInfo.Size() > 1<<20 {
		return nil
	}
	if uid, known := fileUID(policyInfo); !known || uid != 0 {
		return nil
	}
	policyBytes, err := os.ReadFile(policyFile)
	var policy struct {
		App        string `json:"app"`
		AppDir     string `json:"app_dir"`
		Repository string `json:"source_repository"`
		Static     *struct {
			Proxy string `json:"proxy"`
		} `json:"static"`
	}
	if err != nil || json.Unmarshal(policyBytes, &policy) != nil || policy.Static == nil || policy.App != app.Name || policy.AppDir != app.Dir || policy.Repository == "" {
		return nil
	}
	file := p.path(filepath.Join("/var/lib/komizo/static", app.Name+".json"))
	directory, err := os.Lstat(filepath.Dir(file))
	if err != nil || !directory.IsDir() || directory.Mode().Perm()&0077 != 0 {
		return nil
	}
	if uid, known := fileUID(directory); !known || uid != 0 {
		return nil
	}
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 2<<20 {
		return nil
	}
	if uid, known := fileUID(info); !known || uid != 0 {
		return nil
	}
	body, err := os.ReadFile(file)
	var serving StaticServing
	if err != nil || json.Unmarshal(body, &serving) != nil || serving.Proxy != policy.Static.Proxy || serving.Version != 1 || !staticRevision.MatchString(serving.Revision) || serving.Revision != app.Version || !staticHash.MatchString(serving.RouteSHA256) {
		return nil
	}
	routeFile := p.path(filepath.Join("/srv/_proxy/routes", app.Name+".caddy"))
	routeInfo, err := os.Lstat(routeFile)
	if err != nil || !routeInfo.Mode().IsRegular() || routeInfo.Mode().Perm()&0022 != 0 || routeInfo.Size() > 1<<20 {
		return nil
	}
	if uid, known := fileUID(routeInfo); !known || uid != 0 {
		return nil
	}
	route, err := os.ReadFile(routeFile)
	if err != nil || len(route) > 1<<20 {
		return nil
	}
	sum := sha256.Sum256(route)
	if hex.EncodeToString(sum[:]) != serving.RouteSHA256 {
		return nil
	}
	if serving.Active {
		if !staticHash.MatchString(serving.TreeSHA256) {
			return nil
		}
		tree, err := os.Lstat(p.path(filepath.Join("/srv/_public", app.Name, serving.Revision)))
		if err != nil || !tree.IsDir() || tree.Mode().Perm()&0022 != 0 {
			return nil
		}
		if uid, known := fileUID(tree); !known || uid != 0 {
			return nil
		}
		found := false
		for _, container := range inventory.sorted() {
			if container.name == serving.Proxy && container.state == "running" {
				found = true
			}
		}
		if !found {
			return nil
		}
	}
	return &serving
}
