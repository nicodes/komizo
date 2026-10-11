package workload

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"
)

func TestDeploymentConfigurationArchiveRejectsAuthorityAndBounds(t *testing.T) {
	for _, name := range []string{"../compose.yml", "/compose.yml", "config/link", "config/extra", "config/compose.yml"} {
		var b bytes.Buffer
		w := tar.NewWriter(&b)
		kind := byte(tar.TypeReg)
		if name == "config/link" {
			kind = tar.TypeSymlink
		}
		size := int64(1)
		if name == "config/compose.yml" {
			size = MaxBytes + 1
		}
		if err := w.WriteHeader(&tar.Header{Name: name, Typeflag: kind, Size: size, Linkname: "/etc/private"}); err != nil {
			t.Fatal(err)
		}
		if kind == tar.TypeReg && size == 1 {
			w.Write([]byte("x"))
		}
		w.Close()
		if _, _, err := ReadConfiguration(bytes.NewReader(b.Bytes())); err == nil {
			t.Fatal("unsafe archive accepted", name)
		}
	}
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, name := range []string{"./compose.yml", "./hostnames"} {
		body := []byte("fixture")
		w.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Size: int64(len(body))})
		w.Write(body)
	}
	w.Close()
	compose, hosts, err := ReadConfiguration(bytes.NewReader(b.Bytes()))
	if err != nil || string(compose) != "fixture" || string(hosts) != "fixture" {
		t.Fatal("bounded ordinary config refused", err)
	}
}
func TestDeploymentRoutePreservesParentAndRejectsInjectedAuthority(t *testing.T) {
	rev := strings.Repeat("a", 40)
	route, metadata, names, err := DeploymentRoute("example", rev, []byte("Example.test -> api\n*.preview.example.test on-demand\n"), true)
	if err != nil || len(names) != 2 || !bytes.Contains(metadata, []byte("example.test -> api")) {
		t.Fatal(err)
	}
	for _, required := range []string{"Strict-Transport-Security", "X-Komizo-Revision", "header_up X-Forwarded-For {remote_host}", "reverse_proxy example-gate:80", "on_demand", "roll_keep 3"} {
		if !bytes.Contains(route, []byte(required)) {
			t.Fatal("missing route contract", required)
		}
	}
	for _, input := range []string{"example.test -> other bad", "example.test {", "*.example.test dns", "example.test\nEXAMPLE.test", "a..test", "-a.test", "example.test on-demand extra"} {
		if _, _, _, err := DeploymentRoute("example", rev, []byte(input), true); err == nil {
			t.Fatal("injected route accepted", input)
		}
	}
	if _, _, _, err := DeploymentRoute("example", rev, []byte("*.example.test"), false); err == nil {
		t.Fatal("wildcard without approval accepted")
	}
}
