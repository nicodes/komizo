package box

import "testing"

func TestScopedDefinitionSupportsUnrelatedAppsAndRefusesUnsafeOrUndeclaredMetadata(t *testing.T) {
	for _, profile := range []string{"mail-service-v1", "other-org.worker-profile"} {
		d, err := ParseScopedDefinition(profile, "27", ".env,tls.pem,queue-token")
		if err != nil || len(d.Files) != 3 {
			t.Fatal(d, err)
		}
		if string(d.Marker("00112233445566778899aabbccddeeff")) != "profile="+profile+"\nschema=27\ngeneration=00112233445566778899aabbccddeeff\n" {
			t.Fatal("wrong metadata binding")
		}
	}
	for _, row := range [][3]string{{"profile", "", "worker.env"}, {"profile", "0", "worker.env"}, {"profile", "11", "../other.env"}, {"profile", "11", "/etc/shadow"}, {"profile", "11", "provenance"}, {"profile", "11", "a,a"}, {"profile", "11", "a,,b"}, {"profile\nother=x", "11", "file"}, {"", "11", "file"}} {
		if _, err := ParseScopedDefinition(row[0], row[1], row[2]); err == nil {
			t.Fatalf("unsafe definition admitted %q", row)
		}
	}
}
