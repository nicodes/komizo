package devenv

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func keyPair(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, base64.StdEncoding.EncodeToString(der)
}

func TestEncryption(t *testing.T) {
	key, public := keyPair(t)
	want := map[string]string{"SECRET": "quoted ' \" $()\nsecond line=ok 😀", "EMPTY": ""}
	payload, err := seal(public, want, "request")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte(want["SECRET"])) {
		t.Fatal("plaintext leaked into envelope")
	}
	got, err := unseal(key, payload, "request")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err = unseal(key, payload, "different-request"); err == nil {
		t.Fatal("accepted wrong request ID")
	}
	otherKey, _ := keyPair(t)
	if _, err = unseal(otherKey, payload, "request"); err == nil {
		t.Fatal("accepted wrong private key")
	}
	var e envelope
	if err = json.Unmarshal(payload, &e); err != nil {
		t.Fatal(err)
	}
	e.Ciphertext[0] ^= 1
	bad, _ := json.Marshal(e)
	if _, err = unseal(key, bad, "request"); err == nil {
		t.Fatal("accepted tampered ciphertext")
	}
	e.Nonce = []byte("bad")
	bad, _ = json.Marshal(e)
	if _, err = unseal(key, bad, "request"); err == nil {
		t.Fatal("accepted bad nonce")
	}
	if _, err = unseal(key, []byte(`{"version":"unknown"}`), "request"); err == nil {
		t.Fatal("accepted unknown protocol")
	}
	if _, err = seal("bad-key", want, "request"); err == nil {
		t.Fatal("accepted invalid public key")
	}
}

func TestSelection(t *testing.T) {
	secrets := map[string]string{"TOKEN": "synthetic secret", "EMPTY": "", "UNREQUESTED": "must stay remote"}
	variables := map[string]string{"URL": "https://example.com"}
	got, err := selectValues(secrets, variables, "TOKEN,EMPTY", "URL")
	if err != nil || len(got) != 3 || got["EMPTY"] != "" {
		t.Fatalf("selection failed: %v", err)
	}
	if _, ok := got["UNREQUESTED"]; ok {
		t.Fatal("exported unrequested secret")
	}
	for _, tc := range []struct{ secret, variable string }{
		{"MISSING", ""}, {"TOKEN", "TOKEN"}, {"GITHUB_TOKEN", ""},
		{"github_token", ""}, {"TOKEN,", ""}, {"BAD-NAME", ""}, {"", ""},
	} {
		if _, err := selectValues(secrets, variables, tc.secret, tc.variable); err == nil {
			t.Fatalf("accepted invalid selection %+v", tc)
		}
	}
	secrets["TOKEN"] = "bad\x00value"
	if _, err := selectValues(secrets, nil, "TOKEN", ""); err == nil {
		t.Fatal("accepted NUL byte")
	}
}

func makeZip(t *testing.T, name string, payload []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	w := zip.NewWriter(&buffer)
	f, err := w.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestFetchEnvironment(t *testing.T) {
	for _, mode := range []string{"success", "failed-run", "missing-artifact", "tampered", "extra-name", "missing-name", "download-failed", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			want := map[string]string{"TOKEN": "synthetic\nsecret with 'quotes'", "URL": "http://localhost:3000"}
			var requestID string
			var payload []byte
			var deleted bool
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			api := func(ctx context.Context, method, path string, body any) ([]byte, error) {
				switch {
				case method == "POST" && strings.HasSuffix(path, "/ghenv.yml/dispatches"):
					request := body.(map[string]any)
					if request["return_run_details"] != true || request["ref"] != "main" {
						t.Fatal("incorrect dispatch")
					}
					inputs := request["inputs"].(map[string]string)
					if inputs["environment"] != "Preview" || inputs["secret_names"] != "TOKEN" || inputs["variable_names"] != "URL" {
						t.Fatal("incorrect inputs")
					}
					requestID = inputs["request_id"]
					if !requestName.MatchString(requestID) {
						t.Fatal("invalid request ID")
					}
					values := map[string]string{"TOKEN": want["TOKEN"], "URL": want["URL"]}
					if mode == "extra-name" {
						values["UNREQUESTED"] = "should reject"
					}
					if mode == "missing-name" {
						delete(values, "TOKEN")
					}
					var err error
					payload, err = seal(inputs["public_key"], values, requestID)
					if err != nil {
						t.Fatal(err)
					}
					if mode == "tampered" {
						payload = []byte(`{"version":"bad"}`)
					}
					return []byte(`{"workflow_run_id":42}`), nil
				case method == "GET" && strings.HasSuffix(path, "/runs/42"):
					if mode == "failed-run" {
						return []byte(`{"status":"completed","conclusion":"failure"}`), nil
					}
					if mode == "cancelled" {
						cancel()
						return []byte(`{"status":"queued"}`), nil
					}
					return []byte(`{"status":"completed","conclusion":"success"}`), nil
				case method == "GET" && strings.Contains(path, "/runs/42/artifacts"):
					if mode == "missing-artifact" {
						return []byte(`{"artifacts":[]}`), nil
					}
					return []byte(fmt.Sprintf(`{"artifacts":[{"id":7,"name":"ghenv-%s","expired":false}]}`, requestID)), nil
				case method == "GET" && strings.HasSuffix(path, "/artifacts/7/zip"):
					if mode == "download-failed" {
						return nil, errors.New("network failed")
					}
					return makeZip(t, "payload.json", payload), nil
				case method == "DELETE" && strings.HasSuffix(path, "/artifacts/7"):
					if ctx.Err() != nil {
						t.Fatal("cleanup reused cancelled context")
					}
					deleted = true
					return nil, nil
				default:
					t.Fatalf("unexpected API call %s %s", method, path)
					return nil, nil
				}
			}
			got, err := fetchEnvironment(ctx, api, options{Repo: "owner/repo", Environment: "Preview", Ref: "main", Secrets: "TOKEN", Variables: "URL"})
			if mode == "success" {
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("fetch failed: %v", err)
				}
			} else if err == nil {
				t.Fatal("expected rejection")
			}
			wantDelete := mode != "failed-run" && mode != "missing-artifact" && mode != "cancelled"
			if deleted != wantDelete {
				t.Fatalf("artifact deleted=%v, want %v", deleted, wantDelete)
			}
		})
	}
}

func TestArtifactValidation(t *testing.T) {
	for _, data := range [][]byte{[]byte("not a zip"), makeZip(t, "../payload.json", []byte("payload")), makeZip(t, "payload.json", bytes.Repeat([]byte("a"), maxPayload*2+1))} {
		if _, err := readArtifact(data); err == nil {
			t.Fatal("accepted invalid artifact")
		}
	}
}
