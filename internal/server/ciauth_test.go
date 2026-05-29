package server_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/server"
	"github.com/FlorianWenzel/codepulse/internal/server/store"
)

func TestCIAuthKeylessIngest(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "k1"
	b64 := base64.RawURLEncoding

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": kid, "kty": "RSA",
			"n": b64.EncodeToString(key.PublicKey.N.Bytes()),
			"e": b64.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}}})
	}))
	defer jwks.Close()

	sign := func(claims map[string]any) string {
		hb, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
		cb, _ := json.Marshal(claims)
		seg := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
		sum := sha256.Sum256([]byte(seg))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		return seg + "." + b64.EncodeToString(sig)
	}

	srv := server.New(store.NewMemory())
	srv.BootstrapAdmin("admintok") // enables auth
	srv.SetCIAuth(&server.CIAuth{Issuer: "https://gh", Audience: "codepulse", JWKSURL: jwks.URL})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// admin creates a project keyed by the repo slug
	if r := authReq(t, ts.URL, "POST", "/api/v1/projects", "admintok", map[string]string{"key": "acme/app"}); r.StatusCode != http.StatusCreated {
		t.Fatalf("create project = %d, want 201", r.StatusCode)
	}

	// valid OIDC token for acme/app -> keyless ingest succeeds (no static token)
	good := sign(map[string]any{"iss": "https://gh", "aud": "codepulse",
		"exp": time.Now().Add(time.Hour).Unix(), "repository": "acme/app"})
	if r := authReq(t, ts.URL, "POST", "/api/v1/analyses?project=acme/app", good, domain.Report{}); r.StatusCode != http.StatusCreated {
		t.Errorf("keyless ingest (valid) = %d, want 201", r.StatusCode)
	}

	// token for a different repo -> 403
	otherRepo := sign(map[string]any{"iss": "https://gh", "aud": "codepulse",
		"exp": time.Now().Add(time.Hour).Unix(), "repository": "acme/other"})
	if r := authReq(t, ts.URL, "POST", "/api/v1/analyses?project=acme/app", otherRepo, domain.Report{}); r.StatusCode != http.StatusForbidden {
		t.Errorf("keyless ingest (wrong repo) = %d, want 403", r.StatusCode)
	}

	// expired token -> 403
	expired := sign(map[string]any{"iss": "https://gh", "aud": "codepulse",
		"exp": time.Now().Add(-time.Hour).Unix(), "repository": "acme/app"})
	if r := authReq(t, ts.URL, "POST", "/api/v1/analyses?project=acme/app", expired, domain.Report{}); r.StatusCode != http.StatusForbidden {
		t.Errorf("keyless ingest (expired) = %d, want 403", r.StatusCode)
	}

	// wrong audience -> 403
	wrongAud := sign(map[string]any{"iss": "https://gh", "aud": "someone-else",
		"exp": time.Now().Add(time.Hour).Unix(), "repository": "acme/app"})
	if r := authReq(t, ts.URL, "POST", "/api/v1/analyses?project=acme/app", wrongAud, domain.Report{}); r.StatusCode != http.StatusForbidden {
		t.Errorf("keyless ingest (wrong aud) = %d, want 403", r.StatusCode)
	}
}
