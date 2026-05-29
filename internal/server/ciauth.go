package server

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// CIAuth verifies short-lived OIDC tokens minted by a CI provider (e.g. GitHub
// Actions' id-token) so the scanner can upload **without a static token**. It
// validates the RS256 signature against the provider's JWKS, the issuer,
// audience and expiry, and exposes the `repository` claim for authorization.
type CIAuth struct {
	Issuer   string
	Audience string
	JWKSURL  string
	HTTP     *http.Client
	now      func() time.Time
}

// CIClaims are the OIDC claims CodePulse uses.
type CIClaims struct {
	Iss        string          `json:"iss"`
	Aud        json.RawMessage `json:"aud"` // string or []string
	Exp        int64           `json:"exp"`
	Repository string          `json:"repository"`
	Sub        string          `json:"sub"`
}

func (c *CIAuth) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *CIAuth) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

var b64url = base64.RawURLEncoding

// Verify checks a JWT and returns its claims if valid.
func (c *CIAuth) Verify(token string) (*CIClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed token")
	}
	hb, err := b64url.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("bad header")
	}
	var hdr struct{ Alg, Kid string }
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, err
	}
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported alg %q", hdr.Alg)
	}
	pub, err := c.key(hdr.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := b64url.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("bad signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return nil, fmt.Errorf("signature verification failed")
	}

	pb, err := b64url.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("bad payload")
	}
	var cl CIClaims
	if err := json.Unmarshal(pb, &cl); err != nil {
		return nil, err
	}
	if c.Issuer != "" && cl.Iss != c.Issuer {
		return nil, fmt.Errorf("issuer mismatch")
	}
	if c.Audience != "" && !audienceContains(cl.Aud, c.Audience) {
		return nil, fmt.Errorf("audience mismatch")
	}
	if cl.Exp != 0 && c.clock().Unix() > cl.Exp {
		return nil, fmt.Errorf("token expired")
	}
	return &cl, nil
}

// key fetches the JWKS and builds the RSA public key for kid.
func (c *CIAuth) key(kid string) (*rsa.PublicKey, error) {
	req, _ := http.NewRequest(http.MethodGet, c.JWKSURL, nil)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || (kid != "" && k.Kid != kid) {
			continue
		}
		nb, err := b64url.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		eb, err := b64url.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		e := 0
		for _, b := range eb {
			e = e<<8 | int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
	}
	return nil, fmt.Errorf("no matching JWKS key for kid %q", kid)
}

func audienceContains(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return one == want
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}
