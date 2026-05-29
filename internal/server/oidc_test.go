package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/FlorianWenzel/codepulse/internal/server"
	"github.com/FlorianWenzel/codepulse/internal/server/store"
)

// fakeIdP stands in for an OIDC provider: a token endpoint and a userinfo
// endpoint returning a configurable email.
func fakeIdP(email string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"access_token": "fake-access-token"})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fake-access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"email": email})
	})
	return httptest.NewServer(mux)
}

// noRedirect is a client that surfaces the 302 instead of following it.
func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func ssoLogin(t *testing.T, baseURL, idp string, admins []string, email string) (string, string) {
	t.Helper()
	adminSet := map[string]bool{}
	for _, a := range admins {
		adminSet[a] = true
	}
	srv := server.New(store.NewMemory())
	srv.EnableAuth()
	srv.SetOIDC(&server.OIDC{
		AuthURL: "https://idp.example/authorize", TokenURL: idp + "/token", UserInfoURL: idp + "/userinfo",
		ClientID: "cid", ClientSecret: "secret", RedirectURL: baseURL + "/auth/callback", AdminEmails: adminSet,
	})
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	// 1. login -> 302 to IdP, with state + cookie
	resp, err := noRedirect().Get(ts.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d, want 302", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	state := loc.Query().Get("state")
	if state == "" || loc.Query().Get("client_id") != "cid" {
		t.Fatalf("bad authorize redirect: %s", resp.Header.Get("Location"))
	}
	var stateCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "cp_oidc_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("no state cookie set")
	}

	// 2. callback with code + matching state/cookie
	req, _ := http.NewRequest("GET", ts.URL+"/auth/callback?code=abc&state="+state, nil)
	req.AddCookie(stateCookie)
	cbResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if cbResp.StatusCode != http.StatusOK {
		t.Fatalf("callback status = %d, want 200", cbResp.StatusCode)
	}
	var out struct{ Email, Role, Token string }
	json.NewDecoder(cbResp.Body).Decode(&out)
	if out.Email != email {
		t.Errorf("email = %q, want %q", out.Email, email)
	}
	return out.Token, ts.URL
}

func TestSSOAdminLogin(t *testing.T) {
	idp := fakeIdP("alice@corp.com")
	defer idp.Close()
	token, baseURL := ssoLogin(t, "http://callback.local", idp.URL, []string{"alice@corp.com"}, "alice@corp.com")
	if token == "" {
		t.Fatal("no token issued")
	}
	// admin SSO user can create a project
	r := authReq(t, baseURL, "POST", "/api/v1/projects", token, map[string]string{"key": "x"})
	if r.StatusCode != http.StatusCreated {
		t.Errorf("admin SSO create project = %d, want 201", r.StatusCode)
	}
}

func TestSSOViewerLogin(t *testing.T) {
	idp := fakeIdP("bob@corp.com")
	defer idp.Close()
	// bob is NOT in the admin list -> global viewer
	token, baseURL := ssoLogin(t, "http://callback.local", idp.URL, []string{"alice@corp.com"}, "bob@corp.com")
	// viewer can read the portfolio...
	if r := authReq(t, baseURL, "GET", "/api/v1/portfolio", token, nil); r.StatusCode != http.StatusOK {
		t.Errorf("viewer portfolio = %d, want 200", r.StatusCode)
	}
	// ...but cannot create projects
	if r := authReq(t, baseURL, "POST", "/api/v1/projects", token, map[string]string{"key": "y"}); r.StatusCode != http.StatusForbidden {
		t.Errorf("viewer create project = %d, want 403", r.StatusCode)
	}
}
