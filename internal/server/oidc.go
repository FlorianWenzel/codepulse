package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/FlorianWenzel/codepulse/internal/server/store"
)

// OIDC configures a single OpenID Connect / OAuth2 identity provider for SSO
// login. After a successful login CodePulse mints an API token for the user:
// admin if their email is in AdminEmails, otherwise a global read-only viewer.
type OIDC struct {
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AdminEmails  map[string]bool
	HTTP         *http.Client
}

// SetOIDC enables SSO with the given provider config.
func (s *Server) SetOIDC(o *OIDC) { s.oidc = o }

func (o *OIDC) client() *http.Client {
	if o.HTTP != nil {
		return o.HTTP
	}
	return http.DefaultClient
}

// login redirects the browser to the identity provider's authorize endpoint.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		httpError(w, http.StatusNotImplemented, "SSO not configured")
		return
	}
	state, err := generateSecret()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "state")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "cp_oidc_state", Value: state, Path: "/", HttpOnly: true})
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {s.oidc.ClientID},
		"redirect_uri":  {s.oidc.RedirectURL},
		"scope":         {"openid email"},
		"state":         {state},
	}
	http.Redirect(w, r, s.oidc.AuthURL+"?"+q.Encode(), http.StatusFound)
}

// callback handles the IdP redirect: validate state, exchange the code, fetch
// the user's email, and issue a CodePulse token.
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		httpError(w, http.StatusNotImplemented, "SSO not configured")
		return
	}
	state := r.URL.Query().Get("state")
	if c, err := r.Cookie("cp_oidc_state"); err != nil || c.Value == "" || c.Value != state {
		httpError(w, http.StatusBadRequest, "invalid state")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		httpError(w, http.StatusBadRequest, "missing code")
		return
	}

	accessToken, err := s.oidc.exchange(r.Context(), code)
	if err != nil {
		httpError(w, http.StatusBadGateway, "token exchange failed: "+err.Error())
		return
	}
	email, err := s.oidc.userEmail(r.Context(), accessToken)
	if err != nil || email == "" {
		httpError(w, http.StatusBadGateway, "could not resolve user")
		return
	}

	role := store.RoleViewer // global viewer (empty project = read-all)
	if s.oidc.AdminEmails[strings.ToLower(email)] {
		role = store.RoleAdmin
	}
	secret, err := generateSecret()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "token")
		return
	}
	tok := store.Token{ID: hashToken(secret)[:12], Name: "sso:" + email, Role: role,
		Hash: hashToken(secret), CreatedAt: s.now()}
	if err := s.store.CreateToken(tok); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"email": email, "role": role, "token": secret})
}

// exchange swaps an authorization code for an access token.
func (o *OIDC) exchange(ctx context.Context, code string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {o.RedirectURL},
		"client_id":     {o.ClientID},
		"client_secret": {o.ClientSecret},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, o.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := o.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", err
	}
	return tr.AccessToken, nil
}

// userEmail fetches the authenticated user's email from the userinfo endpoint.
func (o *OIDC) userEmail(ctx context.Context, accessToken string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, o.UserInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := o.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var ui struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ui); err != nil {
		return "", err
	}
	return ui.Email, nil
}
