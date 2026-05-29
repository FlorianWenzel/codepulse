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
	Provider     string // optional preset: google | github | gitlab (fills URLs if unset)
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AdminEmails  map[string]bool // emails granted admin
	AdminGroups  map[string]bool // IdP groups granted admin
	HTTP         *http.Client
}

// providerPresets fills in well-known endpoint URLs for common providers.
var providerPresets = map[string]struct{ auth, token, userinfo string }{
	"google": {"https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token", "https://openidconnect.googleapis.com/v1/userinfo"},
	"github": {"https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token", "https://api.github.com/user"},
	"gitlab": {"https://gitlab.com/oauth/authorize", "https://gitlab.com/oauth/token", "https://gitlab.com/oauth/userinfo"},
}

// applyPreset fills empty endpoint URLs from the named provider preset.
func (o *OIDC) applyPreset() {
	p, ok := providerPresets[strings.ToLower(o.Provider)]
	if !ok {
		return
	}
	if o.AuthURL == "" {
		o.AuthURL = p.auth
	}
	if o.TokenURL == "" {
		o.TokenURL = p.token
	}
	if o.UserInfoURL == "" {
		o.UserInfoURL = p.userinfo
	}
}

// SetOIDC enables SSO with the given provider config (applies provider presets).
func (s *Server) SetOIDC(o *OIDC) {
	o.applyPreset()
	s.oidc = o
}

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
	email, groups, err := s.oidc.userInfo(r.Context(), accessToken)
	if err != nil || email == "" {
		httpError(w, http.StatusBadGateway, "could not resolve user")
		return
	}

	role := store.RoleViewer // global viewer (empty project = read-all)
	if s.oidc.AdminEmails[strings.ToLower(email)] {
		role = store.RoleAdmin
	} else {
		for _, g := range groups {
			if s.oidc.AdminGroups[g] {
				role = store.RoleAdmin
				break
			}
		}
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

// userInfo fetches the authenticated user's email and groups from the userinfo
// endpoint.
func (o *OIDC) userInfo(ctx context.Context, accessToken string) (string, []string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, o.UserInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := o.client().Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	var ui struct {
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ui); err != nil {
		return "", nil, err
	}
	return ui.Email, ui.Groups, nil
}
