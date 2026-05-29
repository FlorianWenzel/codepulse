package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/FlorianWenzel/codepulse/internal/server/store"
)

// hashToken returns the hex SHA-256 of a token secret. Only hashes are stored.
func hashToken(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// generateSecret returns a new random token secret (hex of 32 bytes).
func generateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "cp_" + hex.EncodeToString(b), nil
}

// EnableAuth turns on token enforcement.
func (s *Server) EnableAuth() { s.authEnabled = true }

// BootstrapAdmin stores a global admin token with the given secret and enables
// auth. Used to seed the first credential from configuration.
func (s *Server) BootstrapAdmin(secret string) error {
	s.authEnabled = true
	return s.store.CreateToken(store.Token{
		ID: "admin", Name: "bootstrap-admin", Role: store.RoleAdmin,
		Hash: hashToken(secret), CreatedAt: s.now(),
	})
}

// principal resolves the bearer token on the request, if any.
func (s *Server) principal(r *http.Request) (store.Token, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return store.Token{}, false
	}
	return s.store.AuthToken(hashToken(strings.TrimPrefix(h, "Bearer ")))
}

// guard enforces a predicate against the request's principal. It returns true
// when the request may proceed. When auth is disabled, everything passes.
func (s *Server) guard(w http.ResponseWriter, r *http.Request, allow func(store.Token) bool) bool {
	if !s.authEnabled {
		return true
	}
	tok, ok := s.principal(r)
	if !ok {
		httpError(w, http.StatusUnauthorized, "missing or invalid token")
		return false
	}
	if !allow(tok) {
		httpError(w, http.StatusForbidden, "insufficient permissions")
		return false
	}
	return true
}

func isAdmin(t store.Token) bool { return t.Role == store.RoleAdmin }

// canIngest: admin, or a scan/admin token scoped to the project.
func canIngest(project string) func(store.Token) bool {
	return func(t store.Token) bool {
		if isAdmin(t) {
			return true
		}
		return t.Role == store.RoleScan && t.ProjectKey == project
	}
}

// canRead: admin, or any token scoped to the project.
func canRead(project string) func(store.Token) bool {
	return func(t store.Token) bool {
		return isAdmin(t) || t.ProjectKey == project
	}
}

// createToken issues a new token (admin only). The secret is returned once.
func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r, isAdmin) {
		return
	}
	var body struct{ Name, Role, Project string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !store.ValidRole(body.Role) {
		httpError(w, http.StatusBadRequest, "role must be admin|scan|viewer")
		return
	}
	if body.Role != store.RoleAdmin && body.Project == "" {
		httpError(w, http.StatusBadRequest, "scan/viewer tokens require a project")
		return
	}
	secret, err := generateSecret()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "could not generate token")
		return
	}
	tok := store.Token{
		ID: hashToken(secret)[:12], Name: body.Name, Role: body.Role,
		ProjectKey: body.Project, Hash: hashToken(secret), CreatedAt: s.now(),
	}
	if err := s.store.CreateToken(tok); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The secret is shown exactly once.
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": tok.ID, "name": tok.Name, "role": tok.Role,
		"project": tok.ProjectKey, "token": secret, "createdAt": tok.CreatedAt.Format(time.RFC3339),
	})
}
