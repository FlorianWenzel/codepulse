// Command codepulse-server runs the CodePulse HTTP API.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/FlorianWenzel/codepulse/internal/server"
	"github.com/FlorianWenzel/codepulse/internal/server/decorate"
	"github.com/FlorianWenzel/codepulse/internal/server/store"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	// Use Postgres when DATABASE_URL is set; otherwise an in-memory store
	// (handy for local trials). Both satisfy store.Store.
	var st store.Store = store.NewMemory()
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		pg, err := store.OpenPostgres(context.Background(), dsn)
		if err != nil {
			log.Fatalf("connect to database: %v", err)
		}
		defer pg.Close()
		st = pg
		log.Printf("using PostgreSQL store")
	} else {
		log.Printf("using in-memory store (set DATABASE_URL for PostgreSQL)")
	}

	srv := server.New(st)
	if admin := os.Getenv("CODEPULSE_ADMIN_TOKEN"); admin != "" {
		if err := srv.BootstrapAdmin(admin); err != nil {
			log.Fatalf("bootstrap admin token: %v", err)
		}
		log.Printf("auth enabled (admin token configured)")
	} else {
		log.Printf("auth DISABLED (set CODEPULSE_ADMIN_TOKEN to enable)")
	}
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		srv.SetDecorator(&decorate.GitHub{Token: tok})
		log.Printf("GitHub PR decoration enabled")
	}
	if hook := os.Getenv("CODEPULSE_WEBHOOK_URL"); hook != "" {
		srv.SetWebhook(hook)
		log.Printf("notifications webhook enabled")
	}
	if au := os.Getenv("CODEPULSE_OIDC_AUTH_URL"); au != "" {
		admins := map[string]bool{}
		for _, e := range strings.Split(os.Getenv("CODEPULSE_OIDC_ADMIN_EMAILS"), ",") {
			if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
				admins[e] = true
			}
		}
		srv.SetOIDC(&server.OIDC{
			AuthURL: au, TokenURL: os.Getenv("CODEPULSE_OIDC_TOKEN_URL"),
			UserInfoURL:  os.Getenv("CODEPULSE_OIDC_USERINFO_URL"),
			ClientID:     os.Getenv("CODEPULSE_OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("CODEPULSE_OIDC_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("CODEPULSE_OIDC_REDIRECT_URL"), AdminEmails: admins,
		})
		log.Printf("OIDC SSO enabled")
	}

	log.Printf("codepulse-server listening on %s", *addr)
	if err := http.ListenAndServe(*addr, srv); err != nil {
		log.Fatal(err)
	}
}
