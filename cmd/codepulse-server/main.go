// Command codepulse-server runs the CodePulse HTTP API.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"strconv"
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
	if n := os.Getenv("CODEPULSE_INGEST_WORKERS"); n != "" {
		if w, err := strconv.Atoi(n); err == nil && w > 0 {
			srv.EnableAsyncIngest(w)
			log.Printf("async ingest enabled (%d workers)", w)
		}
	}
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
	if au := os.Getenv("CODEPULSE_OIDC_AUTH_URL"); au != "" || os.Getenv("CODEPULSE_OIDC_PROVIDER") != "" {
		csv := func(key string) map[string]bool {
			m := map[string]bool{}
			for _, e := range strings.Split(os.Getenv(key), ",") {
				if e = strings.TrimSpace(e); e != "" {
					m[e] = true
				}
			}
			return m
		}
		admins := map[string]bool{}
		for e := range csv("CODEPULSE_OIDC_ADMIN_EMAILS") {
			admins[strings.ToLower(e)] = true
		}
		srv.SetOIDC(&server.OIDC{
			Provider: os.Getenv("CODEPULSE_OIDC_PROVIDER"),
			AuthURL:  au, TokenURL: os.Getenv("CODEPULSE_OIDC_TOKEN_URL"),
			UserInfoURL:  os.Getenv("CODEPULSE_OIDC_USERINFO_URL"),
			ClientID:     os.Getenv("CODEPULSE_OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("CODEPULSE_OIDC_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("CODEPULSE_OIDC_REDIRECT_URL"),
			AdminEmails:  admins, AdminGroups: csv("CODEPULSE_OIDC_ADMIN_GROUPS"),
		})
		log.Printf("OIDC SSO enabled")
	}

	log.Printf("codepulse-server listening on %s", *addr)
	if err := http.ListenAndServe(*addr, srv); err != nil {
		log.Fatal(err)
	}
}
