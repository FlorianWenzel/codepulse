// Command codepulse-server runs the CodePulse HTTP API.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"

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
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		srv.SetDecorator(&decorate.GitHub{Token: tok})
		log.Printf("GitHub PR decoration enabled")
	}

	log.Printf("codepulse-server listening on %s", *addr)
	if err := http.ListenAndServe(*addr, srv); err != nil {
		log.Fatal(err)
	}
}
