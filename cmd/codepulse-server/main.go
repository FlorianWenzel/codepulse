// Command codepulse-server runs the CodePulse HTTP API.
package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/FlorianWenzel/codepulse/internal/server"
	"github.com/FlorianWenzel/codepulse/internal/server/store"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	// In-memory store for now; a Postgres-backed store implements the same
	// interface and will be selected by configuration in a later phase.
	srv := server.New(store.NewMemory())

	log.Printf("codepulse-server listening on %s", *addr)
	if err := http.ListenAndServe(*addr, srv); err != nil {
		log.Fatal(err)
	}
}
