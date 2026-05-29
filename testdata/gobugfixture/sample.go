package gobugfixture

import (
	"crypto/tls"
	"io"
)

// deferInLoop leaks file handles: the Close calls only run when openAll
// returns, not at the end of each iteration.
func deferInLoop(paths []string) {
	for _, p := range paths {
		f := open(p)
		defer f.Close()
		_ = f
	}
}

// discardedAppend silently drops the appended element.
func discardedAppend(s []int) {
	append(s, 1)
}

// insecureTLS turns off certificate verification.
func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

// deferInClosureInLoop is NOT a finding: the defer is bound to the inner
// closure, which runs (and cleans up) each iteration.
func deferInClosureInLoop(paths []string) {
	for _, p := range paths {
		func() {
			f := open(p)
			defer f.Close()
			_ = f
		}()
	}
}

type closer interface{ Close() error }

func open(string) io.Closer { return nil }
