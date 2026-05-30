package suppressfixture

// Each panic would normally trip go:panic-usage. The inline directives below
// exercise the three suppression forms; only the un-annotated and
// wrong-id cases should remain.

func specificID() { panic("a") } // codepulse:ignore go:panic-usage

func bare() { panic("b") } // codepulse:ignore

func nosonar() { panic("c") } // NOSONAR

func notSuppressed() { panic("d") }

func wrongID() { panic("e") } // codepulse:ignore go:some-other-rule
