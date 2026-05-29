package gofixture

import "fmt"

// TODO: refactor this package once the API stabilizes
func usesPanic() {
	panic("boom")
}

func emptyThing() {
	if true {
	}
}

func complexFunc(x int) int {
	r := 0
	if x > 0 {
		r++
	}
	if x > 1 {
		r++
	}
	if x > 2 {
		r++
	}
	if x > 3 {
		r++
	}
	if x > 4 {
		r++
	}
	if x > 5 {
		r++
	}
	if x > 6 {
		r++
	}
	if x > 7 {
		r++
	}
	if x > 8 {
		r++
	}
	if x > 9 {
		r++
	}
	if x > 10 {
		r++
	}
	if x > 11 {
		r++
	}
	if x > 12 {
		r++
	}
	if x > 13 {
		r++
	}
	if x > 14 {
		r++
	}
	for i := 0; i < x; i++ {
		r += i
	}
	if x > 0 && x < 100 {
		r++
	}
	return r
}

func clean() string {
	return fmt.Sprintln("ok")
}
