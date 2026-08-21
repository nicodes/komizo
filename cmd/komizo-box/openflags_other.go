//go:build !unix

package main

// Zero where the flags do not exist (Windows). komizo-box runs on Alpine and
// nowhere else -- this file is what lets `GOOS=windows go build ./...` cover
// the whole module, and the protections these constants carry on unix are
// absent on a platform the agent never runs on. Stated, not hidden.
const (
	oNoFollow = 0
	oNonBlock = 0
)
